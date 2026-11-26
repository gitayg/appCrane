import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { existsSync, unlinkSync, symlinkSync, cpSync, writeFileSync, readFileSync, mkdirSync } from 'fs';
import { resolve, join } from 'path';
import { getDb } from '../db.js';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getPortsForSlot } from '../services/portAllocator.js';
import { userHasAppPermission, roleForUserOnApp } from '../services/permissions.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';
import { assessRedeployRisk, ACK_PARAM } from '../services/redeployRisk.js';
import { assertNoRestoreInProgress } from '../services/managedDbRestoreGuard.js';
import { parseLabel } from '../services/releaseLog.js';

const router = Router();

router.use(requireAuth);

/**
 * Did the caller say, explicitly, that it accepts the loss?
 *
 * Read from the body in both of its shapes, because the two REST deploy entry
 * points do not share a parser: `POST /deploy/:env` arrives as JSON (a real
 * boolean) and `POST /deploy/upload` arrives through multer as a multipart
 * field (always a string).
 *
 * NOT read from req.query, and that is not a style choice. requireAppAccess
 * assigns the app row to `req.app`, shadowing Express's own `req.app`; Express
 * 4 implements `req.query` as a getter that calls `this.app.get('query parser
 * fn')`, so touching req.query anywhere downstream of that middleware throws
 * `this.app.get is not a function`. Measured — the first version of this
 * function did exactly that and turned every refusal into a 500.
 *
 * ONLY the exact affirmatives count. Anything else — absent, '', 'no', 'false',
 * an object — is "not acknowledged". A guard written as `if (!ack)` would be
 * satisfied by the string 'false'.
 */
function acknowledgedDataLoss(req) {
  const raw = req.body?.[ACK_PARAM];
  return raw === true || raw === 'true';
}

/**
 * The gate itself. Returns null when the deploy may proceed, or the 409 body to
 * send when it may not.
 *
 * FAILS CLOSED, and the failure is loud rather than generic: an API or MCP
 * caller cannot be shown a dialog, so the refusal has to carry everything the
 * decision needs — which paths die, which survive, and the exact parameter that
 * says "go ahead". An error that only says "confirmation required" would make
 * an agent guess, and an agent that guesses parameter names eventually guesses
 * one that works for the wrong reason.
 */
async function refuseUnacknowledgedDataLoss(req, app, env) {
  const risk = await assessRedeployRisk({ db: getDb(), app, env });
  if (!risk.at_risk || acknowledgedDataLoss(req)) return null;
  return {
    error: {
      code: 'DATA_LOSS_NOT_ACKNOWLEDGED',
      message:
        `${risk.summary} This deploy was refused because it was not acknowledged. Re-send it with ` +
        `"${ACK_PARAM}": true in the request body to proceed.`,
      risk,
    },
  };
}

/**
 * POST /api/apps/:slug/deploy/upload - Upload artifact and deploy in one step
 * Multipart form: file (.zip/.tar.gz/.tgz), env (sandbox|production), commit_sha?, commit_message?
 * No GitHub credentials required — CI builds the artifact and pushes it directly.
 */
router.post('/:slug/deploy/upload', requireAppAccess, auditMiddleware('deploy-upload'), async (req, res) => {
  const app = req.app;
  // Refused before the body is read: a converted app deploys from its repository.
  const { conversionRefusal } = await import('../services/uploadConversion.js');
  const refusal = conversionRefusal(getDb(), app);
  if (refusal) return res.status(refusal.status).json({ error: { code: refusal.code, message: refusal.message } });
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const { mkdirSync, unlinkSync } = await import('fs');
  const { execFileSync } = await import('child_process');
  const multer = (await import('multer')).default;

  const tmpDir = join(dataDir, 'tmp');
  mkdirSync(tmpDir, { recursive: true });

  const upload = multer({
    dest: tmpDir,
    limits: { fileSize: 200 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const allowed = ['.tar.gz', '.tgz', '.zip'];
      if (allowed.some(a => file.originalname.toLowerCase().endsWith(a))) cb(null, true);
      else cb(new AppError('Only .tar.gz, .tgz, and .zip files allowed', 400, 'INVALID_FILE'));
    },
  }).single('file');

  upload(req, res, async (multerErr) => {
    if (multerErr) return res.status(400).json({ error: { code: 'UPLOAD_ERROR', message: multerErr.message } });
    if (!req.file) return res.status(400).json({ error: { code: 'NO_FILE', message: 'No file uploaded (field name: file)' } });

    const env = req.body?.env;
    if (!['production', 'sandbox'].includes(env)) {
      try { unlinkSync(req.file.path); } catch (_) {}
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'env must be production or sandbox' } });
    }
    // Security audit 2026-10-06, H3: the deploy.production gate POST
    // /deploy/:env enforces. Without it any member uploaded straight to prod.
    if (env === 'production' && !userHasAppPermission(req.user, app, 'deploy.production')) {
      try { unlinkSync(req.file.path); } catch (_) {}
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Production deploys are not permitted by your role on this app' } });
    }

    // Same gate as POST /deploy/:env. An uploaded artifact reaches the same
    // stopApp + startApp pair, so it destroys the same container.
    const refusal = await refuseUnacknowledgedDataLoss(req, app, env);
    if (refusal) {
      try { unlinkSync(req.file.path); } catch (_) {}
      return res.status(409).json(refusal);
    }

    if (env === 'production') {
      const { assertProductionRelease, sendReleaseRefusal } = await import('../services/releaseCheck.js');
      try { await assertProductionRelease({ app, userId: req.user.id, trigger: 'deploy-request' }); } catch (e) { try { unlinkSync(req.file.path); } catch (_) {} if (e.releaseCheck) return sendReleaseRefusal(res, e); return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: e.message } }); }
    }

    const declaredSha = (req.body?.commit_sha || '').slice(0, 40) || null;
    const commitMessage = (req.body?.commit_message || '').slice(0, 200) || null;

    // services/artifactDeploy.js owns the digest, the extract and the deploy
    // handoff. It is shared with the MCP tool, which is the only route an agent
    // holding a dhk_mcp_* key can take.
    let out;
    try {
      const { deployArtifact } = await import('../services/artifactDeploy.js');
      out = await deployArtifact({
        app, env, filePath: req.file.path, filename: req.file.originalname,
        declaredSha, commitMessage, userId: req.user.id,
      });
    } catch (e) {
      return res.status(400).json({ error: { code: 'UPLOAD_DEPLOY_FAILED', message: e.message } });
    }

    res.json({
      deployment: { id: out.deployId, app: app.slug, env, status: 'pending' },
      // Echoed so the uploader can compare against the digest it computed
      // locally — the only way for the client to confirm the bytes AppCrane
      // deployed are the bytes it meant to send.
      artifact: {
        sha256: out.artifact.sha256,
        bytes: out.artifact.bytes,
        filename: out.artifact.filename,
        declared_commit_sha: out.artifact.declared_commit_sha,
      },
      message: `Deployment #${out.deployId} started. Check status with GET /api/apps/${app.slug}/deployments/${env}`,
    });
  });
});

/**
 * POST /api/apps/:slug/deploy/:env - Trigger deployment
 */
router.post('/:slug/deploy/:env', requireAppAccess, auditMiddleware('deploy'), async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  }
  const label = parseLabel(req.body?.label);

  // Configurable RBAC: production deploys gated by deploy.production permission
  if (env === 'production' && !userHasAppPermission(req.user, req.app, 'deploy.production')) {
    throw new AppError('Production deploys are not permitted by your role on this app', 403, 'FORBIDDEN');
  }

  const db = getDb();
  const app = req.app;
  const ports = getPortsForSlot(app.slot);

  // v2.7.31: refuse to pile a new deploy on top of one already in flight for
  // this app+env (deploy-storm guard). Stale in-flight rows are reclaimed.
  const { assertNoInflightDeploy } = await import('../services/deployer.js');
  assertNoInflightDeploy(db, app.id, env, app.slug);
  assertNoRestoreInProgress(app.slug, env);

  // v2.72.0: a redeploy that destroys state needs the caller to have SAID so.
  // Placed after the in-flight guard and before the deployments INSERT, so a
  // refused deploy leaves no row behind and no deploy-storm window open.
  const refusal = await refuseUnacknowledgedDataLoss(req, app, env);
  if (refusal) return res.status(409).json(refusal);

  if (env === 'production') {
    const { assertProductionRelease, sendReleaseRefusal } = await import('../services/releaseCheck.js');
    try { await assertProductionRelease({ db, app, userId: req.user.id, trigger: 'deploy-request' }); } catch (e) { if (e.releaseCheck) return sendReleaseRefusal(res, e); throw e; }
  }

  // No memory on the server for this container: 409 with the reason, recorded
  // as a failed deployment, the running version untouched.
  const { refuseDeployForMemory } = await import('../services/deployer.js');
  await refuseDeployForMemory({ db, app, env, userId: req.user.id });

  // Create deployment record
  const result = db.prepare(`
    INSERT INTO deployments (app_id, env, status, deployed_by, release_label)
    VALUES (?, ?, 'pending', ?, ?)
  `).run(app.id, env, req.user.id, label);

  const deployId = result.lastInsertRowid;

  // Start deploy in background
  try {
    const { deployApp } = await import('../services/deployer.js');
    deployApp(deployId, app, env, ports).catch(err => {
      console.error(`Deploy ${deployId} failed:`, err);
    });
  } catch (e) {
    // deployer not yet implemented - mark as pending
    db.prepare("UPDATE deployments SET status = 'failed', log = ?, finished_at = datetime('now') WHERE id = ?")
      .run(`Deploy service error: ${e.message}`, deployId);
  }

  res.json({
    deployment: { id: deployId, app: app.slug, env, status: 'pending' },
    message: `Deployment #${deployId} started. Check status with GET /api/apps/${app.slug}/deployments/${env}`,
  });
});

/**
 * GET /api/apps/:slug/deploy/:env/risk - What a redeploy would destroy.
 *
 * Exists so the dashboard's second confirmation can NAME the paths instead of
 * asking "are you sure?". A confirmation that carries no information is one
 * people learn to click through, which is worse than no confirmation, so the
 * UI is given the same verdict object the 409 carries and renders it.
 *
 * Read-only and side-effect free: it inspects a container and returns what it
 * found. Behind requireAppAccess like every other per-app route here.
 */
router.get('/:slug/deploy/:env/risk', requireAppAccess, async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  }
  res.json({ risk: await assessRedeployRisk({ db: getDb(), app: req.app, env }) });
});

/**
 * GET /api/apps/:slug/deployments/:env - Deployment history
 */
router.get('/:slug/deployments/:env', requireAppAccess, (req, res) => {
  const { env } = req.params;
  const db = getDb();

  const deployments = db.prepare(`
    SELECT d.*, u.name as deployed_by_name
    FROM deployments d
    LEFT JOIN users u ON d.deployed_by = u.id
    WHERE d.app_id = ? AND d.env = ?
    ORDER BY d.started_at DESC
    LIMIT 20
  `).all(req.app.id, env);

  res.json({ deployments });
});

/**
 * GET /api/apps/:slug/deployments/:env/:id/log - Get deploy log
 */
router.get('/:slug/deployments/:env/:id/log', requireAppAccess, (req, res) => {
  const db = getDb();
  const deploy = db.prepare('SELECT * FROM deployments WHERE id = ? AND app_id = ?').get(
    parseInt(req.params.id), req.app.id
  );
  if (!deploy) throw new AppError('Deployment not found', 404, 'NOT_FOUND');

  res.json({ log: deploy.log || '', status: deploy.status, failure_reason: deploy.failure_reason ?? null });
});

/**
 * POST /api/apps/:slug/rollback/:env - Rollback to previous version
 */
router.post('/:slug/rollback/:env', requireAppAccess, auditMiddleware('rollback'), async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  }
  // v2.7.13: rollback is owner-only (or global admin), same gate as promote.
  if (!isAdmin(req.user) && roleForUserOnApp(req.user, req.app) !== 'owner') {
    throw new AppError('Only the app owner can roll back this app.', 403, 'FORBIDDEN');
  }
  assertNoRestoreInProgress(req.app.slug, env);
  const { deployment_id } = req.body || {};
  const { rollbackApp } = await import('../services/deployer.js');
  const r = await rollbackApp(req.app, env, deployment_id, req.user.id);
  res.json({
    message: `Rolled back ${req.app.slug} ${env} to version ${r.version || 'deployment #' + r.rollback_to}`,
    deployment: { id: r.deployment_id, rollback_to: r.rollback_to },
  });
});

/**
 * POST /api/apps/:slug/promote - Promote the live sandbox release to production.
 *
 * Gated: requires a live + healthy sandbox (see promoteApp), and the caller
 * must hold deploy.production. github and managed apps rebuild for prod;
 * upload apps and deploy_artifact releases copy the exact tested sandbox
 * release. Mechanics live in
 * services/deployer.js promoteApp() so REST and the appcrane_promote MCP tool
 * stay in lockstep.
 */
router.post('/:slug/promote', requireAppAccess, requireStepUp('promote_production'), auditMiddleware('promote'), async (req, res) => {
  // v2.7.12: promotion is owner-only (or global admin). Per-app admins and
  // plain members cannot promote to production.
  if (!isAdmin(req.user) && roleForUserOnApp(req.user, req.app) !== 'owner') {
    throw new AppError('Only the app owner can promote to production.', 403, 'FORBIDDEN');
  }
  assertNoRestoreInProgress(req.app.slug, 'production');
  const { promoteApp } = await import('../services/deployer.js');
  const r = await promoteApp(req.app, req.user.id).catch((e) => { if (e.releaseCheck) return e; throw e; });
  if (r instanceof Error) return (await import('../services/releaseCheck.js')).sendReleaseRefusal(res, r);
  res.status(r.status === 'pending' ? 202 : 200).json({
    message: `Promoting sandbox v${r.version || '?'} to production${r.mode === 'rebuild' ? ' (fresh build)' : ''}`,
    deployment: { id: r.deployment_id, from_sandbox: r.from_sandbox, status: r.status },
  });
});

/**
 * POST /api/apps/:slug/restart/:env - Recreate the container with fresh env vars from the DB.
 * docker restart does NOT re-read env vars (they're baked in at `docker run`), so we inspect the
 * running container to find its image, stop it, and start a new one with the current env.
 */
router.post('/:slug/restart/:env', requireAppAccess, auditMiddleware('restart'), async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  }
  // A restart re-reads the stored command, mounts and env, decrypts production
  // secrets and starts a container with them: for production that is a deploy
  // in everything but name, so it takes the deploy gate.
  if (env === 'production' && !userHasAppPermission(req.user, req.app, 'deploy.production')) {
    throw new AppError('Restarting production requires the deploy.production permission for this app', 403, 'FORBIDDEN');
  }
  assertNoRestoreInProgress(req.app.slug, env);

  const { recreateEnvContainer, assertNoAutomaticRecreate } = await import('../services/containerRecreate.js');
  assertNoAutomaticRecreate(req.app, env);
  res.json(await recreateEnvContainer({ app: req.app, env, actor: req.user, reason: 'restart' }));
});

export default router;
