import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { decrypt } from '../services/encryption.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware, logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';

function parseGithubUrl(url) {
  const m = url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?(?:\/.*)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

function getBaseUrl() {
  const craneDomain = process.env.CRANE_DOMAIN;
  return craneDomain
    ? `https://${craneDomain}`
    : (process.env.BASE_URL || `http://localhost:${process.env.PORT || 5001}`);
}

const router = Router();

// Per-token rate limiter: max 30 requests per 5 minutes
const _webhookAttempts = new Map();
function checkWebhookRateLimit(token) {
  const now = Date.now();
  const rec = _webhookAttempts.get(token);
  if (!rec || now > rec.resetAt) {
    _webhookAttempts.set(token, { count: 1, resetAt: now + 300_000 });
    return true;
  }
  if (rec.count >= 30) return false;
  rec.count++;
  return true;
}

/**
 * POST /api/webhooks/:token - GitHub webhook receiver (public, HMAC verified)
 */
router.post('/:token', async (req, res) => {
  const db = getDb();
  const config = db.prepare(`
    SELECT wc.*, a.id as app_id, a.slug, a.name as app_name, a.branch as app_branch
    FROM webhook_configs wc
    JOIN apps a ON a.id = wc.app_id
    WHERE wc.token = ?
  `).get(req.params.token);

  if (!config) {
    return res.status(404).json({ error: 'Unknown webhook token' });
  }

  if (!checkWebhookRateLimit(req.params.token)) {
    return res.status(429).json({ error: 'Too many webhook requests. Retry after 5 minutes.' });
  }

  // Capture request metadata once — used in delivery log at every exit point
  const deliveryId = req.headers['x-github-delivery'] || null;
  const event = req.headers['x-github-event'] || null;
  const body = JSON.stringify(req.body);
  const payloadHash = crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);

  // Log every inbound request to webhook_deliveries (before any processing).
  // One row per triggered deployment; one row for every rejection/skip.
  // Retain last 100 rows per app to keep diagnostic data without unbounded growth.
  function logDelivery({ sigValid, actionTaken, branch = null, commitSha = null, deployId = null }) {
    try {
      db.prepare(`
        INSERT INTO webhook_deliveries
          (app_id, event, delivery_id, payload_hash, branch, commit_hash,
           sig_valid, action_taken, deploy_id, result)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        config.app_id, event, deliveryId, payloadHash,
        branch, commitSha, sigValid ? 1 : 0, actionTaken, deployId ?? null,
        actionTaken, // keep legacy `result` column in sync
      );
      // Trim to last 100 per app (runs fast — table is tiny)
      db.prepare(`
        DELETE FROM webhook_deliveries
        WHERE app_id = ? AND id NOT IN (
          SELECT id FROM webhook_deliveries WHERE app_id = ? ORDER BY id DESC LIMIT 100
        )
      `).run(config.app_id, config.app_id);
    } catch (e) {
      log.warn(`Webhook delivery log failed: ${e.message}`);
    }
  }

  // Verify GitHub HMAC signature — REQUIRED (anyone with the token could fire
  // deploys otherwise, and the token is returned in API responses).
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) {
    logDelivery({ sigValid: false, actionTaken: 'sig_invalid' });
    return res.status(401).json({ error: 'Missing X-Hub-Signature-256 header' });
  }
  const expected = 'sha256=' + crypto.createHmac('sha256', config.secret).update(body).digest('hex');
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  // timingSafeEqual throws on length mismatch — guard first
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    logDelivery({ sigValid: false, actionTaken: 'sig_invalid' });
    return res.status(401).json({ error: 'Invalid signature' });
  }

  if (event !== 'push') {
    logDelivery({ sigValid: true, actionTaken: 'skipped_event' });
    return res.json({ message: `Ignored event: ${event}` });
  }

  // Check branch filter
  const ref = req.body?.ref || '';
  const branch = ref.replace('refs/heads/', '');
  const filterBranch = config.branch_filter || config.app_branch || 'main';
  const commitSha = req.body?.after?.slice(0, 8) || null;

  if (branch !== filterBranch) {
    logDelivery({ sigValid: true, actionTaken: 'skipped_branch', branch, commitSha });
    return res.json({ message: `Ignored push to branch ${branch} (filter: ${filterBranch})` });
  }

  if (!config.auto_deploy_sandbox && !config.auto_deploy_prod) {
    logDelivery({ sigValid: true, actionTaken: 'skipped_no_auto', branch, commitSha });
    return res.json({ message: `Webhook received for ${config.slug} but no auto-deploy configured` });
  }

  // Trigger deploys — one delivery log row per environment triggered
  const triggered = [];

  if (config.auto_deploy_sandbox) {
    const deployResult = db.prepare(`
      INSERT INTO deployments (app_id, env, status, commit_hash, commit_message, log)
      VALUES (?, 'sandbox', 'pending', ?, ?, 'Triggered by webhook')
    `).run(config.app_id, commitSha, req.body?.head_commit?.message?.slice(0, 200));

    logDelivery({ sigValid: true, actionTaken: 'deploy_triggered', branch, commitSha, deployId: deployResult.lastInsertRowid });
    logAudit(null, config.app_id, 'webhook-deploy', { env: 'sandbox', commit: commitSha });
    triggered.push('sandbox');
    log.info(`Webhook triggered sandbox deploy for ${config.slug}`);

    try {
      const { deployApp } = await import('../services/deployer.js');
      const { getPortsForSlot } = await import('../services/portAllocator.js');
      const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(config.app_id);
      const ports = getPortsForSlot(app.slot);
      deployApp(deployResult.lastInsertRowid, app, 'sandbox', ports).catch(err => {
        log.error(`Webhook deploy failed: ${err.message}`);
      });
    } catch (e) {
      log.warn('Deploy service not available for webhook trigger');
    }
  }

  if (config.auto_deploy_prod) {
    const deployResult = db.prepare(`
      INSERT INTO deployments (app_id, env, status, commit_hash, commit_message, log)
      VALUES (?, 'production', 'pending', ?, ?, 'Triggered by webhook')
    `).run(config.app_id, commitSha, req.body?.head_commit?.message?.slice(0, 200));

    logDelivery({ sigValid: true, actionTaken: 'deploy_triggered', branch, commitSha, deployId: deployResult.lastInsertRowid });
    logAudit(null, config.app_id, 'webhook-deploy', { env: 'production', commit: commitSha });
    triggered.push('production');
    log.info(`Webhook triggered production deploy for ${config.slug}`);

    try {
      const { deployApp } = await import('../services/deployer.js');
      const { getPortsForSlot } = await import('../services/portAllocator.js');
      const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(config.app_id);
      const ports = getPortsForSlot(app.slot);
      deployApp(deployResult.lastInsertRowid, app, 'production', ports).catch(err => {
        log.error(`Webhook prod deploy failed: ${err.message}`);
      });
    } catch (e) {
      log.warn('Deploy service not available for webhook prod trigger');
    }
  }

  res.json({ message: `Webhook processed for ${config.slug}`, triggered });
});

/**
 * GET /api/apps/:slug/webhook - Get webhook config
 */
router.get('/:slug/webhook', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  const config = db.prepare(
    'SELECT token, auto_deploy_sandbox, auto_deploy_prod, branch_filter FROM webhook_configs WHERE app_id = ?'
  ).get(req.app.id);

  if (!config) throw new AppError('Webhook not configured', 404, 'NOT_FOUND');

  res.json({
    webhook_url: `${getBaseUrl()}/api/webhooks/${config.token}`,
    auto_deploy_sandbox: !!config.auto_deploy_sandbox,
    auto_deploy_prod: !!config.auto_deploy_prod,
    branch_filter: config.branch_filter,
  });
});

/**
 * PUT /api/apps/:slug/webhook - Update webhook config
 */
router.put('/:slug/webhook', requireAuth, requireAppUser, auditMiddleware('webhook-config'), (req, res) => {
  const { auto_deploy_sandbox, auto_deploy_prod, branch_filter } = req.body;
  const db = getDb();

  const updates = [];
  const values = [];

  if (auto_deploy_sandbox !== undefined) { updates.push('auto_deploy_sandbox = ?'); values.push(auto_deploy_sandbox ? 1 : 0); }
  if (auto_deploy_prod !== undefined) { updates.push('auto_deploy_prod = ?'); values.push(auto_deploy_prod ? 1 : 0); }
  if (branch_filter !== undefined) { updates.push('branch_filter = ?'); values.push(branch_filter); }

  if (updates.length > 0) {
    db.prepare(`UPDATE webhook_configs SET ${updates.join(', ')} WHERE app_id = ?`)
      .run(...values, req.app.id);
  }

  const config = db.prepare('SELECT * FROM webhook_configs WHERE app_id = ?').get(req.app.id);

  res.json({
    webhook_url: `${getBaseUrl()}/api/webhooks/${config.token}`,
    auto_deploy_sandbox: !!config.auto_deploy_sandbox,
    auto_deploy_prod: !!config.auto_deploy_prod,
    branch_filter: config.branch_filter,
    message: 'Webhook config updated',
  });
});

/**
 * GET /api/apps/:slug/webhook/deliveries - Recent webhook delivery log
 */
router.get('/:slug/webhook/deliveries', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT id, received_at, event, delivery_id, branch, commit_hash,
           sig_valid, action_taken, deploy_id
    FROM webhook_deliveries WHERE app_id = ? ORDER BY id DESC LIMIT 100
  `).all(req.app.id);
  res.json({ deliveries: rows });
});

/**
 * GET /api/apps/:slug/updates - Check GitHub for newer commits vs what's deployed
 */
router.get('/:slug/updates', requireAuth, requireAppAccess, async (req, res) => {
  const app = req.app;
  if (!app.github_url) return res.json({ available: false, not_applicable: true, reason: 'No GitHub URL configured' });

  const parsed = parseGithubUrl(app.github_url);
  if (!parsed) return res.json({ available: false, not_applicable: true, reason: 'Could not parse GitHub URL' });
  const { owner, repo } = parsed;
  const branch = app.branch || 'main';

  let token = null;
  if (app.github_token_encrypted) {
    try { token = decrypt(app.github_token_encrypted); } catch (_) {}
  }

  try {
    const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'AppCrane' };
    if (token) headers.Authorization = `token ${token}`;

    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${branch}`, { headers });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      return res.json({ available: false, reason: `GitHub ${r.status}: ${body.message || ''}` });
    }
    const data = await r.json();
    const latestSha = data.sha;
    const latestMessage = data.commit?.message?.split('\n')[0] || '';
    const latestDate = data.commit?.committer?.date || null;

    const db = getDb();
    // Get most recent live deployment; fall back to any completed deployment
    // in case status never reached 'live' (e.g. first deploy still in progress).
    const latestDeploy = (env) =>
      db.prepare(
        "SELECT commit_hash FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1"
      ).get(app.id, env)
      || db.prepare(
        "SELECT commit_hash FROM deployments WHERE app_id = ? AND env = ? ORDER BY id DESC LIMIT 1"
      ).get(app.id, env);

    const prod = latestDeploy('production');
    const sand = latestDeploy('sandbox');

    // Returns true when sha is unknown/missing (can't confirm up-to-date → assume update available)
    // or when the stored hash genuinely differs from the latest GitHub SHA.
    const differs = (sha) => {
      if (!sha || sha === 'unknown') return true;
      return !latestSha.startsWith(sha) && !sha.startsWith(latestSha.slice(0, sha.length));
    };

    // Only report "up to date" when at least one env has a known hash AND it matches.
    const prodDiffers = prod ? differs(prod.commit_hash) : null;
    const sandDiffers = sand ? differs(sand.commit_hash) : null;
    const available = !!(prodDiffers || sandDiffers);

    res.json({
      available,
      latest_sha: latestSha.slice(0, 8),
      latest_message: latestMessage,
      latest_date: latestDate,
      production: { deployed_sha: prod?.commit_hash || null, update_available: prodDiffers },
      sandbox:    { deployed_sha: sand?.commit_hash || null, update_available: sandDiffers },
    });
  } catch (e) {
    res.json({ available: false, reason: e.message });
  }
});

/**
 * POST /api/apps/:slug/webhook/register-github - Register AppCrane webhook on the GitHub repo
 */
router.post('/:slug/webhook/register-github', requireAuth, requireAppAccess, async (req, res) => {
  const app = req.app;

  if (!app.github_url) return res.status(400).json({ error: 'No GitHub URL configured for this app' });

  const parsed = parseGithubUrl(app.github_url);
  if (!parsed) return res.status(400).json({ error: 'Could not parse GitHub URL' });
  const { owner, repo } = parsed;

  if (!app.github_token_encrypted) {
    return res.status(400).json({ error: `No GitHub token. Add via: PUT /api/apps/${app.slug} {"github_token":"ghp_..."}` });
  }

  let token;
  try { token = decrypt(app.github_token_encrypted); }
  catch (e) { return res.status(500).json({ error: 'Failed to decrypt GitHub token' }); }

  const db = getDb();
  const webhookConfig = db.prepare('SELECT * FROM webhook_configs WHERE app_id = ?').get(app.id);
  if (!webhookConfig) return res.status(404).json({ error: 'Webhook config not found' });

  const craneDomain = process.env.CRANE_DOMAIN;
  const baseUrl = craneDomain ? `https://${craneDomain}` : (process.env.BASE_URL || `http://localhost:${process.env.PORT || 5001}`);
  const webhookUrl = `${baseUrl}/api/webhooks/${webhookConfig.token}`;

  try {
    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/hooks`, {
      method: 'POST',
      headers: {
        Accept: 'application/vnd.github.v3+json',
        Authorization: `token ${token}`,
        'User-Agent': 'AppCrane',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'web',
        active: true,
        events: ['push'],
        config: { url: webhookUrl, content_type: 'json', secret: webhookConfig.secret, insecure_ssl: '0' },
      }),
    });

    const data = await r.json();
    if (!r.ok) {
      const alreadyExists = r.status === 422 && data.errors?.some(e => /already exist/i.test(e.message));
      if (alreadyExists) return res.json({ success: true, message: 'Webhook already registered on GitHub', webhook_url: webhookUrl });
      return res.status(r.status).json({ error: data.message || 'GitHub API error' });
    }

    log.info(`GitHub webhook registered for ${app.slug} (hook id ${data.id})`);
    res.json({ success: true, message: 'Webhook registered on GitHub', webhook_url: webhookUrl, github_hook_id: data.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
