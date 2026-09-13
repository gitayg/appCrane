import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { decrypt } from '../services/encryption.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { evaluatePush, recordDelivery, triggerAutoDeploys } from '../services/deployTrigger.js';
import { usesLocalRepo, localBranchHeadSha } from '../services/managedRepo.js';

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
    recordDelivery({
      appId: config.app_id, event, deliveryId, payloadHash,
      sigValid, actionTaken, branch, commitSha, deployId,
    });
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
  const commitSha = req.body?.after?.slice(0, 8) || null;
  const gate = evaluatePush(config, branch);

  if (gate.action === 'skipped_branch') {
    logDelivery({ sigValid: true, actionTaken: 'skipped_branch', branch, commitSha });
    return res.json({ message: `Ignored push to branch ${branch} (filter: ${gate.filterBranch})` });
  }

  if (gate.action === 'skipped_no_auto') {
    logDelivery({ sigValid: true, actionTaken: 'skipped_no_auto', branch, commitSha });
    return res.json({ message: `Webhook received for ${config.slug} but no auto-deploy configured` });
  }

  // Trigger deploys — one delivery log row per environment triggered
  // (services/deployTrigger.js; a push to a local managed repo runs the same code).
  const triggered = (await triggerAutoDeploys({
    config, branch, commitSha,
    commitMessage: req.body?.head_commit?.message?.slice(0, 200),
    logDelivery: (d) => logDelivery({ sigValid: true, ...d }),
  })).map((t) => t.env);

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

  // A managed app whose repository is on this host has no GitHub URL; its
  // "latest" is the branch tip of the local repo. Same response shape, so the
  // dashboard's update banner and its Deploy Now (a normal deploy, which
  // clones that repo) need no change. An unknown repo_backend marker is
  // reported, not guessed at.
  let localRepo;
  try { localRepo = usesLocalRepo(app); } catch (e) { return res.json({ available: false, reason: e.message }); }
  if (localRepo) {
    try {
      const latestSha = await localBranchHeadSha(app, app.branch || 'main');
      const cmp = compareDeployments(app.id, latestSha);
      return res.json({
        available: cmp.available,
        latest_sha: latestSha.slice(0, 8),
        latest_message: null,
        latest_date: null,
        production: cmp.production,
        sandbox: cmp.sandbox,
      });
    } catch (e) {
      return res.json({ available: false, reason: e.message });
    }
  }

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

    const cmp = compareDeployments(app.id, latestSha);

    res.json({
      available: cmp.available,
      latest_sha: latestSha.slice(0, 8),
      latest_message: latestMessage,
      latest_date: latestDate,
      production: cmp.production,
      sandbox:    cmp.sandbox,
    });
  } catch (e) {
    res.json({ available: false, reason: e.message });
  }
});

/**
 * The deployed-vs-latest comparison /updates reports, for any source of
 * `latestSha` (a full 40-hex commit).
 */
function compareDeployments(appId, latestSha) {
  const db = getDb();
  // Get most recent live deployment; fall back to any completed deployment
  // in case status never reached 'live' (e.g. first deploy still in progress).
  const latestDeploy = (env) =>
    db.prepare(
      "SELECT commit_hash FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1"
    ).get(appId, env)
    || db.prepare(
      "SELECT commit_hash FROM deployments WHERE app_id = ? AND env = ? ORDER BY id DESC LIMIT 1"
    ).get(appId, env);

  const prod = latestDeploy('production');
  const sand = latestDeploy('sandbox');

  // Returns true when sha is unknown/missing (can't confirm up-to-date → assume update available)
  // or when the stored hash genuinely differs from the latest SHA.
  const differs = (sha) => {
    if (!sha || sha === 'unknown') return true;
    return !latestSha.startsWith(sha) && !sha.startsWith(latestSha.slice(0, sha.length));
  };

  // Only report "up to date" when at least one env has a known hash AND it matches.
  const prodDiffers = prod ? differs(prod.commit_hash) : null;
  const sandDiffers = sand ? differs(sand.commit_hash) : null;
  return {
    available: !!(prodDiffers || sandDiffers),
    production: { deployed_sha: prod?.commit_hash || null, update_available: prodDiffers },
    sandbox:    { deployed_sha: sand?.commit_hash || null, update_available: sandDiffers },
  };
}

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
