import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getPortsForSlot } from '../services/portAllocator.js';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/apps/:slug/health/:env - Get health config and state
 */
router.get('/:slug/health/:env', requireAppAccess, (req, res) => {
  const { env } = req.params;
  const db = getDb();

  const config = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(req.app.id, env);
  const state = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(req.app.id, env);

  res.json({ env, config, state });
});

/**
 * PUT /api/apps/:slug/health/:env - Update health config
 */
router.put('/:slug/health/:env', requireAppUser, auditMiddleware('health-config'), (req, res) => {
  const { env } = req.params;
  const { endpoint, interval_sec, fail_threshold, down_threshold, enabled } = req.body;
  const db = getDb();

  const updates = [];
  const values = [];

  if (endpoint !== undefined) {
    if (typeof endpoint !== 'string' || !endpoint.startsWith('/') || endpoint.includes('@') || endpoint.includes('..')) {
      throw new AppError('endpoint must start with / and contain no @ or .. characters', 400, 'VALIDATION');
    }
    updates.push('endpoint = ?'); values.push(endpoint);
  }
  if (interval_sec !== undefined) { updates.push('interval_sec = ?'); values.push(interval_sec); }
  if (fail_threshold !== undefined) { updates.push('fail_threshold = ?'); values.push(fail_threshold); }
  if (down_threshold !== undefined) { updates.push('down_threshold = ?'); values.push(down_threshold); }
  if (enabled !== undefined) { updates.push('enabled = ?'); values.push(enabled ? 1 : 0); }

  if (updates.length === 0) {
    return res.json({ message: 'No changes' });
  }

  db.prepare(`UPDATE health_configs SET ${updates.join(', ')} WHERE app_id = ? AND env = ?`)
    .run(...values, req.app.id, env);

  const config = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(req.app.id, env);
  res.json({ env, config, message: 'Health config updated' });
});

function buildPublicUrl(app, env, endpoint = '') {
  const craneDomain = process.env.CRANE_DOMAIN;
  if (craneDomain) {
    const path = env === 'production' ? `/${app.slug}` : `/${app.slug}-sandbox`;
    return `https://${craneDomain}${path}${endpoint}`;
  }
  const domain = app.domain || app.slug;
  return env === 'production'
    ? `https://${domain}${endpoint}`
    : `https://${domain.replace(/^([^.]+)/, '$1-sandbox')}${endpoint}`;
}

/**
 * POST /api/apps/:slug/health/:env/test - Test health endpoint now
 */
router.post('/:slug/health/:env/test', requireAppAccess, async (req, res) => {
  const { env } = req.params;
  const db = getDb();

  const config = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(req.app.id, env);
  if (!config) throw new AppError('Health config not found', 404, 'NOT_FOUND');

  const ports = getPortsForSlot(req.app.slot);
  const port = env === 'production' ? ports.prod_be : ports.sand_be;
  const url = `http://localhost:${port}${config.endpoint}`;

  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    const elapsed = Date.now() - start;
    let body = null;
    try { body = await response.json(); } catch (e) { body = await response.text().catch(() => null); }

    // Update health state
    db.prepare(`
      UPDATE health_state SET last_check_at = datetime('now'), last_status = ?, last_response_ms = ?,
        consecutive_fails = CASE WHEN ? = 200 THEN 0 ELSE consecutive_fails + 1 END
      WHERE app_id = ? AND env = ?
    `).run(response.status, elapsed, response.status, req.app.id, env);

    const publicUrl = buildPublicUrl(req.app, env, config.endpoint);

    res.json({
      endpoint: config.endpoint,
      url: publicUrl,
      status: response.status,
      response_ms: elapsed,
      body,
      healthy: response.status === 200,
    });
  } catch (err) {
    const elapsed = Date.now() - start;
    const publicUrl = buildPublicUrl(req.app, env, config.endpoint);
    res.json({
      endpoint: config.endpoint,
      url: publicUrl,
      status: 0,
      response_ms: elapsed,
      error: err.name === 'AbortError' ? 'Timeout (5s)' : err.message,
      healthy: false,
    });
  }
});

/**
 * GET /api/apps/:slug/live-version/:env - Get live version from app's health endpoint
 */
router.get('/:slug/live-version/:env', requireAppAccess, async (req, res) => {
  const { env } = req.params;
  const db = getDb();

  const config = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(req.app.id, env);
  const endpoint = config?.endpoint || '/api/health';

  const ports = getPortsForSlot(req.app.slot);
  const port = env === 'production' ? ports.prod_be : ports.sand_be;
  const url = `http://localhost:${port}${endpoint}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (response.ok) {
      const body = await response.json();
      res.json({ version: body.version || null, status: body.status || null });
    } else {
      res.json({ version: null, error: `HTTP ${response.status}` });
    }
  } catch (e) {
    res.json({ version: null, error: e.name === 'AbortError' ? 'Timeout' : 'Not reachable' });
  }
});

export default router;
