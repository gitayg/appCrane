import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAdmin, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/audit - Global audit log (admin only)
 */
router.get('/audit', requireAdmin, (req, res) => {
  const db = getDb();
  const url = new URL(req.url, `http://${req.headers.host}`);
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 200);
  const offset = parseInt(url.searchParams.get('offset')) || 0;
  const appSlug = url.searchParams.get('app');
  const action = url.searchParams.get('action');
  // v2.28.0: filter by who acted — 'agent' or 'human'. This is the question
  // auditors and incident responders actually ask once most platform work
  // arrives over MCP ("what did the agents do?"), and it was previously
  // unanswerable because only user_id was recorded.
  const actorRaw = url.searchParams.get('actor');
  const actor = ['agent', 'human'].includes(actorRaw) ? actorRaw : null;

  let sql = `
    SELECT al.*, u.name as user_name, a.slug as app_slug, a.name as app_name
    FROM audit_log al
    LEFT JOIN users u ON al.user_id = u.id
    LEFT JOIN apps a ON al.app_id = a.id
  `;

  const conditions = [];
  const params = [];

  if (appSlug) {
    conditions.push('a.slug = ?');
    params.push(appSlug);
  }
  if (action) {
    conditions.push('al.action LIKE ?');
    params.push(`%${action}%`);
  }
  if (actor) {
    // Fall back to the user's current kind for rows written before 070 that
    // the backfill couldn't reach (deleted users stay NULL = unattributed).
    conditions.push("COALESCE(al.actor_kind, u.kind) = ?");
    params.push(actor);
  }

  if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const entries = db.prepare(sql).all(...params);
  const total = db.prepare('SELECT COUNT(*) as count FROM audit_log').get().count;

  // Actor breakdown so the UI can show "N agent actions / M human" without a
  // second round-trip.
  const byActor = db.prepare(`
    SELECT COALESCE(al.actor_kind, u.kind, 'unknown') AS actor, COUNT(*) AS n
    FROM audit_log al LEFT JOIN users u ON al.user_id = u.id
    GROUP BY actor
  `).all();

  res.json({ entries, total, limit, offset, actor, by_actor: byActor });
});

/**
 * GET /api/apps/:slug/audit - Per-app audit log
 */
router.get('/:slug/audit', requireAppAccess, (req, res) => {
  const db = getDb();
  const url2 = new URL(req.url, `http://${req.headers.host}`);
  const limit = Math.min(parseInt(url2.searchParams.get('limit')) || 50, 200);

  const entries = db.prepare(`
    SELECT al.*, u.name as user_name
    FROM audit_log al
    LEFT JOIN users u ON al.user_id = u.id
    WHERE al.app_id = ?
    ORDER BY al.created_at DESC
    LIMIT ?
  `).all(req.app.id, limit);

  res.json({ entries });
});

/**
 * GET /api/apps/:slug/logs/:env - App runtime logs
 */
router.get('/:slug/logs/:env', requireAppAccess, async (req, res) => {
  const { env } = req.params;
  const url3 = new URL(req.url, `http://${req.headers.host}`);
  const lines = Math.min(parseInt(url3.searchParams.get('lines')) || 100, 2000);
  const search = url3.searchParams.get('search') || '';
  const app = req.app;

  try {
    const { getAppLogs } = await import('../services/docker.js');
    const logs = await getAppLogs(app.slug, env, lines, search);
    res.json({ logs });
  } catch (e) {
    res.json({ logs: [], message: 'Container logs not available (app may not be running)' });
  }
});

export default router;
