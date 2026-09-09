import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { isAdmin } from '../utils/roles.js';
import { userHasAppPermission } from '../services/permissions.js';
import { AppError } from '../utils/errors.js';

const router = Router();

router.use(requireAuth);

/**
 * The apps on which `user` holds `app.audit.view`, as a SQL scope.
 *
 * Written as a subquery rather than a JS filter over a fetched page: the
 * filtering has to happen BEFORE LIMIT/OFFSET or the pages are wrong (and
 * before COUNT(*) or the pagination offers pages that don't exist).
 *
 * The two arms mirror roleForUserOnApp() exactly — an app_user_roles row of
 * 'owner'/'admin' wins, anything else falls back to a bare app_users
 * membership meaning 'user'. Written as one UNION so an owner/admin row that
 * has no matching app_users row still counts, which is the case
 * roleForUserOnApp() handles by checking app_user_roles first.
 */
const AUDIT_SCOPE_SQL = `
  SELECT au.app_id
    FROM app_users au
    LEFT JOIN app_user_roles r ON r.app_id = au.app_id AND r.user_id = au.user_id
    JOIN role_permissions rp
      ON rp.permission = 'app.audit.view'
     AND rp.role = CASE WHEN r.app_role IN ('owner', 'admin') THEN r.app_role ELSE 'user' END
     AND rp.granted = 1
   WHERE au.user_id = ?
  UNION
  SELECT r.app_id
    FROM app_user_roles r
    JOIN role_permissions rp
      ON rp.permission = 'app.audit.view'
     AND rp.role = r.app_role
     AND rp.granted = 1
   WHERE r.user_id = ? AND r.app_role IN ('owner', 'admin')
`;

/**
 * GET /api/audit - Platform-wide audit log.
 *
 * v2.66.0: no longer admin-only. A global admin / platform_admin still sees
 * every row; anyone else sees only rows for apps on which they hold
 * `app.audit.view`. Rows with a NULL app_id are platform-level events
 * (sign-ins, user management, settings) and stay admin-only — `app_id IN
 * (subquery)` is NULL for them, which is not true, so they drop out without a
 * special case.
 */
router.get('/audit', (req, res) => {
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

  // Non-admins are scoped BEFORE the count and the page, so `total` and the
  // rows agree and no row for an app they can't audit is ever materialised.
  const scoped = !isAdmin(req.user);
  if (scoped) {
    conditions.push(`al.app_id IN (${AUDIT_SCOPE_SQL})`);
    params.push(req.user.id, req.user.id);
  }

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

  const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';

  // `total` MUST carry the same filters as `entries` — it drives client
  // pagination, so counting the whole table while showing a filtered page
  // offers pages that don't exist. Built before limit/offset are appended to
  // `params` so the count binds only the filter values.
  const total = db.prepare(`
    SELECT COUNT(*) as count
    FROM audit_log al
    LEFT JOIN users u ON al.user_id = u.id
    LEFT JOIN apps a ON al.app_id = a.id
    ${where}
  `).get(...params).count;

  sql += where + ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const entries = db.prepare(sql).all(...params);

  // Actor breakdown so the UI can show "N agent actions / M human" without a
  // second round-trip. Carries the caller's scope for the same reason the
  // entries do — an unscoped count is a count of rows they may not read.
  const byActor = db.prepare(`
    SELECT COALESCE(al.actor_kind, u.kind, 'unknown') AS actor, COUNT(*) AS n
    FROM audit_log al LEFT JOIN users u ON al.user_id = u.id
    ${scoped ? `WHERE al.app_id IN (${AUDIT_SCOPE_SQL})` : ''}
    GROUP BY actor
  `).all(...(scoped ? [req.user.id, req.user.id] : []));

  res.json({ entries, total, limit, offset, actor, by_actor: byActor });
});

/**
 * GET /api/:slug/audit - Per-app audit log.
 *
 * NOTE the path: this router has ONE mount, `app.use('/api', logsRoutes)`, so
 * the per-app routes live at /api/<slug>/... and NOT at /api/apps/<slug>/...
 * (verified by probe, not by reading the mount line).
 *
 * requireAppAccess is satisfied by any assignment, including a plain 'user';
 * the audit trail names who deployed and who was granted access, so it is
 * gated by the matrix on top (default: Admin and Owner).
 */
router.get('/:slug/audit', requireAppAccess, (req, res) => {
  if (!userHasAppPermission(req.user, req.app, 'app.audit.view')) {
    throw new AppError('Viewing the audit trail for this app is not permitted by your role', 403, 'FORBIDDEN');
  }
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
 * GET /api/:slug/logs/:env - App runtime logs. (Path caveat: see the audit
 * route above — /api/<slug>/logs/<env>, not /api/apps/<slug>/logs/<env>.)
 *
 * Narrower than app membership (default: Owner only). Container logs are
 * unredacted application output — bearer tokens, e-mail addresses, request
 * paths and stack traces all end up there.
 */
router.get('/:slug/logs/:env', requireAppAccess, async (req, res) => {
  if (!userHasAppPermission(req.user, req.app, 'app.logs.view')) {
    throw new AppError('Viewing runtime logs for this app is not permitted by your role', 403, 'FORBIDDEN');
  }
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
