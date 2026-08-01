import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAdmin, requirePlatformAdmin, requireAppAccess } from '../middleware/auth.js';
import { getSystemInfo, formatBytes } from '../services/platform.js';
import { getPortsForSlot } from '../services/portAllocator.js';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/credentials/health (v2.25.3) — platform integration credential
 * status for the dashboard banner. Reads the checker's persisted state
 * (settings.credcheck_state) and returns any currently-failing credential.
 * platform_admin only — this is sensitive operational detail (which integration
 * is down), deliberately NOT surfaced on the public /api/info. Closes the gap
 * where a dead Graph mail token can't email its own failure alert.
 */
router.get('/credentials/health', requirePlatformAdmin, (req, res) => {
  const db = getDb();
  let state = {};
  try {
    const row = db.prepare("SELECT value FROM settings WHERE key = 'credcheck_state'").get();
    if (row?.value) state = JSON.parse(row.value);
  } catch (_) { /* treat unreadable state as "nothing failing" */ }
  const failing = Object.entries(state)
    .filter(([, s]) => s && s.ok === false)
    .map(([name, s]) => ({ name, since: s.since || null, error: s.error || null, fix: s.fix || null }));
  res.json({ ok: failing.length === 0, failing });
});

/**
 * GET /api/server/health - Server health overview (admin)
 */
router.get('/server/health', requireAdmin, (req, res) => {
  const db = getDb();
  const system = getSystemInfo();

  const apps = db.prepare('SELECT * FROM apps').all();
  const appCount = apps.length;

  // Count running/down apps
  const healthStates = db.prepare('SELECT * FROM health_state').all();
  const downCount = healthStates.filter(h => h.is_down).length;
  const healthyCount = healthStates.filter(h => h.last_status === 200).length;

  // Recent deploys
  const recentDeploys = db.prepare(`
    SELECT d.*, a.slug, u.name as deployed_by_name
    FROM deployments d
    JOIN apps a ON d.app_id = a.id
    LEFT JOIN users u ON d.deployed_by = u.id
    ORDER BY d.started_at DESC LIMIT 10
  `).all();

  // Recent audit events
  const recentAudit = db.prepare(`
    SELECT al.*, u.name as user_name, a.slug as app_slug
    FROM audit_log al
    LEFT JOIN users u ON al.user_id = u.id
    LEFT JOIN apps a ON al.app_id = a.id
    ORDER BY al.created_at DESC LIMIT 20
  `).all();

  res.json({
    system: {
      ...system,
      memory_formatted: {
        total: formatBytes(system.memory.total),
        used: formatBytes(system.memory.used),
        free: formatBytes(system.memory.free),
      },
      disk_formatted: {
        total: formatBytes(system.disk.total),
        used: formatBytes(system.disk.used),
        free: formatBytes(system.disk.free),
      },
    },
    apps: { total: appCount, environments: appCount * 2, healthy: healthyCount, down: downCount },
    recent_deploys: recentDeploys,
    recent_audit: recentAudit,
  });
});

/**
 * GET /api/server/app-metrics - Batch CPU/RAM for all apps (admin)
 */
router.get('/server/app-metrics', requireAdmin, async (req, res) => {
  const db = getDb();
  const apps = db.prepare('SELECT slug FROM apps').all();
  const { getProcessMetrics } = await import('../services/docker.js');

  const metrics = {};
  await Promise.all(apps.map(async (app) => {
    metrics[app.slug] = {};
    for (const env of ['production', 'sandbox']) {
      try { metrics[app.slug][env] = await getProcessMetrics(app.slug, env); }
      catch (_) { metrics[app.slug][env] = null; }
    }
  }));

  res.json({ metrics });
});

/**
 * GET /api/apps/:slug/metrics/:env - Per-app metrics
 */
router.get('/apps/:slug/metrics/:env', requireAppAccess, async (req, res) => {
  const { env } = req.params;
  const ports = getPortsForSlot(req.app.slot);

  let procMetrics = null;
  try {
    const { getProcessMetrics } = await import('../services/docker.js');
    procMetrics = await getProcessMetrics(req.app.slug, env);
  } catch (e) {}

  const db = getDb();
  const healthState = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?')
    .get(req.app.id, env);

  const recentDeploys = db.prepare(
    'SELECT version, status, started_at, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 5'
  ).all(req.app.id, env);

  const craneDomain = process.env.CRANE_DOMAIN;
  const url = craneDomain
    ? `https://${craneDomain}/${env === 'production' ? req.app.slug : `${req.app.slug}-sandbox`}`
    : (() => { const d = req.app.domain || `${req.app.slug}.example.com`; return env === 'production' ? `https://${d}` : `https://${d.replace(/^([^.]+)/, '$1-sandbox')}`; })();

  res.json({
    app: req.app.slug,
    env,
    url,
    process: procMetrics || { status: 'unknown', cpu: 0, memory: 0 },
    health: healthState,
    recent_deploys: recentDeploys,
  });
});

/**
 * GET /api/dashboard/app-activity - Per-app visitor counts for the last 7 days
 * "Visitors" = identity session creations (user logins) per app per day.
 */
router.get('/dashboard/app-activity', requireAdmin, (req, res) => {
  const db = getDb();

  // Build 7-day label array (YYYY-MM-DD strings)
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }

  // Unique visitor counts grouped by app + day (from app_visits, deduplicated per user/app/day)
  const rows = db.prepare(`
    SELECT a.slug, a.name,
           v.day,
           COUNT(*) AS count
    FROM app_visits v
    JOIN apps a ON a.id = v.app_id
    WHERE v.day >= date('now', '-6 days')
    GROUP BY a.slug, v.day
  `).all();

  // Build per-app series
  const appsMap = {};
  for (const row of rows) {
    if (!appsMap[row.slug]) appsMap[row.slug] = { slug: row.slug, name: row.name, counts: Object.fromEntries(days.map(d => [d, 0])) };
    appsMap[row.slug].counts[row.day] = row.count;
  }

  const apps = Object.values(appsMap).map(a => ({
    slug: a.slug,
    name: a.name,
    counts: days.map(d => a.counts[d] ?? 0),
  }));

  res.json({ days, apps });
});

/**
 * GET /api/dashboard/leaderboards (v2.6.10+)
 *
 * Two leaderboards driven off the existing app_visits table (one row
 * per user/app/day, written from /api/identity/verify on every Caddy
 * forward_auth call):
 *
 *   - apps[]:  top apps by distinct active users over the window
 *   - users[]: top users by distinct apps opened over the window
 *
 * Query params:
 *   days  — lookback window in days (default 7, max 90)
 *   top   — how many rows per leaderboard (default 10, max 50)
 *
 * Both lists are admin-only — user-level activity rolled up by name is
 * sensitive enough to keep behind requireAdmin. Per-app rollups are
 * admin too (in line with /dashboard/app-activity which is already
 * gated the same way).
 */
router.get('/dashboard/leaderboards', requireAdmin, (req, res) => {
  const db = getDb();
  const days = Math.min(Math.max(parseInt(req.query.days, 10) || 7, 1), 90);
  const top  = Math.min(Math.max(parseInt(req.query.top,  10) || 10, 1), 50);

  // ─ Top apps by distinct active users in the window.
  // Attribute each app to its owner (first owner by id, matching how the
  // apps detail route resolves `owner`). LEFT JOIN so apps with no owner
  // record (creator deleted / pre-migration-048) still list, just unattributed.
  const apps = db.prepare(`
    SELECT a.slug, a.name,
           COUNT(DISTINCT v.user_id) AS users,
           COUNT(*) AS visit_days,
           ou.name  AS owner_name,
           ou.email AS owner_email
    FROM app_visits v
    JOIN apps a ON a.id = v.app_id
    LEFT JOIN (
      SELECT app_id, MIN(user_id) AS owner_id
      FROM app_user_roles WHERE app_role = 'owner'
      GROUP BY app_id
    ) o ON o.app_id = a.id
    LEFT JOIN users ou ON ou.id = o.owner_id
    WHERE v.day >= date('now', '-' || ? || ' days')
    GROUP BY a.id, a.slug, a.name, ou.name, ou.email
    ORDER BY users DESC, visit_days DESC, a.name ASC
    LIMIT ?
  `).all(days, top);

  // ─ Top users by distinct apps opened in the window
  const users = db.prepare(`
    SELECT u.id, u.name, u.email,
           COUNT(DISTINCT v.app_id) AS apps,
           COUNT(*) AS visit_days
    FROM app_visits v
    JOIN users u ON u.id = v.user_id
    WHERE v.day >= date('now', '-' || ? || ' days')
      AND u.active = 1
    GROUP BY u.id, u.name, u.email
    ORDER BY apps DESC, visit_days DESC, u.name ASC
    LIMIT ?
  `).all(days, top);

  res.json({ days, top, apps, users });
});

/**
 * GET /api/dashboard/active-users (v2.21.22) — count of users currently active
 * in the system, i.e. active (non-deactivated) accounts that either opened an
 * app (app_last_visit, updated on every Caddy forward_auth) or took a platform
 * action (audit_log) within the last `minutes`. Admin-only, like the other
 * dashboard rollups. Query: minutes (default 15, 1..1440).
 */
router.get('/dashboard/active-users', requireAdmin, (req, res) => {
  const minutes = Math.min(Math.max(parseInt(req.query.minutes, 10) || 15, 1), 1440);
  const db = getDb();
  const { count } = db.prepare(`
    SELECT COUNT(DISTINCT u.id) AS count
    FROM users u
    WHERE u.active = 1 AND (
      EXISTS (
        SELECT 1 FROM app_last_visit v
        WHERE v.user_id = u.id AND v.last_visit_at >= datetime('now', '-' || ? || ' minutes')
      ) OR EXISTS (
        SELECT 1 FROM audit_log al
        WHERE al.user_id = u.id AND al.created_at >= datetime('now', '-' || ? || ' minutes')
      )
    )
  `).get(minutes, minutes);
  res.json({ minutes, count });
});

/**
 * GET /api/dashboard/app-storage (v2.21.24) — total on-disk footprint per app:
 * the whole <DATA_DIR>/apps/<slug> tree (release checkouts + shared /data,
 * across sandbox + production) — i.e. what the app actually costs on the host
 * disk, not just its persistent volume. Admin-only. One `du` per app; returns
 * biggest-first so the Manage "Storage" column can rank disk hogs.
 */
router.get('/dashboard/app-storage', requireAdmin, async (req, res) => {
  const { dirSizeBytes } = await import('../services/diskUsage.js');
  const { resolveSafe } = await import('../utils/paths.js');
  const dataDir = process.env.DATA_DIR || './data';
  const db = getDb();
  const apps = db.prepare('SELECT slug FROM apps').all();
  const out = apps.map(({ slug }) => {
    let total = 0;
    try { total = dirSizeBytes(resolveSafe(dataDir, 'apps', slug)); } catch (_) { total = 0; }
    return { slug, total_bytes: total };
  });
  out.sort((a, b) => b.total_bytes - a.total_bytes);
  res.json({ apps: out });
});

/**
 * GET /api/server/tls-check - ENH-005: HSTS preload + cert validity check
 */
router.get('/server/tls-check', requireAdmin, async (req, res) => {
  const domain = process.env.CRANE_DOMAIN;
  if (!domain) return res.json({ domain: null, skipped: true, reason: 'CRANE_DOMAIN not set' });

  const db = getDb();
  const tlsRows = db.prepare("SELECT key, value FROM settings WHERE key IN ('tls_cert_file','tls_key_file')").all();
  const tlsMap = Object.fromEntries(tlsRows.map(r => [r.key, r.value || '']));
  const manualTls = !!(
    (tlsMap.tls_cert_file || process.env.TLS_CERT_FILE) &&
    (tlsMap.tls_key_file  || process.env.TLS_KEY_FILE)
  );

  const warnings = [];
  let hstsPreloaded = false;
  let certValid = null;

  // HSTS preload check
  try {
    const r = await fetch(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (r.ok) {
      const data = await r.json();
      hstsPreloaded = data.status === 'preloaded';
      if (hstsPreloaded && !manualTls) {
        warnings.push({
          level: 'error',
          code: 'HSTS_PRELOADED_ACME',
          message: `${domain} is HSTS-preloaded. ACME (Let's Encrypt) requires port 80 for HTTP challenges, which HSTS-preloaded browsers will refuse. Provide a manual TLS certificate instead.`,
        });
      }
    }
  } catch (_) {
    // hstspreload.org unreachable — skip check
  }

  // Cert validity — try to fetch the domain's HTTPS endpoint
  try {
    const r = await fetch(`https://${domain}/api/info`, {
      signal: AbortSignal.timeout(8000),
    });
    certValid = r.ok || r.status < 500;
  } catch (e) {
    certValid = false;
    const msg = e.message || '';
    if (/cert|ssl|tls|self.signed|UNABLE_TO_VERIFY/i.test(msg)) {
      warnings.push({
        level: 'error',
        code: 'CERT_INVALID',
        message: `TLS certificate for ${domain} is invalid or self-signed: ${msg}`,
      });
    } else if (/ECONNREFUSED|ETIMEDOUT|ENOTFOUND/i.test(msg)) {
      warnings.push({
        level: 'warn',
        code: 'DOMAIN_UNREACHABLE',
        message: `${domain} is not reachable — DNS may not be pointed at this server yet, or ports 80/443 are blocked.`,
      });
    }
  }

  res.json({
    domain,
    tls_mode: manualTls ? 'manual' : 'acme',
    hsts_preloaded: hstsPreloaded,
    cert_valid: certValid,
    warnings,
  });
});

export default router;
