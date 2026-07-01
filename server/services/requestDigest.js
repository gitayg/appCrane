/**
 * v2.14.2: daily digest emailing each app owner/admin the open requests
 * awaiting action on their apps. Runs once a day (default 08:00 server-local),
 * persisting the last-run date so it survives restarts and never double-sends.
 * Uses the platform email service (registered users only).
 */
import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import log from '../utils/logger.js';

function getSetting(db, key, fallback) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row && row.value != null ? row.value : fallback;
}
function setSetting(db, key, value) {
  db.prepare(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).run(key, String(value));
}

/**
 * Queue a digest to every owner/admin who has open requests on their apps.
 * Returns { owners, requests } for logging / manual invocation.
 */
export function sendPendingRequestDigests() {
  const db = getDb();
  const rows = db.prepare(`
    SELECT id, app_slug, message, user_name, created_at
    FROM enhancement_requests
    WHERE status NOT IN ('done', 'no_changes_needed')
      AND validated_at IS NULL
      AND app_slug IS NOT NULL
    ORDER BY created_at ASC
  `).all();
  if (!rows.length) { log.info('[request-digest] no pending requests'); return { owners: 0, requests: 0 }; }

  const byApp = new Map();
  for (const r of rows) {
    if (!byApp.has(r.app_slug)) byApp.set(r.app_slug, []);
    byApp.get(r.app_slug).push(r);
  }

  // email → { name, apps: [{ appName, reqs }] }
  const byOwner = new Map();
  for (const [slug, reqs] of byApp) {
    const app = db.prepare('SELECT id, name FROM apps WHERE slug = ?').get(slug);
    if (!app) continue;
    const owners = db.prepare(`
      SELECT DISTINCT u.email, u.name FROM app_user_roles aur
      JOIN users u ON u.id = aur.user_id
      WHERE aur.app_id = ? AND aur.app_role IN ('owner', 'admin') AND u.active = 1 AND u.email IS NOT NULL
    `).all(app.id);
    for (const o of owners) {
      if (!byOwner.has(o.email)) byOwner.set(o.email, { name: o.name, apps: [] });
      byOwner.get(o.email).apps.push({ appName: app.name || slug, reqs });
    }
  }

  let sent = 0;
  for (const [email, data] of byOwner) {
    const total = data.apps.reduce((n, a) => n + a.reqs.length, 0);
    const subject = `${total} request${total === 1 ? '' : 's'} awaiting your action`;
    let body = `Hi${data.name ? ' ' + data.name : ''},\n\nYou have ${total} open request${total === 1 ? '' : 's'} awaiting action:\n`;
    for (const a of data.apps) {
      body += `\n${a.appName}\n`;
      for (const r of a.reqs) {
        body += `  • #${String(r.id).padStart(4, '0')} — ${String(r.message || '').slice(0, 120)} (${r.user_name || 'someone'})\n`;
      }
    }
    body += `\nReview them in AppCrane -> Requests.\n\n-- AppCrane`;
    try { enqueueEmail({ to: email, subject, text: body, source: 'request-digest' }); sent++; }
    catch (_) { /* skip bad recipient */ }
  }
  log.info(`[request-digest] queued ${sent} digest(s) covering ${rows.length} pending request(s)`);
  return { owners: sent, requests: rows.length };
}

// Hourly tick that runs the digest once a day at/after the configured hour
// (setting `request_digest_hour`, default 8, server-local time).
let _timer = null;
export function startRequestDigestScheduler() {
  if (_timer) return;
  const tick = () => {
    try {
      const db = getDb();
      const hour = parseInt(getSetting(db, 'request_digest_hour', '8'), 10) || 8;
      const today = new Date().toISOString().slice(0, 10);
      if (getSetting(db, 'request_digest_last_run', '') !== today && new Date().getHours() >= hour) {
        sendPendingRequestDigests();
        setSetting(db, 'request_digest_last_run', today);
      }
    } catch (e) {
      log.warn(`[request-digest] scheduler tick failed: ${e.message}`);
    }
  };
  tick();
  _timer = setInterval(tick, 60 * 60 * 1000);
  log.info('[request-digest] daily scheduler started');
}
