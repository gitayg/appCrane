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

const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function oneLine(s, max = 140) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 1).trimEnd() + '...' : t;
}

// The 🎯 element-picker prepends a "--- Pointed element ---" block (URL /
// Selector / Tag / Text) to the request message. That noise dominates the
// digest, so collapse each request to one readable line: the user's own words
// if they typed any, else a friendly hint from the pointed element.
function summarizeRequest(raw) {
  const msg = String(raw || '').trim();
  const i = msg.indexOf('--- Pointed element ---');
  if (i === -1) return { summary: oneLine(msg) || '(no description)', url: null };
  const before = msg.slice(0, i).trim();
  const block  = msg.slice(i);
  const url = (block.match(/^URL:\s*(.+)$/m)       || [])[1]?.trim() || null;
  const tag = (block.match(/^Tag:\s*<([^>\n]+)>/m) || [])[1]?.trim() || null;
  const txt = (block.match(/Text:\s*"([^"\n]{1,120})"/) || [])[1]?.trim() || null;
  const summary = before
    || (txt ? `Pointed at "${txt}"` : tag ? `Pointed at <${tag}>` : 'Pointed at an element');
  return { summary: oneLine(summary), url };
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(String(iso).includes('T') ? iso : String(iso).replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? '' : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
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

  const base = process.env.CRANE_DOMAIN ? `https://${process.env.CRANE_DOMAIN}` : '';
  const reviewLink = base ? `${base}/requests` : null;
  const PER_APP_CAP = 10; // keep the email skimmable; the rest is one click away

  let sent = 0;
  for (const [email, data] of byOwner) {
    const total = data.apps.reduce((n, a) => n + a.reqs.length, 0);
    const subject = `${total} request${total === 1 ? '' : 's'} awaiting your action`;
    // Busiest app first.
    data.apps.sort((a, b) => b.reqs.length - a.reqs.length);
    const appWord = data.apps.length === 1 ? 'app' : 'apps';
    const reqWord = total === 1 ? 'request' : 'requests';

    // ---- plain-text fallback ----
    let text = `Hi${data.name ? ' ' + data.name : ''},\n\n` +
      `You have ${total} open ${reqWord} awaiting action across ${data.apps.length} ${appWord}:\n`;
    for (const a of data.apps) {
      text += `\n${a.appName} (${a.reqs.length})\n`;
      const shown = a.reqs.slice(0, PER_APP_CAP);
      for (const r of shown) {
        const { summary, url } = summarizeRequest(r.message);
        text += `  - #${String(r.id).padStart(4, '0')}  ${summary}` +
          `  [${r.user_name || 'someone'}${url ? ', ' + url : ''}]\n`;
      }
      if (a.reqs.length > shown.length) {
        text += `  + ${a.reqs.length - shown.length} more — read more in AppCrane${reviewLink ? ': ' + reviewLink : ''}\n`;
      }
    }
    text += `\nReview them in AppCrane -> Requests${reviewLink ? ': ' + reviewLink : ''}.\n`;

    // ---- HTML ----
    const sections = data.apps.map(a => {
      const shown = a.reqs.slice(0, PER_APP_CAP);
      const rows = shown.map(r => {
        const { summary, url } = summarizeRequest(r.message);
        const meta = [esc(r.user_name || 'someone'), fmtDate(r.created_at), url ? esc(url) : null]
          .filter(Boolean).join(' &middot; ');
        return `<tr>` +
          `<td style="padding:8px 10px;vertical-align:top;white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#6b7280;border-top:1px solid #eef0f3;">#${String(r.id).padStart(4, '0')}</td>` +
          `<td style="padding:8px 10px;vertical-align:top;border-top:1px solid #eef0f3;">` +
            `<div style="font-size:14px;color:#111827;">${esc(summary)}</div>` +
            `<div style="font-size:12px;color:#6b7280;margin-top:2px;">${meta}</div>` +
          `</td></tr>`;
      }).join('');
      const moreN = a.reqs.length - shown.length;
      const moreLabel = reviewLink
        ? `<a href="${esc(reviewLink)}" style="color:#3b82f6;text-decoration:none;">read more in AppCrane</a>`
        : 'read more in AppCrane';
      const overflow = moreN > 0
        ? `<tr><td colspan="2" style="padding:6px 10px;font-size:12px;color:#6b7280;border-top:1px solid #eef0f3;">+ ${moreN} more &mdash; ${moreLabel}</td></tr>`
        : '';
      return `<div style="margin:22px 0 0;">` +
        `<div style="font-size:15px;font-weight:600;color:#111827;padding-bottom:6px;border-bottom:2px solid #e5e7eb;">` +
          `${esc(a.appName)} <span style="font-weight:400;color:#6b7280;">&middot; ${a.reqs.length} open</span></div>` +
        `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">${rows}${overflow}</table>` +
      `</div>`;
    }).join('');

    const btn = reviewLink
      ? `<a href="${esc(reviewLink)}" style="display:inline-block;margin-top:24px;background:#3b82f6;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 18px;border-radius:6px;">Review in AppCrane</a>`
      : '';

    const html = `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:640px;margin:0 auto;color:#111827;">` +
      `<p style="font-size:15px;margin:0 0 4px;">Hi${data.name ? ' ' + esc(data.name) : ''},</p>` +
      `<p style="font-size:14px;color:#374151;margin:0;">You have <strong>${total}</strong> open ${reqWord} awaiting action across <strong>${data.apps.length}</strong> ${appWord}.</p>` +
      `${sections}${btn}` +
      `<p style="font-size:12px;color:#9ca3af;margin-top:24px;">You're receiving this because you own or administer these apps.</p>` +
    `</div>`;

    try { enqueueEmail({ to: email, subject, text, html, source: 'request-digest' }); sent++; }
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
