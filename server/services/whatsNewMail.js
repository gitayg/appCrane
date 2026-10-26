// After AppCrane upgrades itself, mail app owners and platform admins what
// changed.
//
// The trigger is a boot where the running version is newer than the last one
// announced (settings `whats_new_last_announced`). The first boot with nothing
// recorded records the running version and sends nothing, so a fresh install,
// or the first boot of the release that adds this, does not mail the whole
// history. A downgrade or a restart at the same version sends nothing.
//
// Notes come from releaseNotes.js, the same source as the dashboard's What's
// New: the curated lines in release-notes.json, or the release commit subject
// ("vX.Y.Z: ...") for a version that has none. When none can be read (no git
// checkout and GitHub unreachable) the mail still goes out, saying which
// version is now running and linking to the dashboard.
//
// One mail per recipient per release: the idempotency key names the version
// and the address, and migration 123 makes it unique for these rows, so a
// restart, a crash mid-send or two processes at once cannot send it twice.
//
// `whats_new_email_enabled` = '0' (platform admins, PUT /api/settings/:key)
// turns it off. While off, the recorded version still moves forward, so
// turning it back on does not mail everything that shipped in between.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import { getVersionNotes } from './releaseNotes.js';
import { BRAND, bulletList, esc, renderBrandedEmail, versionPill } from './mail/brandedLayout.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob } from './jobHealth.js';

export const K = {
  lastAnnounced: 'whats_new_last_announced',
  enabled: 'whats_new_email_enabled',
};
export const SOURCE = 'whats-new';
const MAX_NOTES = 15;

const PKG_VERSION = JSON.parse(readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8')).version;

function getSetting(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row && row.value != null ? row.value : null;
}

function setSetting(db, key, value) {
  db.prepare(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).run(key, String(value));
}

export function cmpVersion(a, b) {
  const pa = String(a || '0').split('.').map(Number);
  const pb = String(b || '0').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

const isEnabled = (db) => !['0', 'false', 'off'].includes(String(getSetting(db, K.enabled) ?? '').trim().toLowerCase());

/** Active humans with an e-mail who own an app, plus platform admins; one per address. */
export function whatsNewRecipients(db) {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email FROM users u
    WHERE u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''
      AND COALESCE(u.kind, 'human') = 'human'
      AND (u.role = 'platform_admin'
           OR EXISTS (SELECT 1 FROM app_user_roles r WHERE r.user_id = u.id AND r.app_role = 'owner'))
    ORDER BY u.id
  `).all();
  const seen = new Set();
  return rows.filter((u) => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Notes for versions in (from, to], newest first. */
export function notesBetween(notes, from, to) {
  return (Array.isArray(notes) ? notes : [])
    .filter((n) => n && cmpVersion(n.version, from) > 0 && cmpVersion(n.version, to) <= 0)
    .sort((a, b) => cmpVersion(b.version, a.version));
}

const noteLines = (n) => (Array.isArray(n.lines) && n.lines.length ? n.lines : [n.commit_message]);

export function renderWhatsNew({ from, to, notes, name }) {
  const url = dashboardBaseUrl();
  const several = notes.length !== 1 || notes[0].version !== to;
  const subject = several
    ? `[AppCrane] What's new in v${to} (since v${from})`
    : `[AppCrane] What's new in v${to}`;
  const shown = notes.slice(0, MAX_NOTES);
  const more = notes.length - shown.length;
  const intro = `AppCrane was updated to v${to}.`;
  const missing = 'The release notes could not be read on this server. Open the dashboard to see what changed.';
  const footer = 'You get this because you own an app on AppCrane or administer it.';

  let text = `Hi${name ? ' ' + name : ''},\n\n${intro}\n\n`;
  if (shown.length) {
    for (const n of shown) {
      const lines = noteLines(n);
      text += lines.length === 1
        ? `- v${n.version}: ${lines[0]}\n`
        : `- v${n.version}:\n${lines.map((l) => `    - ${l}\n`).join('')}`;
    }
    if (more > 0) text += `- and ${more} more\n`;
  } else {
    text += `${missing}\n`;
  }
  text += `\nDashboard: ${url}\n\n${footer}\n`;

  const sections = shown.map((n) =>
    `<div style="margin:18px 0 0;">${versionPill(n.version)}${bulletList(noteLines(n))}</div>`).join('')
    + (more > 0 ? `<p style="margin:16px 0 0;font-size:13px;color:${BRAND.dim};">and ${more} more</p>` : '');
  const bodyHtml = shown.length
    ? sections
    : `<p style="margin:12px 0 0;font-size:14px;color:${BRAND.dim};">${esc(missing)}</p>`;
  const html = renderBrandedEmail({
    preheader: intro,
    greeting: `Hi${name ? ' ' + name : ''},`,
    intro,
    bodyHtml,
    cta: { label: 'Open the AppCrane dashboard', url },
    footer,
  });
  return { subject, text, html };
}

/**
 * Announce the running version if it is newer than the last one announced.
 * @returns {Promise<{ status: 'recorded'|'unchanged'|'disabled'|'sent', sent?: number, skipped?: number }>}
 */
export async function announceWhatsNew({ db = getDb(), version = PKG_VERSION, loadNotes = getVersionNotes } = {}) {
  const last = getSetting(db, K.lastAnnounced);
  if (!last) {
    setSetting(db, K.lastAnnounced, version);
    log.info(`[whats-new] first run: recorded v${version}, nothing sent`);
    return { status: 'recorded' };
  }
  if (cmpVersion(version, last) <= 0) return { status: 'unchanged' };

  const advance = db.transaction(() => {
    const now = getSetting(db, K.lastAnnounced);
    if (!now || cmpVersion(version, now) > 0) setSetting(db, K.lastAnnounced, version);
  });

  if (!isEnabled(db)) {
    advance.immediate();
    log.info(`[whats-new] mail is off: recorded v${version}, nothing sent`);
    return { status: 'disabled' };
  }

  let notes = [];
  try {
    notes = notesBetween(await loadNotes(), last, version);
  } catch (e) {
    log.warn(`[whats-new] release notes unavailable: ${e.message}`);
  }

  const already = db.prepare('SELECT 1 FROM email_queue WHERE source = ? AND idempotency_key = ?');
  let sent = 0, skipped = 0;
  for (const u of whatsNewRecipients(db)) {
    const idempotencyKey = `whats-new:${version}:${u.email.trim().toLowerCase()}`;
    if (already.get(SOURCE, idempotencyKey)) { skipped++; continue; }
    const { subject, text, html } = renderWhatsNew({ from: last, to: version, notes, name: u.name });
    try {
      enqueueEmail({ to: u.email, subject, text, html, appId: null, idempotencyKey, source: SOURCE });
      sent++;
    } catch (e) {
      skipped++;
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[whats-new] skipped ${u.email}: ${e.message}`);
    }
  }
  advance.immediate();
  log.info(`[whats-new] v${last} -> v${version}: queued ${sent}, skipped ${skipped}`);
  return { status: 'sent', sent, skipped };
}

/** Run once, shortly after boot, off the startup path. Never throws. */
export function scheduleWhatsNewMail(delayMs = 20_000) {
  jobStarted('whats-new-mail');
  const t = setTimeout(() => {
    trackJob('whats-new-mail', announceWhatsNew).catch((e) => log.error(`[whats-new] failed: ${e.message}`));
  }, delayMs);
  t.unref?.();
  return t;
}
