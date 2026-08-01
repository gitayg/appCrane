/**
 * Platform credential health checker (v2.25.2).
 *
 * Every 15 minutes, probes the platform's integration credentials — the tokens
 * whose silent expiry breaks core features:
 *   - Microsoft Graph mail client secret (email sending)
 *   - GitHub service-account PAT (managed-app repos / deploys)
 * and emails every platform admin when one stops working. Probes skip cleanly
 * when a credential isn't configured (nothing to check).
 *
 * State is persisted in settings.credcheck_state so we alert on the *transition*
 * to failing (not every tick), re-alert at most once a day while still failing,
 * and send a one-line recovery notice when it comes back.
 *
 * Caveat: if the failing credential is Graph itself and Graph is the only mail
 * transport, the alert email can't be delivered — that case is logged loudly
 * (ERROR) so it surfaces in the server logs / log drain.
 */

import { getDb } from '../db.js';
import { sendEmail } from './emailService.js';
import { probeGraph } from './graphMailer.js';
import { probeServiceAccount } from './githubService.js';
import log from '../utils/logger.js';

const CHECK_INTERVAL_MS = 15 * 60_000;
const FIRST_CHECK_DELAY_MS = 60_000;      // let the app finish booting
const RE_ALERT_MS = 24 * 60 * 60_000;     // renotify at most once/day while broken
const STATE_KEY = 'credcheck_state';
let timer = null;

const PROBES = [
  { name: 'Microsoft Graph (email)', fix: 'Settings → Mail', run: probeGraph },
  { name: 'GitHub service account',  fix: 'Settings → GitHub', run: probeServiceAccount },
];

function loadState(db) {
  try {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(STATE_KEY);
    return row?.value ? JSON.parse(row.value) : {};
  } catch (_) { return {}; }
}

function saveState(db, state) {
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .run(STATE_KEY, JSON.stringify(state));
}

function platformAdminEmails(db) {
  return db.prepare(
    "SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL"
  ).all().map(r => r.email);
}

async function alertAdmins(db, subject, body) {
  const admins = platformAdminEmails(db);
  if (admins.length === 0) { log.warn(`[credcheck] no platform admins to alert: ${subject}`); return; }
  for (const to of admins) {
    // Send directly (not via the queue) so a broken mail credential surfaces
    // synchronously here rather than dead-lettering silently.
    await sendEmail({ to, subject, text: body, fromName: 'AppCrane' }).catch(e =>
      log.error(`[credcheck] could not email admin ${to} about "${subject}": ${e.message}`));
  }
}

async function runOnce(probes = PROBES) {
  const db = getDb();
  const state = loadState(db);
  const now = Date.now();

  for (const probe of probes) {
    let result;
    try { result = await probe.run(); }
    catch (e) { result = { ok: false, error: e.message }; } // probes shouldn't throw, but be safe

    const prev = state[probe.name] || { ok: true };

    if (result.skipped) {
      // Not configured → nothing to check; forget any prior state.
      delete state[probe.name];
      continue;
    }

    if (!result.ok) {
      const firstFailure = prev.ok !== false;
      const staleAlert = prev.lastAlertAt && (now - prev.lastAlertAt) >= RE_ALERT_MS;
      if (firstFailure || staleAlert) {
        const when = new Date(now).toISOString();
        await alertAdmins(db,
          `[AppCrane] ${probe.name} credential is FAILING`,
          `AppCrane's ${probe.name} credential stopped working.\n\n` +
          `Checked: ${when}\n` +
          `Error: ${result.error || '(no detail)'}\n\n` +
          `This usually means the token/secret expired, was rotated, or was revoked.\n` +
          `Fix it in ${probe.fix}. You'll get a recovery notice once it works again.\n`);
        log.error(`[credcheck] ${probe.name} FAILING: ${result.error || '(no detail)'}`);
      }
      state[probe.name] = { ok: false, since: prev.ok === false ? prev.since : now, lastAlertAt: (firstFailure || staleAlert) ? now : prev.lastAlertAt };
    } else {
      if (prev.ok === false) {
        await alertAdmins(db,
          `[AppCrane] ${probe.name} credential RECOVERED`,
          `AppCrane's ${probe.name} credential is working again as of ${new Date(now).toISOString()}.\n`);
        log.info(`[credcheck] ${probe.name} recovered`);
      }
      state[probe.name] = { ok: true };
    }
  }

  saveState(db, state);
}

/** Start the 15-minute credential checker. Idempotent. */
export function startCredentialChecker() {
  if (timer) return;
  log.info('[credcheck] platform credential checker started (every 15m)');
  setTimeout(() => { runOnce().catch(e => log.error(`[credcheck] first run: ${e.message}`)); }, FIRST_CHECK_DELAY_MS);
  timer = setInterval(() => { runOnce().catch(e => log.error(`[credcheck] tick: ${e.message}`)); }, CHECK_INTERVAL_MS);
  if (timer.unref) timer.unref();
}

export function stopCredentialChecker() {
  if (timer) { clearInterval(timer); timer = null; }
}

// Exported for tests / manual trigger.
export { runOnce as runCredentialCheckOnce };
