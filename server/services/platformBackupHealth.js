/**
 * Job Health 'platform-backup-offsite' (v2.145.0).
 *
 * Measured on a production host: a nightly local platform backup on the same
 * disk as the database, no off-site destination, and the only trace of that a
 * log WARN. Every Job Health row read as fine. This check makes the missing or
 * stale off-site copy a failing job: hourly, it records a run that fails with
 * offSiteHealth()'s message when no destination is configured or the last
 * successful upload is older than OFFSITE_MAX_AGE_HOURS, and passes otherwise.
 *
 * While it fails, every platform admin gets one e-mail a day that says exactly
 * what to configure. It uses alertAdmins' idempotency key (per job, status and
 * day) and is queued before the run is recorded, so the hourly re-send and Job
 * Health's own generic failing alert are both no-ops until the date changes.
 *
 * While the off-site copy is fine but the recovery key for the current key
 * fingerprint was never downloaded, the row reads 'warning' (no e-mail).
 */
import { trackJobSync, jobStarted, setJobDetail, sanitizeError } from './jobHealth.js';
import { offSiteHealth, getBackupConfig } from './backupScheduler.js';
import { noteKeyFingerprint, RECOVERY_KEY_NOT_DOWNLOADED } from './recoveryKey.js';
import { enqueueEmail } from './emailQueue.js';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

export const JOB_ID = 'platform-backup-offsite';
const CHECK_MS = 60 * 60 * 1000;

/** One check. Returns the health it recorded; never throws. */
export function checkPlatformBackupOffsite(now = Date.now()) {
  let health;
  try {
    noteKeyFingerprint(getDb(), new Date(now));
    health = offSiteHealth(getBackupConfig(), now);
  } catch (e) {
    health = { ok: false, severity: 'failing', warnings: [], reason: 'error', fix: null, message: `The off-site backup state could not be read: ${e.message}` };
  }
  const warnings = health.warnings || [];
  setJobDetail(JOB_ID, {
    reason: health.reason, last_success_at: health.last_success_at ?? null,
    age_hours: health.age_hours ?? null, max_age_hours: health.max_age_hours ?? null,
    recovery_key_downloaded: health.recovery_key?.downloaded_for_current_key ?? null,
    ...(health.severity === 'warning' ? { severity: 'warning' } : {}),
    message: [health.message, ...warnings].join(' '),
  });
  if (!health.ok) mailAdmins(health, now);
  try {
    trackJobSync(JOB_ID, () => { if (!health.ok) throw new Error(health.message); });
  } catch (_) { /* recorded as the failing run */ }
  return health;
}

/** The body of the daily e-mail: what is wrong and exactly what to configure. */
export function mailText(health) {
  return [
    `AppCrane's platform backup off-site check is failing: ${sanitizeError(health.message)}`,
    '',
    'What to do:',
    health.fix || 'See Settings > Backup.',
    '',
    ...(health.recovery_key && !health.recovery_key.downloaded_for_current_key && (health.warnings || []).length
      ? [`Also: ${RECOVERY_KEY_NOT_DOWNLOADED}`, ''] : []),
    'This e-mail repeats once a day while the check fails. See Settings > Job Health, row "Platform backup off-site copy".',
  ].join('\n');
}

function mailAdmins(health, now) {
  const db = getDb();
  const day = new Date(now).toISOString().slice(0, 10);
  const subject = health.reason === 'not-configured'
    ? 'AppCrane background job failing: Platform backup off-site copy (no S3 destination configured)'
    : 'AppCrane background job failing: Platform backup off-site copy';
  const text = mailText(health);
  const admins = db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all();
  for (const { email } of admins) {
    try {
      enqueueEmail({ to: email, subject, text, appId: null, source: 'job-health', idempotencyKey: `job-health:${JOB_ID}:failing:${day}:${email}` });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[backup-health] alert to admin skipped: ${e.message}`);
    }
  }
}

let _timer = null;
export function startPlatformBackupHealth() {
  if (_timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  checkPlatformBackupOffsite();
  _timer = setInterval(() => { try { checkPlatformBackupOffsite(); } catch (e) { log.warn(`[backup-health] check failed: ${e.message}`); } }, CHECK_MS);
  _timer.unref?.();
}

export function stopPlatformBackupHealth() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}
