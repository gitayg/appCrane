import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { JOBS, jobStarted, trackJob } from '../jobHealth.js';

// How long app audit events are kept: one platform-wide window (default 365
// days), signed into the audit chain's retention checkpoint under the key
// 'app_audit' so the verifier can tell a pruned row from a deleted one. It is
// platform-wide on purpose: an app owner cannot shorten the history of what
// their own app did.

export const APP_AUDIT_RETENTION_KEY = 'app_audit';
export const SETTING_KEY = 'app_audit_retention_days';
export const DEFAULT_DAYS = 365;
export const MIN_DAYS = 30;
export const MAX_DAYS = 3650;
const DAY = 86_400_000;
const BATCH = 2000;
const MAX_BATCHES = 500;
export const JOB_ID = 'app-audit-retention';

export function validDays(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= MIN_DAYS && n <= MAX_DAYS ? n : null;
}

export function getAppAuditRetentionDays(db = getDb()) {
  let v = null;
  try { v = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTING_KEY)?.value ?? null; } catch (_) {}
  return validDays(v) ?? DEFAULT_DAYS;
}

export function setAppAuditRetentionDays(days, userId = null, db = getDb()) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(SETTING_KEY, String(days), userId);
  return getAppAuditRetentionDays(db);
}

const sqlTime = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
const yieldTurn = () => new Promise(r => setImmediate(r));

/** Seal what is pending and sign the current window first, then delete rows older than it. */
export async function pruneAppAuditEvents({ db = getDb(), now = Date.now() } = {}) {
  const chain = await import('../auditChain.js');
  await chain.sealNew({ db });
  chain.checkpointNow({ db, now });
  const cutoff = sqlTime(now - getAppAuditRetentionDays(db) * DAY);
  const del = db.prepare('DELETE FROM app_audit_events WHERE id IN (SELECT id FROM app_audit_events WHERE created_at < ? ORDER BY id LIMIT ?)');
  let removed = 0;
  for (let i = 0; i < MAX_BATCHES; i++) {
    const n = del.run(cutoff, BATCH).changes;
    removed += n;
    if (n < BATCH) break;
    await yieldTurn();
  }
  if (removed) log.info(`[app-audit] retention removed ${removed} app audit event(s)`);
  return removed;
}

let timer = null;
export function startAppAuditRetention() {
  if (timer) return;
  JOBS[JOB_ID] ??= { label: 'App audit event retention', cadenceMs: DAY };
  jobStarted(JOB_ID, { cadenceMs: DAY });
  const tick = () => trackJob(JOB_ID, () => pruneAppAuditEvents()).catch(e => log.warn(`[app-audit] retention: ${e.message}`));
  const first = setTimeout(tick, 15 * 60_000);
  first.unref?.();
  timer = setInterval(tick, DAY);
  timer.unref?.();
}
