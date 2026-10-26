import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob } from './jobHealth.js';

// Events are kept by severity: info 30 days, warning 90, critical 365 by
// default, each overridable by a platform setting. Pruning deletes in batches
// and yields between them so a large backlog never holds the write lock long.

export const RETENTION_DEFAULTS = Object.freeze({ info: 30, warning: 90, critical: 365 });
export const RETENTION_MIN_DAYS = 1;
export const RETENTION_MAX_DAYS = 3650;
export const PRUNE_BATCH = 2000;
const MAX_BATCHES_PER_TIER = 500;
const DAY = 86_400_000;
const FIRST_RUN_DELAY_MS = 10 * 60_000;

export const retentionKey = (severity) => `event_retention_${severity}_days`;

export function validRetentionDays(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= RETENTION_MIN_DAYS && n <= RETENTION_MAX_DAYS ? n : null;
}

export function getRetention(db = getDb()) {
  const out = {};
  for (const [sev, def] of Object.entries(RETENTION_DEFAULTS)) {
    let v = null;
    try { v = db.prepare('SELECT value FROM settings WHERE key = ?').get(retentionKey(sev))?.value ?? null; } catch (_) {}
    out[sev] = validRetentionDays(v) ?? def;
  }
  return out;
}

export function setRetention(values, userId = null, db = getDb()) {
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `);
  db.transaction(() => {
    for (const sev of Object.keys(RETENTION_DEFAULTS)) {
      if (values[sev] === undefined) continue;
      upsert.run(retentionKey(sev), String(values[sev]), userId);
    }
  })();
  return getRetention(db);
}

export function sqliteTime(ms) {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
}

const yieldTurn = () => new Promise(r => setImmediate(r));

/** Delete events older than their tier's window. Returns { info, warning, critical } counts. */
export async function pruneEvents({ now = Date.now(), db = getDb(), batch = PRUNE_BATCH } = {}) {
  const days = getRetention(db);
  const del = db.prepare(`
    DELETE FROM events WHERE id IN (
      SELECT id FROM events WHERE severity = ? AND ts < ? ORDER BY ts LIMIT ?
    )
  `);
  const removed = {};
  for (const [sev, d] of Object.entries(days)) {
    const cutoff = sqliteTime(now - d * DAY);
    removed[sev] = 0;
    for (let i = 0; i < MAX_BATCHES_PER_TIER; i++) {
      const n = del.run(sev, cutoff, batch).changes;
      removed[sev] += n;
      if (n < batch) break;
      await yieldTurn();
    }
  }
  const total = removed.info + removed.warning + removed.critical;
  if (total) log.info(`[events] retention removed ${total} event(s) (info ${removed.info}, warning ${removed.warning}, critical ${removed.critical})`);
  return removed;
}

let timers = [];

export function startEventRetention() {
  if (timers.length) return;
  jobStarted('event-retention');
  const run = () => trackJob('event-retention', () => pruneEvents()).catch(e => log.warn(`[events] retention failed: ${e.message}`));
  const first = setTimeout(run, FIRST_RUN_DELAY_MS);
  const daily = setInterval(run, DAY);
  first.unref?.();
  daily.unref?.();
  timers = [first, daily];
}

export function stopEventRetention() {
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}
