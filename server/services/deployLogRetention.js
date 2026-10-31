import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob } from './jobHealth.js';

// deployments.log was kept for as long as the app existed. The ROW is kept
// (history, audit and rollback read it: release_path, image_ref, commit,
// failure_reason); only the log text goes, and only on rows that are both
// outside the newest KEEP_NEWEST of their app+env and older than MAX_AGE_DAYS.
// The live row and any in flight keep theirs whatever their age. Readers of
// the log (the deploy-log route, appcrane_get_deploy_log, releaseCheck,
// releaseWatch) already treat a NULL log as empty, and the last two read only
// the deploy that is running. Batched with a yield between batches, like
// eventRetention.js, so a large backlog never holds the write lock long.

export const KEEP_NEWEST = 20;
export const MAX_AGE_DAYS = 90;
export const PRUNE_BATCH = 500;
const MAX_BATCHES = 1000;
const DAY = 86_400_000;
const FIRST_RUN_DELAY_MS = 15 * 60_000;

const sqliteTime = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
const yieldTurn = () => new Promise((r) => setImmediate(r));

/** NULL old deploy logs. Returns the number of rows cleared. */
export async function pruneDeployLogs({ now = Date.now(), db = getDb(), batch = PRUNE_BATCH } = {}) {
  const clear = db.prepare(`
    UPDATE deployments SET log = NULL WHERE id IN (
      SELECT id FROM (
        SELECT id, log, status, COALESCE(finished_at, started_at) AS at,
               ROW_NUMBER() OVER (PARTITION BY app_id, env ORDER BY id DESC) AS rn
        FROM deployments
      )
      WHERE rn > ? AND log IS NOT NULL AND at < ?
        AND status NOT IN ('live', 'pending', 'building', 'deploying')
      LIMIT ?
    )
  `);
  const cutoff = sqliteTime(now - MAX_AGE_DAYS * DAY);
  let cleared = 0;
  for (let i = 0; i < MAX_BATCHES; i++) {
    const n = clear.run(KEEP_NEWEST, cutoff, batch).changes;
    cleared += n;
    if (n < batch) break;
    await yieldTurn();
  }
  if (cleared) log.info(`[deploy-logs] retention cleared the log of ${cleared} deployment(s) older than ${MAX_AGE_DAYS} days`);
  return cleared;
}

let timers = [];

export function startDeployLogRetention() {
  if (timers.length) return;
  jobStarted('deploy-log-retention');
  const run = () => trackJob('deploy-log-retention', () => pruneDeployLogs()).catch((e) => log.warn(`[deploy-logs] retention failed: ${e.message}`));
  const first = setTimeout(run, FIRST_RUN_DELAY_MS);
  const daily = setInterval(run, DAY);
  first.unref?.();
  daily.unref?.();
  timers = [first, daily];
}

export function stopDeployLogRetention() {
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}
