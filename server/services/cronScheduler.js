/**
 * Host-side cron scheduler for app_cron_jobs.
 *
 * Why host-side, not in-container: containers come and go on every deploy.
 * A `schedule.every().day` loop inside the container is fine on the happy
 * path but: (a) every app reimplements the same primitive, (b) it doesn't
 * survive a deploy that lands while the loop is mid-tick, and (c) "did my
 * 00:00 UTC job fire" gets answered by reading the container's stderr
 * instead of one canonical row.
 *
 * What this does: every 60 seconds, walks app_cron_jobs WHERE enabled = 1
 * with the current wall-clock; for any whose `schedule` matches the
 * current minute, fires a one-off `docker exec` against the app's
 * container with the configured `command`. Records exit code + last 4 KB
 * of stdout/stderr on the row. Per-job mutex prevents overlap if the
 * previous run is still going.
 *
 * What this does NOT do: complex cron features (named days, range steps
 * mixed with lists, ranges with steps, year fields, @reboot). The five
 * fields are minute / hour / day-of-month / month / day-of-week, and each
 * supports `*`, integer literal, comma-list of integers, `*` -or-
 * integer/range with `/step`, and `a-b` ranges. Good enough for "rebuild
 * this dataset every day at midnight" and most other periodic-task shapes.
 */

import { execFile } from 'child_process';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

const TICK_MS = 60_000;
const LOG_TAIL_BYTES = 4096;
const runningJobs = new Set(); // per-job mutex, keyed by `${app_id}:${env}:${name}`
let timer = null;

// ── Cron expression parser ──────────────────────────────────────────────────

const FIELD_RANGES = [
  [0, 59], // minute
  [0, 23], // hour
  [1, 31], // day of month
  [1, 12], // month
  [0, 6],  // day of week (Sunday = 0)
];

/**
 * Parse one cron field into a Set of matching integers. Supports:
 *   `*`              → every value in range
 *   `5`              → exactly 5
 *   `1,3,5`          → 1 or 3 or 5
 *   `1-5`            → 1 through 5
 *   `* /15`          → 0, 15, 30, 45  (every 15)
 *   `0-30/5`         → 0, 5, 10, 15, 20, 25, 30
 *
 * Throws on out-of-range, malformed, or unsupported syntax.
 */
function parseField(token, [lo, hi]) {
  const result = new Set();
  for (const part of String(token).split(',')) {
    const [rangeSpec, stepSpec] = part.split('/');
    const step = stepSpec === undefined ? 1 : parseInt(stepSpec, 10);
    if (!Number.isFinite(step) || step <= 0) throw new Error(`Invalid step in "${part}"`);

    let start, end;
    if (rangeSpec === '*') {
      start = lo; end = hi;
    } else if (rangeSpec.includes('-')) {
      const [a, b] = rangeSpec.split('-').map(s => parseInt(s, 10));
      if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error(`Invalid range "${rangeSpec}"`);
      start = a; end = b;
    } else {
      const n = parseInt(rangeSpec, 10);
      if (!Number.isFinite(n)) throw new Error(`Invalid number "${rangeSpec}"`);
      start = n; end = n;
    }
    if (start < lo || end > hi || start > end) {
      throw new Error(`"${part}" out of range [${lo}-${hi}]`);
    }
    for (let i = start; i <= end; i += step) result.add(i);
  }
  return result;
}

/** Parse a 5-field cron expression into five Sets. Throws on bad input. */
export function parseCron(expr) {
  const fields = String(expr).trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(`Cron expression must have exactly 5 fields (got ${fields.length})`);
  }
  return fields.map((f, i) => parseField(f, FIELD_RANGES[i]));
}

/** True if `now` matches the parsed cron sets. UTC-based. */
export function matchesAtUtc(parsed, now) {
  const [minute, hour, dom, month, dow] = parsed;
  if (!minute.has(now.getUTCMinutes()))    return false;
  if (!hour.has(now.getUTCHours()))        return false;
  if (!month.has(now.getUTCMonth() + 1))   return false;

  // Standard cron rule: if BOTH dom and dow are constrained (not `*`), match
  // when EITHER hits. If only one is constrained, that one must match.
  const domAll = dom.size === 31;
  const dowAll = dow.size === 7;
  const domHit = dom.has(now.getUTCDate());
  const dowHit = dow.has(now.getUTCDay());
  if (domAll && dowAll) return true;
  if (domAll) return dowHit;
  if (dowAll) return domHit;
  return domHit || dowHit;
}

// ── Sync from deployhub.json ────────────────────────────────────────────────

/**
 * Replace the cron rows for (app_id, env) with what the manifest declares.
 * Removes rows that no longer appear; upserts the rest. Idempotent — safe to
 * call on every deploy.
 *
 * @param {number} appId
 * @param {'sandbox'|'production'} env
 * @param {Array<{name,schedule,command,enabled?,timeout_seconds?}>|undefined} cronArray
 */
export function syncCronJobsFromManifest(appId, env, cronArray) {
  const db = getDb();
  const jobs = Array.isArray(cronArray) ? cronArray : [];

  // Validate everything up front so a bad entry doesn't leave half-synced state.
  for (const j of jobs) {
    if (!j || typeof j.name !== 'string' || !j.name.trim()) {
      throw new Error('Each cron entry needs a non-empty "name"');
    }
    if (typeof j.schedule !== 'string') throw new Error(`cron[${j.name}]: schedule must be a string`);
    if (typeof j.command !== 'string' || !j.command.trim()) {
      throw new Error(`cron[${j.name}]: command must be a non-empty string`);
    }
    try { parseCron(j.schedule); }
    catch (e) { throw new Error(`cron[${j.name}]: invalid schedule "${j.schedule}" — ${e.message}`); }
  }

  const keepNames = new Set(jobs.map(j => j.name));
  const tx = db.transaction(() => {
    // Remove rows for this (app, env) whose name is no longer in the manifest.
    const existing = db.prepare('SELECT name FROM app_cron_jobs WHERE app_id = ? AND env = ?').all(appId, env);
    for (const row of existing) {
      if (!keepNames.has(row.name)) {
        db.prepare('DELETE FROM app_cron_jobs WHERE app_id = ? AND env = ? AND name = ?').run(appId, env, row.name);
      }
    }
    // Upsert the rest.
    const upsert = db.prepare(`
      INSERT INTO app_cron_jobs (app_id, env, name, schedule, command, enabled, timeout_seconds)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(app_id, env, name) DO UPDATE SET
        schedule        = excluded.schedule,
        command         = excluded.command,
        enabled         = excluded.enabled,
        timeout_seconds = excluded.timeout_seconds,
        updated_at      = datetime('now')
    `);
    for (const j of jobs) {
      upsert.run(
        appId, env, j.name, j.schedule, j.command,
        j.enabled === false ? 0 : 1,
        Number.isFinite(j.timeout_seconds) && j.timeout_seconds > 0
          ? Math.min(parseInt(j.timeout_seconds, 10), 3600)
          : 600,
      );
    }
  });
  tx();
  return { synced: jobs.length, removed: keepNames.size === 0 ? 'all' : undefined };
}

// ── Execution ───────────────────────────────────────────────────────────────

const containerName = (slug, env) => `appcrane-${slug}-${env}`;

function runDockerExec(slug, env, command, timeoutSeconds) {
  return new Promise((resolve) => {
    const args = ['exec', containerName(slug, env), 'sh', '-c', command];
    const child = execFile('docker', args, {
      timeout: timeoutSeconds * 1000,
      maxBuffer: LOG_TAIL_BYTES * 4,
    }, (err, stdout, stderr) => {
      const combined = (String(stdout || '') + (stderr ? `\n${stderr}` : '')).slice(-LOG_TAIL_BYTES);
      if (err) {
        return resolve({
          exitCode: typeof err.code === 'number' ? err.code : 1,
          log: combined || err.message,
          error: err.message,
        });
      }
      resolve({ exitCode: 0, log: combined, error: null });
    });
    child.on('error', () => { /* covered by callback */ });
  });
}

/**
 * Run a single cron job NOW, regardless of schedule. Used by the tick loop
 * (when due) and by the appcrane_run_cron_now MCP tool for manual triggers.
 * Records last_run_at / last_exit_code / last_log on the row.
 */
export async function runCronJob(jobRow) {
  const key = `${jobRow.app_id}:${jobRow.env}:${jobRow.name}`;
  if (runningJobs.has(key)) {
    log.info(`[cron] skip ${key} — previous run still in flight`);
    return { skipped: true, reason: 'previous run still in flight' };
  }
  runningJobs.add(key);
  const db = getDb();
  try {
    const app = db.prepare('SELECT slug FROM apps WHERE id = ?').get(jobRow.app_id);
    if (!app) return { skipped: true, reason: 'app not found' };

    const startedAt = new Date().toISOString();
    log.info(`[cron] running ${key} (${jobRow.schedule}) → ${jobRow.command}`);
    const result = await runDockerExec(app.slug, jobRow.env, jobRow.command, jobRow.timeout_seconds);
    const finishedAt = new Date().toISOString();

    const logHeader = `[${startedAt} → ${finishedAt}, exit=${result.exitCode}]\n`;
    const persistedLog = (logHeader + (result.log || '')).slice(-LOG_TAIL_BYTES);

    db.prepare(`
      UPDATE app_cron_jobs
      SET last_run_at = ?, last_exit_code = ?, last_log = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(finishedAt, result.exitCode, persistedLog, jobRow.id);

    if (result.exitCode === 0) {
      log.info(`[cron] ✓ ${key} exit=0`);
    } else {
      log.warn(`[cron] ✗ ${key} exit=${result.exitCode}: ${(result.error || result.log || '').slice(0, 200)}`);
    }
    return { ran: true, exitCode: result.exitCode, log: persistedLog };
  } finally {
    runningJobs.delete(key);
  }
}

// ── Tick loop ───────────────────────────────────────────────────────────────

async function tick() {
  try {
    const db = getDb();
    const now = new Date();
    // Round to the current minute boundary (the schedule fields don't go
    // finer than minutes) so identical wall-clocks don't double-fire on
    // back-to-back ticks.
    now.setUTCSeconds(0, 0);

    const jobs = db.prepare(`
      SELECT j.id, j.app_id, j.env, j.name, j.schedule, j.command, j.timeout_seconds, j.last_run_at
      FROM app_cron_jobs j
      WHERE j.enabled = 1
    `).all();

    for (const job of jobs) {
      // Already ran this minute? skip.
      if (job.last_run_at && job.last_run_at.startsWith(now.toISOString().slice(0, 16))) continue;
      let parsed;
      try { parsed = parseCron(job.schedule); }
      catch (_) { continue; } // bad schedule — already logged at sync time; don't spam
      if (!matchesAtUtc(parsed, now)) continue;

      // Fire — don't await; one slow job shouldn't block the rest of the tick.
      runCronJob(job).catch(e => log.error(`[cron] runCronJob threw: ${e.message}`));
    }
  } catch (e) {
    log.error(`[cron] tick error: ${e.message}`);
  }
}

/** Start the scheduler. Idempotent — second call is a no-op. */
export function startCronScheduler() {
  if (timer) return;
  log.info(`[cron] scheduler started (tick every ${TICK_MS / 1000}s)`);
  timer = setInterval(tick, TICK_MS);
  // Don't fire immediately — wait for the first minute boundary tick.
  // (Test setups can call tick() directly.)
}

/** Stop the scheduler. Idempotent. */
export function stopCronScheduler() {
  if (timer) { clearInterval(timer); timer = null; }
}
