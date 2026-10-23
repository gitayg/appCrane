import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { stripUrlCredentials } from './gitCredentialScrub.js';
import { recordJobEvent } from './eventStore.js';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export const HISTORY_LIMIT = 20;
const SUCCESS_PERSIST_GAP_MS = 10 * MIN;
const ALERT_WATCH_MS = 15 * MIN;

// Every background job AppCrane reports on. cadenceMs is how often a run is
// expected; null means the job is one-shot (never late, only ok or failing).
export const JOBS = {
  'email-queue':      { label: 'E-mail queue worker',              cadenceMs: 5_000 },
  'vuln-scan':        { label: 'Daily vulnerability scan + digest', cadenceMs: DAY },
  'local-backup':     { label: 'Nightly local backup',             cadenceMs: DAY },
  'offsite-backup':   { label: 'Nightly off-site (S3) backup',      cadenceMs: DAY },
  'request-digest':   { label: 'Daily pending-request digest',      cadenceMs: DAY },
  'credential-check': { label: 'Platform credential checker',       cadenceMs: 15 * MIN },
  'metrics-sampler':  { label: 'Container metrics sampler',         cadenceMs: 5 * MIN },
  'github-pr-poller': { label: 'GitHub PR poller',                  cadenceMs: 5 * MIN },
  'disk-quota':       { label: 'Disk quota sweep',                  cadenceMs: 15 * MIN },
  'cron-scheduler':   { label: 'App cron scheduler',                cadenceMs: MIN },
  'crew-retention':   { label: 'Crew history retention',            cadenceMs: DAY },
  'db-auth-alerts':   { label: 'Managed database login alerts',     cadenceMs: 3 * MIN },
  'gh-mcp-reaper':    { label: 'GitHub MCP container reaper',       cadenceMs: MIN },
  'coder-idle-sweep': { label: 'Idle coder container sweep',        cadenceMs: 5 * MIN },
  'host-resources':   { label: 'Server memory and disk check',      cadenceMs: 5 * MIN },
  'whats-new-mail':   { label: "What's New mail (once per release)", cadenceMs: null },
  'event-retention':  { label: 'Event store retention',             cadenceMs: DAY },
  'api-key-expiry':   { label: 'API key expiry sweep and warnings', cadenceMs: 5 * MIN },
  'audit-chain':      { label: 'Audit chain sealer and verifier',   cadenceMs: 5 * MIN },
  'restore-drill':    { label: 'Scheduled restore drill',           cadenceMs: 7 * DAY },
  'access-reviews':   { label: 'Access review campaigns and reminders', cadenceMs: 60 * MIN },
  'auto-patch':       { label: 'RCE auto-patch worker',             cadenceMs: 15 * MIN },
  'runtime-patch':    { label: 'Runtime auto-patch (PHP, Node.js)', cadenceMs: 60 * MIN },
  'mongo-kernel':     { label: 'Managed MongoDB kernel check',      cadenceMs: 6 * HOUR },
  'node-runtime':     { label: 'AppCrane Node.js security check',   cadenceMs: 6 * HOUR },
};

const started = new Map();
const active = new Map();
const lastRun = new Map();
const lastPersisted = new Map();
const counters = new Map();
const details = new Map();
let watchTimer = null;
let alertsEnabled = false;

function graceFor(cadenceMs) {
  return Math.max(cadenceMs * 0.25, 2 * MIN);
}

function windowFor(cadenceMs) {
  return cadenceMs + graceFor(cadenceMs);
}

function cadenceOf(id) {
  return started.get(id)?.cadenceMs ?? JOBS[id]?.cadenceMs ?? null;
}

export function sanitizeError(err) {
  try {
    let s = String(err?.message ?? err ?? '').slice(0, 4000);
    s = stripUrlCredentials(s);
    s = s.replace(/\b(dhk_[a-z]+_)[A-Za-z0-9_-]+/gi, '$1[redacted]');
    s = s.replace(/\b(gh[pousr]_|github_pat_|sk-ant-|sk-|xox[abpr]-)[A-Za-z0-9_-]+/g, '$1[redacted]');
    s = s.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted]');
    s = s.replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]');
    s = s.replace(/((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|signature|credential)s?["']?\s*[:=]\s*["']?)[^\s"'&,;]+/gi, '$1[redacted]');
    s = s.replace(/[A-Za-z0-9+/_-]{32,}={0,2}/g, '[redacted]');
    s = s.replace(/(^|[\s'"(=])(\/[^\s'"]*\/)([^\s/'"]+)/g, '$1.../$3');
    s = s.replace(/\s+/g, ' ').trim();
    return s.length > 300 ? s.slice(0, 297) + '...' : s;
  } catch (_) {
    return 'error (details withheld)';
  }
}

/** Mark a job's scheduler as running in this process. Never throws. */
export function jobStarted(id, opts = {}) {
  try {
    started.set(id, {
      at: Date.now(),
      cadenceMs: opts.cadenceMs ?? JOBS[id]?.cadenceMs ?? null,
      enabled: typeof opts.enabled === 'function' ? opts.enabled : null,
    });
  } catch (_) { /* reporting never breaks a job */ }
}

/** For a job that catches its own errors: mark the run in progress as failed. */
export function noteJobFailure(id, err) {
  try {
    const run = active.get(id);
    if (run) { run.error = err ?? new Error('failed'); return; }
    const now = Date.now();
    record(id, { startedAt: now, finishedAt: now, error: err ?? new Error('failed') });
  } catch (_) { /* reporting never breaks a job */ }
}

/**
 * Run `fn` as one run of job `id`, recording start, outcome and duration.
 * Returns what `fn` returns and rethrows what `fn` throws, so wrapping a tick
 * changes nothing about the job; a failure to record is swallowed.
 */
export async function trackJob(id, fn) {
  const run = { startedAt: Date.now(), error: null };
  try { active.set(id, run); } catch (_) {}
  let thrown = null;
  try {
    return await fn();
  } catch (e) {
    thrown = e;
    throw e;
  } finally {
    try {
      active.delete(id);
      record(id, { startedAt: run.startedAt, finishedAt: Date.now(), error: thrown ?? run.error });
    } catch (_) { /* reporting never breaks a job */ }
  }
}

/** Synchronous twin of trackJob, for ticks that must stay synchronous. */
export function trackJobSync(id, fn) {
  const run = { startedAt: Date.now(), error: null };
  try { active.set(id, run); } catch (_) {}
  let thrown = null;
  try {
    return fn();
  } catch (e) {
    thrown = e;
    throw e;
  } finally {
    try {
      active.delete(id);
      record(id, { startedAt: run.startedAt, finishedAt: Date.now(), error: thrown ?? run.error });
    } catch (_) { /* reporting never breaks a job */ }
  }
}

/** Attach what a job last observed (host-resources: memory and disk) to its Job Health row. */
export function setJobDetail(id, detail) {
  try { details.set(id, detail); } catch (_) {}
}

export function isJobRunning(id) {
  return active.has(id);
}

function record(id, { startedAt, finishedAt, error }) {
  const ok = !error;
  const entry = {
    started_at: new Date(startedAt).toISOString(),
    finished_at: new Date(finishedAt).toISOString(),
    ok,
    duration_ms: Math.max(0, finishedAt - startedAt),
    error: ok ? null : sanitizeError(error),
  };
  const prev = lastRun.get(id);
  lastRun.set(id, entry);
  const c = counters.get(id) || { runs: 0, failures: 0 };
  c.runs++;
  if (!ok) c.failures++;
  counters.set(id, c);

  const persisted = lastPersisted.get(id);
  const changed = !prev || prev.ok !== ok;
  const stale = !persisted || finishedAt - persisted >= SUCCESS_PERSIST_GAP_MS;
  if (!ok || changed || stale) {
    try {
      persist(id, entry);
      lastPersisted.set(id, finishedAt);
    } catch (e) {
      log.debug?.(`[job-health] could not record ${id}: ${e.message}`);
    }
  }
  if (alertsEnabled && !ok && prev?.ok !== false) {
    try { alertAdmins(id, 'failing', entry.error); } catch (_) {}
  }
  recordJobEvent(id, JOBS[id]?.label, prev?.ok, entry);
}

function persist(id, entry) {
  const db = getDb();
  db.prepare(`INSERT INTO job_runs (job, started_at, finished_at, ok, duration_ms, error)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, entry.started_at, entry.finished_at, entry.ok ? 1 : 0, entry.duration_ms, entry.error);
  db.prepare(`DELETE FROM job_runs WHERE job = ? AND id NOT IN
              (SELECT id FROM job_runs WHERE job = ? ORDER BY id DESC LIMIT ?)`)
    .run(id, id, HISTORY_LIMIT);
}

function historyFor(db, id) {
  return db.prepare(`SELECT started_at, finished_at, ok, duration_ms, error FROM job_runs
                     WHERE job = ? ORDER BY id DESC LIMIT ?`)
    .all(id, HISTORY_LIMIT)
    .map(r => ({ ...r, ok: r.ok === 1 }));
}

/** Pure status rule, exported for tests. */
export function computeStatus({ cadenceMs, startedAt, enabled, last, running }, now = Date.now()) {
  if (enabled === false) return 'disabled';
  if (startedAt == null && !running) return 'disabled';
  if (!last) {
    if (cadenceMs != null && !running && now - startedAt > windowFor(cadenceMs)) return 'late';
    return 'never-run';
  }
  if (!last.ok) return 'failing';
  if (cadenceMs != null && !running && now - Date.parse(last.finished_at) > windowFor(cadenceMs)) return 'late';
  return 'ok';
}

function queueDepth(db) {
  try {
    const rows = db.prepare('SELECT status, COUNT(*) AS n FROM email_queue GROUP BY status').all();
    const by = Object.fromEntries(rows.map(r => [r.status, r.n]));
    const oldest = db.prepare("SELECT MIN(created_at) AS t FROM email_queue WHERE status = 'queued'").get()?.t || null;
    return { queued: by.queued || 0, sending: by.sending || 0, failed: by.failed || 0, oldest_queued_at: oldest };
  } catch (_) {
    return null;
  }
}

export function getJobHealth(now = Date.now()) {
  const db = getDb();
  return Object.entries(JOBS).map(([id, meta]) => {
    const s = started.get(id);
    const history = historyFor(db, id);
    const last = lastRun.get(id) || history[0] || null;
    let enabled = null;
    if (s?.enabled) { try { enabled = !!s.enabled(); } catch (_) { enabled = null; } }
    const cadenceMs = cadenceOf(id);
    const running = active.has(id);
    let status = computeStatus({ cadenceMs, startedAt: s?.at ?? null, enabled, last, running }, now);
    if (status === 'ok' && details.get(id)?.severity === 'warning') status = 'warning';
    const base = last ? Date.parse(last.finished_at) : s?.at ?? null;
    const next = cadenceMs != null && base != null && status !== 'disabled'
      ? new Date(base + cadenceMs).toISOString() : null;
    const lastFailure = last && !last.ok ? last : history.find(h => !h.ok) || null;
    const job = {
      id,
      label: meta.label,
      cadence_ms: cadenceMs,
      status,
      running,
      started_in_process: !!s,
      last_run: last,
      next_expected_run: next,
      late_after: cadenceMs != null && base != null ? new Date(base + windowFor(cadenceMs)).toISOString() : null,
      last_error: lastFailure?.error || null,
      since_boot: counters.get(id) || { runs: 0, failures: 0 },
      history,
    };
    if (id === 'email-queue') job.queue = queueDepth(db);
    if (details.has(id)) job.detail = details.get(id);
    return job;
  });
}

function platformAdminEmails(db) {
  return db.prepare(
    "SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL"
  ).all().map(r => r.email);
}

/**
 * E-mail every platform admin once per job, status and day. The idempotency key
 * is unique for source 'job-health' (migration 130), so a second alert the same
 * day fails the insert instead of sending twice.
 */
export function alertAdmins(id, status, error) {
  return import('./emailQueue.js').then(({ enqueueEmail }) => {
    const db = getDb();
    const day = new Date().toISOString().slice(0, 10);
    const label = JOBS[id]?.label || id;
    const subject = `AppCrane background job ${status}: ${label}`;
    const text = status === 'failing'
      ? `The background job "${label}" failed its last run.\n\nError: ${error || '(none)'}\n\nSee Settings > Job Health.`
      : `The background job "${label}" has not run within its expected window.\n\nSee Settings > Job Health.`;
    for (const to of platformAdminEmails(db)) {
      try {
        enqueueEmail({ to, subject, text, appId: null, source: 'job-health',
          idempotencyKey: `job-health:${id}:${status}:${day}:${to}` });
      } catch (e) {
        if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[job-health] alert to admin skipped: ${e.message}`);
      }
    }
  }).catch(() => {});
}

/** Turn on admin e-mail alerts (failing at once, late every 15 minutes). */
export function enableJobHealthAlerts() {
  alertsEnabled = true;
  if (watchTimer) return;
  watchTimer = setInterval(() => { try { alertOnUnhealthy(); } catch (_) {} }, ALERT_WATCH_MS);
  watchTimer.unref?.();
}

export function alertOnUnhealthy(now = Date.now()) {
  for (const j of getJobHealth(now)) {
    if (j.status === 'late') alertAdmins(j.id, 'late', null);
    if (j.status === 'late') recordJobEvent(j.id, j.label, null, 'late');
  }
}

export function _resetJobHealthForTests() {
  started.clear(); active.clear(); lastRun.clear(); lastPersisted.clear(); counters.clear(); details.clear();
  if (watchTimer) { clearInterval(watchTimer); watchTimer = null; }
  alertsEnabled = false;
}
