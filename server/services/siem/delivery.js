import os from 'os';
import crypto from 'crypto';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { onEvent } from '../eventStore.js';
import { JOBS, jobStarted, trackJob, setJobDetail, sanitizeError } from '../jobHealth.js';
import { installId } from '../installCheckin.js';
import { toEcs, SEVERITY_RANK } from './mapping.js';
import { getAllowlist } from './netGuard.js';
import { sendSyslog } from './syslog.js';
import { sendHttps } from './https.js';
import { sendS3 } from './s3Export.js';
import { hydrate, getSinkRow, listSinkRows } from './store.js';

// Delivery: each sink replays the events table from its own durable cursor
// (siem_sinks.cursor_event_id) in id order, a bounded batch at a time. The
// cursor moves only after the destination accepted the batch, so delivery is
// at-least-once: a batch that half-succeeded is sent again, and every document
// carries a stable event.id (appcrane-<install>-<events.id>) to dedupe on.
// Failures back off exponentially with jitter. Each sink is a Job Health job
// ("siem:<id>") that turns failing once delivery has failed for longer than
// alert_after_sec or the oldest undelivered event is older than max_lag_sec.

const TICK_MS = 5_000;
const MAX_BATCHES_PER_TICK = 20;
const BACKOFF_BASE_MS = 5_000;
const BACKOFF_MAX_MS = 5 * 60_000;
const JOB_CADENCE_MS = 60_000;

const state = new Map();
let timer = null;
let unsubscribe = null;
let wakeTimer = null;
let instance = null;
let senders = { syslog: sendSyslog, https: sendHttps, s3: sendS3 };

export function jobIdFor(sinkId) {
  return `siem:${sinkId}`;
}

function ctx() {
  if (!instance) {
    try { instance = installId(); } catch (_) { instance = 'local'; }
  }
  return { instance, hostname: os.hostname() };
}

function stateFor(id) {
  if (!state.has(id)) state.set(id, { inFlight: null, nextAttemptAt: 0 });
  return state.get(id);
}

export function backoffMs(failures, random = Math.random) {
  const base = Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1), BACKOFF_MAX_MS);
  return Math.round(base * (0.5 + random() * 0.5));
}

export function matches(row, filters) {
  if (SEVERITY_RANK[row.severity] < SEVERITY_RANK[filters.min_severity || 'info']) return false;
  if (filters.kinds?.length && !filters.kinds.some(k => row.kind === k || row.kind.startsWith(`${k}.`))) return false;
  if (filters.apps?.length && !(row.app_slug && filters.apps.includes(row.app_slug))) return false;
  return true;
}

function readBatch(db, cursor, limit) {
  return db.prepare(`SELECT e.*, u.name AS user_name, su.name AS subject_user_name
      FROM events e LEFT JOIN users u ON u.id = e.user_id LEFT JOIN users su ON su.id = e.subject_user_id
     WHERE e.id > ? ORDER BY e.id LIMIT ?`).all(cursor, limit);
}

function sqliteNow() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function ageMs(ts) {
  if (!ts) return 0;
  const t = Date.parse(/[zZ]$/.test(ts) ? ts : `${String(ts).replace(' ', 'T')}Z`);
  return Number.isNaN(t) ? 0 : Date.now() - t;
}

export async function send(sink, docs) {
  return senders[sink.type](docs, sink, sink.secrets, getAllowlist());
}

/**
 * Deliver what is pending for one sink. Resolves { delivered, scanned } or
 * throws the delivery error after recording it. Never runs twice at once for
 * the same sink in this process.
 */
export function deliverSink(sinkId, { force = false } = {}) {
  const st = stateFor(sinkId);
  if (st.inFlight) return st.inFlight;
  st.inFlight = (async () => {
    const db = getDb();
    let delivered = 0;
    let scanned = 0;
    let sink = hydrate(getSinkRow(sinkId, db));
    if (!sink || !sink.enabled) return { delivered, scanned };
    if (!force && Date.now() < st.nextAttemptAt) return { delivered, scanned, waiting: true };
    const batch = sink.config.batch_size || 500;
    try {
      for (let i = 0; i < MAX_BATCHES_PER_TICK; i++) {
        const rows = readBatch(db, sink.cursor, batch);
        if (!rows.length) break;
        const picked = rows.filter(r => matches(r, sink.filters));
        if (sink.type === 's3' && !force && rows.length < batch && ageMs(rows[0].ts) < (sink.config.flush_sec || 300) * 1000) break;
        db.prepare('UPDATE siem_sinks SET last_attempt_at = ? WHERE id = ?').run(sqliteNow(), sinkId);
        if (picked.length) {
          const c = ctx();
          await send(sink, picked.map(r => toEcs(r, c)));
        }
        const last = rows[rows.length - 1].id;
        const moved = db.prepare(`UPDATE siem_sinks SET cursor_event_id = ?, delivered_count = delivered_count + ?,
            last_success_at = ?, last_error = NULL, failing_since = NULL, consecutive_failures = 0
          WHERE id = ? AND cursor_event_id = ?`).run(last, picked.length, sqliteNow(), sinkId, sink.cursor);
        delivered += picked.length;
        scanned += rows.length;
        if (!moved.changes) break;
        sink = { ...sink, cursor: last };
        st.nextAttemptAt = 0;
        if (rows.length < batch) break;
      }
      return { delivered, scanned };
    } catch (e) {
      const row = getSinkRow(sinkId, db);
      const failures = (row?.consecutive_failures || 0) + 1;
      st.nextAttemptAt = Date.now() + backoffMs(failures);
      db.prepare(`UPDATE siem_sinks SET last_error = ?, last_error_at = ?, consecutive_failures = ?,
          failing_since = COALESCE(failing_since, ?) WHERE id = ?`)
        .run(sanitizeError(e), sqliteNow(), failures, sqliteNow(), sinkId);
      throw e;
    }
  })().finally(() => { st.inFlight = null; });
  return st.inFlight;
}

/** Lag and failure state for one sink. */
export function sinkHealth(row, db = getDb()) {
  const pending = db.prepare('SELECT COUNT(*) AS n FROM (SELECT 1 FROM events WHERE id > ? LIMIT 100001)').get(row.cursor_event_id).n;
  const oldest = db.prepare('SELECT ts FROM events WHERE id > ? ORDER BY id LIMIT 1').get(row.cursor_event_id)?.ts || null;
  const cfg = hydrate(row).config;
  const lagSec = oldest ? Math.max(0, Math.round(ageMs(oldest) / 1000)) : 0;
  const failingSec = row.failing_since ? Math.round(ageMs(row.failing_since) / 1000) : 0;
  const alertAfter = cfg.alert_after_sec ?? 300;
  const maxLag = (cfg.max_lag_sec ?? 900) + (row.type === 's3' ? (cfg.flush_sec ?? 0) : 0);
  let problem = null;
  if (row.failing_since && failingSec >= alertAfter) problem = `delivery failing for ${failingSec}s: ${row.last_error || 'error'}`;
  else if (lagSec > maxLag) problem = `oldest undelivered event is ${lagSec}s old (max ${maxLag}s)`;
  return {
    lag_events: pending > 100000 ? '100000+' : pending, lag_seconds: lagSec, last_success_at: row.last_success_at,
    last_error: row.last_error, failing_since: row.failing_since, consecutive_failures: row.consecutive_failures,
    cursor_event_id: row.cursor_event_id, problem,
  };
}

function registerJob(row) {
  const id = jobIdFor(row.id);
  if (!JOBS[id]) {
    JOBS[id] = { label: `SIEM stream: ${row.name}`, cadenceMs: JOB_CADENCE_MS };
    jobStarted(id, { cadenceMs: JOB_CADENCE_MS, enabled: () => !!getSinkRow(row.id)?.enabled });
  } else {
    JOBS[id].label = `SIEM stream: ${row.name}`;
  }
  return id;
}

export function unregisterJob(sinkId) {
  delete JOBS[jobIdFor(sinkId)];
  state.delete(sinkId);
}

/** One Job Health run for a sink: deliver, then fail the run if the problem is sustained. */
export function tickSink(row) {
  const id = registerJob(row);
  return trackJob(id, async () => {
    try { await deliverSink(row.id); } catch (_) { /* recorded on the row; judged below */ }
    const h = sinkHealth(getSinkRow(row.id) || row);
    setJobDetail(id, h);
    if (h.problem) throw new Error(h.problem);
    return h;
  });
}

export async function tickAll() {
  const rows = listSinkRows();
  const live = new Set(rows.map(r => jobIdFor(r.id)));
  for (const k of Object.keys(JOBS)) if (k.startsWith('siem:') && !live.has(k)) delete JOBS[k];
  await Promise.all(rows.filter(r => r.enabled).map(r => tickSink(r).catch(() => {})));
}

function wake() {
  if (wakeTimer) return;
  wakeTimer = setTimeout(() => {
    wakeTimer = null;
    for (const r of listSinkRows()) {
      if (r.enabled && r.type !== 's3') deliverSink(r.id).catch(() => {});
    }
  }, 1000);
  wakeTimer.unref?.();
}

export function startSiemDelivery({ intervalMs = TICK_MS } = {}) {
  if (timer) return;
  for (const r of listSinkRows()) registerJob(r);
  timer = setInterval(() => { tickAll().catch(e => log.debug?.(`[siem] tick failed: ${e.message}`)); }, intervalMs);
  timer.unref?.();
  unsubscribe = onEvent(() => { try { wake(); } catch (_) {} });
}

export function stopSiemDelivery() {
  if (timer) clearInterval(timer);
  if (wakeTimer) clearTimeout(wakeTimer);
  timer = null; wakeTimer = null;
  unsubscribe?.();
  unsubscribe = null;
}

/** Send one synthetic event straight to the sink, bypassing filters and the cursor. */
export async function sendTestEvent(sinkId) {
  const sink = hydrate(getSinkRow(sinkId));
  if (!sink) throw Object.assign(new Error('Sink not found'), { status: 404 });
  const c = ctx();
  const doc = toEcs({
    id: 0, ts: new Date().toISOString(), kind: 'siem.test', severity: 'info',
    summary: 'AppCrane SIEM test event', data: { test: true },
  }, c);
  doc.event.id = `appcrane-${c.instance}-test-${crypto.randomBytes(6).toString('hex')}`;
  await send(sink, [doc]);
  return { event_id: doc.event.id };
}

export function _setSendersForTests(s) { senders = { ...senders, ...s }; }
export function _resetSiemForTests() {
  stopSiemDelivery();
  state.clear();
  instance = null;
  senders = { syslog: sendSyslog, https: sendHttps, s3: sendS3 };
  for (const k of Object.keys(JOBS)) if (k.startsWith('siem:')) delete JOBS[k];
}
