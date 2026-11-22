import os from 'os';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { JOBS, jobStarted, trackJob, sanitizeError } from '../jobHealth.js';
import { installId } from '../installCheckin.js';
import { hydrate } from '../siem/store.js';
import { backoffMs } from '../siem/delivery.js';
import { sendSyslog } from '../siem/syslog.js';
import { sendHttps } from '../siem/https.js';
import { sendS3 } from '../siem/s3Export.js';
import { toAppAuditEcs } from './mapping.js';
import { onAppAuditEvent } from './store.js';
import { ownerAllowlist, platformPolicy, listStreamRows } from './streams.js';

// Delivery for owner audit streams, the SIEM delivery model (durable cursor,
// at-least-once, exponential backoff) over app_audit_events. The batch query
// is WHERE app_id = <the stream's app>: that one clause is what keeps a stream
// to its own app's events.

const TICK_MS = 10_000;
const BATCH = 500;
const MAX_BATCHES = 20;
export const JOB_ID = 'app-audit-streams';

const state = new Map();
let senders = { syslog: sendSyslog, https: sendHttps, s3: sendS3 };
let timer = null;
let unsubscribe = null;
let instance = null;
let wakeTimer = null;
const woken = new Set();

function ctx() {
  if (!instance) { try { instance = installId(); } catch (_) { instance = 'local'; } }
  return { instance, hostname: os.hostname() };
}

const sqliteNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);

function matchesActions(action, actions) {
  return !actions?.length || actions.some(a => action === a || (a.endsWith('.') ? action.startsWith(a) : action.startsWith(`${a}.`)));
}

/** Deliver what is pending for one stream. Resolves { delivered, scanned }; throws after recording a failure. */
export function deliverStream(streamId, { force = false } = {}) {
  const st = state.get(streamId) || { inFlight: null, nextAttemptAt: 0 };
  state.set(streamId, st);
  if (st.inFlight) return st.inFlight;
  st.inFlight = (async () => {
    const db = getDb();
    const row = db.prepare('SELECT * FROM app_audit_streams WHERE id = ?').get(streamId);
    if (!row || !row.enabled || !platformPolicy(db).owner_streams_enabled) return { delivered: 0, scanned: 0 };
    if (!force && Date.now() < st.nextAttemptAt) return { delivered: 0, scanned: 0, waiting: true };
    const sink = hydrate({ ...row, filter_kinds: null, filter_apps: null, min_severity: 'info' });
    const actions = row.filter_actions ? JSON.parse(row.filter_actions) : null;
    let cursor = row.cursor_event_id;
    let delivered = 0;
    let scanned = 0;
    try {
      for (let i = 0; i < MAX_BATCHES; i++) {
        const rows = db.prepare('SELECT * FROM app_audit_events WHERE app_id = ? AND id > ? ORDER BY id LIMIT ?').all(row.app_id, cursor, BATCH);
        if (!rows.length) break;
        db.prepare('UPDATE app_audit_streams SET last_attempt_at = ? WHERE id = ?').run(sqliteNow(), streamId);
        const picked = rows.filter(r => matchesActions(r.action, actions));
        if (picked.length) {
          const c = ctx();
          await senders[sink.type](picked.map(r => toAppAuditEcs(r, c)), sink, sink.secrets, ownerAllowlist(db));
        }
        const last = rows[rows.length - 1].id;
        const moved = db.prepare(`UPDATE app_audit_streams SET cursor_event_id = ?, delivered_count = delivered_count + ?,
            last_success_at = ?, last_error = NULL, failing_since = NULL, consecutive_failures = 0
          WHERE id = ? AND cursor_event_id = ?`).run(last, picked.length, sqliteNow(), streamId, cursor);
        delivered += picked.length;
        scanned += rows.length;
        if (!moved.changes) break;
        cursor = last;
        st.nextAttemptAt = 0;
        if (rows.length < BATCH) break;
      }
      return { delivered, scanned };
    } catch (e) {
      const failures = (db.prepare('SELECT consecutive_failures AS n FROM app_audit_streams WHERE id = ?').get(streamId)?.n || 0) + 1;
      st.nextAttemptAt = Date.now() + backoffMs(failures);
      db.prepare(`UPDATE app_audit_streams SET last_error = ?, last_error_at = ?, consecutive_failures = ?,
          failing_since = COALESCE(failing_since, ?) WHERE id = ?`).run(sanitizeError(e), sqliteNow(), failures, sqliteNow(), streamId);
      throw e;
    }
  })().finally(() => { st.inFlight = null; });
  return st.inFlight;
}

export async function tickAllStreams() {
  if (!platformPolicy().owner_streams_enabled) return;
  await Promise.all(listStreamRows().filter(r => r.enabled).map(r => deliverStream(r.id).catch(() => {})));
}

export function startAppAuditDelivery({ intervalMs = TICK_MS } = {}) {
  if (timer) return;
  JOBS[JOB_ID] ??= { label: 'App audit streams', cadenceMs: 60_000 };
  jobStarted(JOB_ID, { cadenceMs: 60_000 });
  timer = setInterval(() => { trackJob(JOB_ID, () => tickAllStreams()).catch(e => log.debug?.(`[app-audit] tick failed: ${e.message}`)); }, intervalMs);
  timer.unref?.();
  unsubscribe = onAppAuditEvent((id, appId) => {
    woken.add(appId);
    if (wakeTimer) return;
    wakeTimer = setTimeout(() => {
      wakeTimer = null;
      const apps = [...woken];
      woken.clear();
      for (const a of apps) for (const r of listStreamRows(a)) if (r.enabled && r.type !== 's3') deliverStream(r.id).catch(() => {});
    }, 1000);
    wakeTimer.unref?.();
  });
}

export function stopAppAuditDelivery() {
  if (timer) clearInterval(timer);
  if (wakeTimer) clearTimeout(wakeTimer);
  timer = null;
  wakeTimer = null;
  woken.clear();
  unsubscribe?.();
  unsubscribe = null;
}

/** One synthetic event straight to the stream, bypassing the cursor. */
export async function sendStreamTest(row) {
  const sink = hydrate({ ...row, filter_kinds: null, filter_apps: null, min_severity: 'info' });
  const c = ctx();
  const doc = toAppAuditEcs({
    id: 0, app_id: row.app_id, app_slug: row.app_slug || String(row.app_id), action: 'appcrane.stream_test', occurred_at: new Date().toISOString(),
    created_at: sqliteNow(), actor_type: 'app', actor_id: 'appcrane', actor_verified: 1, targets: '[]', context: '{}',
  }, c);
  await senders[sink.type]([doc], sink, sink.secrets, ownerAllowlist());
  return { event_id: doc.event.id };
}

export function _setStreamSendersForTests(s) { senders = { ...senders, ...s }; }
export function _resetAppAuditDeliveryForTests() {
  stopAppAuditDelivery();
  state.clear();
  senders = { syslog: sendSyslog, https: sendHttps, s3: sendS3 };
}
