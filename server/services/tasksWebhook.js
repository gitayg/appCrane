// Tasks webhook: an app may register one https URL; AppCrane POSTs every
// change a PERSON made in the dashboard (reply, status change, delete) to it.
// The app's own API calls are not echoed back. The poll feed
// (GET /api/service/tasks/events?since=) carries every event and is the
// source of truth; the webhook is a prompt to poll sooner, so a missed
// delivery loses nothing.
//
// This is an outbound request to a URL an app chose: SSRF. Same guard as Crew
// push (crewPush.js), from remoteFetch.js: https only, no userinfo, the host
// checked when the URL is set AND at connect time through makeGuardedLookup
// (the address checked is the address dialled), IP literals checked directly,
// redirects never followed, 10 s timeout, response body discarded unread.
//
// Each body is signed: X-AppCrane-Signature = "sha256=" + hex HMAC-SHA256 of
// "<X-AppCrane-Timestamp>.<raw body>", keyed with the app's own
// APPCRANE_SERVICE_TOKEN, which the app already holds. No second secret.

import crypto from 'crypto';
import https from 'https';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { makeGuardedLookup, assertHostNotBlocked, isBlockedAddress } from './remoteFetch.js';
import { getServiceTokenPlaintext } from './appServiceToken.js';
import { renderEvent } from './tasksEvents.js';
import log from '../utils/logger.js';

export const WEBHOOK_LIMITS = Object.freeze({
  URL_MAX: 2048,
  TIMEOUT_MS: 10_000,
  RESPONSE_MAX_BYTES: 64 * 1024,
  MAX_CONSECUTIVE_FAILURES: 20,
});

const DEFAULT_DELAYS_MS = [2_000, 15_000];

let config = { post: null, delays: DEFAULT_DELAYS_MS, resolve: undefined, isBlocked: isBlockedAddress };

/** Tests only: replace the poster, retry delays and address guard inputs. */
export function configureTaskWebhooks(overrides = {}) {
  config = { ...config, ...overrides };
}

function badUrl(msg, code = 'WEBHOOK_URL_INVALID') { return new AppError(msg, 400, code); }

/** Validate an app's webhook URL, including where its name resolves today. */
export async function validateWebhookUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) throw badUrl('url must be a non-empty string');
  const s = raw.trim();
  if (s.length > WEBHOOK_LIMITS.URL_MAX) throw badUrl(`url must be at most ${WEBHOOK_LIMITS.URL_MAX} characters`);
  let u;
  try { u = new URL(s); } catch { throw badUrl('url must be an absolute https URL'); }
  if (u.protocol !== 'https:') throw badUrl('url must use https');
  if (u.username || u.password) throw badUrl('url must not carry credentials');
  await new Promise((resolve, reject) => {
    makeGuardedLookup({ ...(config.resolve ? { resolve: config.resolve } : {}), isBlocked: config.isBlocked })(
      u.hostname.replace(/^\[(.*)\]$/, '$1'), { all: true },
      (err) => {
        if (!err) return resolve();
        if (err.code === 'EBLOCKEDADDRESS') return reject(badUrl('url resolves to a private, loopback or link-local address', 'WEBHOOK_URL_BLOCKED'));
        return reject(badUrl('url host does not resolve'));
      });
  });
  return u.toString();
}

export function getWebhook(appId) {
  const row = getDb().prepare('SELECT * FROM task_app_settings WHERE app_id = ?').get(appId);
  return {
    url: row?.webhook_url || null,
    last_status: row?.last_status || null,
    last_attempt_at: row?.last_attempt_at || null,
    consecutive_failures: row?.consecutive_failures || 0,
  };
}

export function setWebhook(appId, url) {
  getDb().prepare(`
    INSERT INTO task_app_settings (app_id, webhook_url, consecutive_failures, last_status, updated_at)
    VALUES (?, ?, 0, NULL, ?)
    ON CONFLICT(app_id) DO UPDATE SET webhook_url = excluded.webhook_url, consecutive_failures = 0,
      last_status = NULL, updated_at = excluded.updated_at
  `).run(appId, url, new Date().toISOString());
  return getWebhook(appId);
}

/**
 * POST a JSON body to an https URL with the address guard. Resolves (never
 * rejects) to { ok, status?, reason, permanent? }; `reason` never carries the
 * URL, a header or a response body.
 */
export function postJsonSafely(rawUrl, { headers = {}, body = '', timeoutMs = WEBHOOK_LIMITS.TIMEOUT_MS, isBlocked = isBlockedAddress, lookup, ca } = {}) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(rawUrl);
      if (url.protocol !== 'https:') return resolve({ ok: false, reason: 'not_https', permanent: true });
      assertHostNotBlocked(url, isBlocked);
    } catch (e) {
      return resolve({ ok: false, reason: e.code === 'EBLOCKEDADDRESS' ? 'blocked_address' : 'bad_url', permanent: true });
    }
    const payload = Buffer.from(body, 'utf8');
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    const req = https.request(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json', 'Content-Length': payload.length, 'User-Agent': 'AppCrane-Tasks-Webhook/1' },
      lookup: lookup || makeGuardedLookup({ isBlocked }),
      ca,
      timeout: timeoutMs,
      agent: false,
    }, (res) => {
      const status = res.statusCode || 0;
      let seen = 0;
      res.on('data', (chunk) => { seen += chunk.length; if (seen > WEBHOOK_LIMITS.RESPONSE_MAX_BYTES) res.destroy(); });
      res.on('error', () => {});
      res.resume();
      if (status >= 300 && status < 400) return done({ ok: false, status, reason: 'redirect_refused' });
      done({ ok: status >= 200 && status < 300, status, reason: status >= 200 && status < 300 ? 'ok' : `http_${status}` });
    });
    req.on('timeout', () => { req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })); });
    req.on('error', (e) => {
      if (e.code === 'EBLOCKEDADDRESS') return done({ ok: false, reason: 'blocked_address', permanent: true });
      done({ ok: false, reason: e.code === 'ETIMEDOUT' ? 'timeout' : (e.code || 'network_error') });
    });
    req.end(payload);
  });
}

export function signBody(token, timestamp, body) {
  return 'sha256=' + crypto.createHmac('sha256', token).update(`${timestamp}.${body}`).digest('hex');
}

// One chain per app keeps an app's deliveries in event order.
const chains = new Map();

async function deliver(appId, eventId) {
  const db = getDb();
  const ev = db.prepare('SELECT * FROM task_events WHERE id = ?').get(eventId);
  if (!ev) return;
  const body = JSON.stringify({ type: `task.${ev.kind}`, event: renderEvent(db, ev) });
  const post = config.post || postJsonSafely;
  const delays = config.delays;
  let last = null;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    if (attempt > 0) await new Promise((r) => { const t = setTimeout(r, delays[attempt - 1]); t.unref?.(); });
    // Re-read before every attempt: the app may be gone, its URL changed or
    // removed, or its token rotated while we waited.
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
    const url = app ? getWebhook(appId).url : null;
    if (!url) return;
    const token = getServiceTokenPlaintext(app);
    if (!token) { last = { ok: false, reason: 'no_service_token', permanent: true }; break; }
    const ts = String(Math.floor(Date.now() / 1000));
    last = await post(url, {
      headers: { 'X-AppCrane-Timestamp': ts, 'X-AppCrane-Signature': signBody(token, ts, body), 'X-AppCrane-Event-Id': String(ev.id) },
      body,
    });
    if (last.ok || last.permanent) break;
  }
  const at = new Date().toISOString();
  if (last.ok) {
    db.prepare('UPDATE task_app_settings SET consecutive_failures = 0, last_status = ?, last_attempt_at = ? WHERE app_id = ?').run(String(last.status), at, appId);
    return;
  }
  db.prepare('UPDATE task_app_settings SET consecutive_failures = consecutive_failures + 1, last_status = ?, last_attempt_at = ? WHERE app_id = ?').run(last.reason, at, appId);
  const row = db.prepare('SELECT consecutive_failures FROM task_app_settings WHERE app_id = ?').get(appId);
  if (row && row.consecutive_failures >= WEBHOOK_LIMITS.MAX_CONSECUTIVE_FAILURES) {
    db.prepare("UPDATE task_app_settings SET webhook_url = NULL, last_status = 'disabled_after_failures' WHERE app_id = ?").run(appId);
  }
  log.info(`[tasks] webhook delivery failed for app ${appId} event ${ev.id}: ${last.reason}`);
}

/** Queue delivery of one event, if a person caused it and the app has a webhook. */
export function queueTaskWebhook(eventId) {
  const db = getDb();
  const ev = db.prepare('SELECT id, app_id, via FROM task_events WHERE id = ?').get(eventId);
  if (!ev || ev.via !== 'dashboard') return false;
  if (!getWebhook(ev.app_id).url) return false;
  const prev = chains.get(ev.app_id) || Promise.resolve();
  const next = prev.then(() => deliver(ev.app_id, ev.id))
    .catch((e) => log.warn(`[tasks] webhook chain error for app ${ev.app_id}: ${e.message}`));
  chains.set(ev.app_id, next);
  next.finally(() => { if (chains.get(ev.app_id) === next) chains.delete(ev.app_id); });
  return true;
}

/** Tests only: wait for every queued delivery. */
export async function drainTaskWebhooks() {
  while (chains.size) await Promise.allSettled([...chains.values()]);
}
