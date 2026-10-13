/**
 * A2A push notifications for Crew (phase 2).
 *
 * A hosted agent that cannot hold an SSE stream open registers a webhook for a
 * task (a2a.proto TaskPushNotificationConfig: url, token, authentication
 * {scheme, credentials}) and AppCrane POSTs each update to it as a
 * StreamResponse (spec §4.3.3), with `Authorization: <scheme> <credentials>`
 * when authentication is set. The spec gives `token` no transport; it is sent
 * as `X-A2A-Notification-Token`, the header the A2A SDKs use for it.
 *
 * ── This is an outbound request to a URL a caller chose: SSRF ───────────────
 * AppCrane sits next to the Docker socket, Caddy's admin API (2019), its own
 * API and, on a cloud host, the metadata service at 169.254.169.254. So:
 *   - https only, no userinfo in the URL, at most 2048 chars;
 *   - the host is checked when the config is created (fail early) AND on every
 *     delivery, through makeGuardedLookup(): the address that is checked is
 *     the address that is dialled, so DNS rebinding between a check and the
 *     connect cannot get through;
 *   - an IP-literal host is checked directly (literals never reach a lookup);
 *   - redirects are never followed: any 3xx is a failed delivery and its
 *     Location is not read — a public URL that 302s to the metadata service
 *     would otherwise walk around the check;
 *   - 10 s timeout (spec §4.3.3 recommends 10-30 s), request body capped, the
 *     response body is discarded unread after at most 64 KB and never stored;
 *   - retries with exponential backoff (spec §13.2 SHOULD), a refused address
 *     is not retried, and a config that fails 8 times in a row is disabled
 *     (spec §4.3.3 MAY stop after consecutive failures).
 *
 * ── Who gets what ────────────────────────────────────────────────────────────
 * A config belongs to the crew agent that created it and is rendered from ITS
 * view of the task (crew.taskFor), re-checked at every delivery: if the agent
 * stops being able to see the task, nothing more is sent. A config is also
 * bound to the agent TOKEN that created it (token_id): before every delivery
 * and every retry, crewTokens.pushConfigAuthorized() re-runs what an A2A
 * request would have to pass — that token live, agent active, owner active and
 * still allowed Crew — and a config that fails is deleted. Revoking or
 * rotating a token deletes the agent's configs in the same transaction. The
 * token and the
 * credentials are the client's own secrets for its own webhook — stored
 * encrypted, used only as headers on that webhook, never returned by Get/List
 * and never logged.
 */
import crypto from 'crypto';
import https from 'https';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import { crewEvents, taskFor } from './crew.js';
import { cursorOf, eventsSince, isTerminalCrewState, toTask } from './crewA2aView.js';
import { makeGuardedLookup, assertHostNotBlocked, isBlockedAddress } from './remoteFetch.js';
import { pushConfigAuthorized } from './crewTokens.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

export const PUSH_LIMITS = Object.freeze({
  CONFIGS_PER_TASK_PER_AGENT: 5,
  URL_MAX: 2048,
  TOKEN_MAX: 512,
  CREDENTIALS_MAX: 4096,
  TIMEOUT_MS: 10_000,
  REQUEST_MAX_BYTES: 256 * 1024,
  RESPONSE_MAX_BYTES: 64 * 1024,
  MAX_CONSECUTIVE_FAILURES: 8,
});

// Backoff before attempts 2..n. Overridable for tests through startCrewPush().
const DEFAULT_RETRY_DELAYS_MS = [1_000, 5_000, 25_000];

export class PushConfigError extends Error {
  constructor(message, field) { super(message); this.field = field; }
}

const SCHEME_RE = /^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,31}$/; // RFC 9110 token, short
const HEADER_VALUE_RE = /^[\x20-\x7e]*$/;                          // printable ASCII: no CR/LF smuggling

/**
 * Validate a client's TaskPushNotificationConfig. Throws PushConfigError
 * (field, message) — crewA2a.js turns it into InvalidParams.
 */
export function validatePushConfig(cfg) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw new PushConfigError('must be a TaskPushNotificationConfig object', 'taskPushNotificationConfig');
  const raw = cfg.url;
  if (typeof raw !== 'string' || !raw) throw new PushConfigError('url is required', 'url');
  if (raw.length > PUSH_LIMITS.URL_MAX) throw new PushConfigError(`url is longer than ${PUSH_LIMITS.URL_MAX} characters`, 'url');
  let url;
  try { url = new URL(raw); } catch { throw new PushConfigError('url is not a valid absolute URL', 'url'); }
  if (url.protocol !== 'https:') throw new PushConfigError('url must be https:// (the payload and credentials travel in it)', 'url');
  if (url.username || url.password) throw new PushConfigError('url must not carry credentials; use authentication', 'url');
  if (url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) throw new PushConfigError('url must not point at this host', 'url');
  try { assertHostNotBlocked(url); } catch (e) { throw new PushConfigError(`url ${e.message}; AppCrane does not deliver into its own network`, 'url'); }
  let token = null;
  if (cfg.token != null && cfg.token !== '') {
    if (typeof cfg.token !== 'string' || cfg.token.length > PUSH_LIMITS.TOKEN_MAX || !HEADER_VALUE_RE.test(cfg.token)) {
      throw new PushConfigError(`token must be printable ASCII, at most ${PUSH_LIMITS.TOKEN_MAX} characters`, 'token');
    }
    token = cfg.token;
  }
  let scheme = null;
  let credentials = null;
  if (cfg.authentication != null) {
    const a = cfg.authentication;
    if (typeof a !== 'object' || Array.isArray(a)) throw new PushConfigError('authentication must be {scheme, credentials}', 'authentication');
    if (typeof a.scheme !== 'string' || !SCHEME_RE.test(a.scheme)) throw new PushConfigError('authentication.scheme must be an HTTP auth scheme name such as Bearer or Basic', 'authentication.scheme');
    scheme = a.scheme;
    if (a.credentials != null && a.credentials !== '') {
      if (typeof a.credentials !== 'string' || a.credentials.length > PUSH_LIMITS.CREDENTIALS_MAX || !HEADER_VALUE_RE.test(a.credentials)) {
        throw new PushConfigError(`authentication.credentials must be printable ASCII, at most ${PUSH_LIMITS.CREDENTIALS_MAX} characters`, 'authentication.credentials');
      }
      credentials = a.credentials;
    }
  }
  return { url: url.toString(), token, scheme, credentials };
}

/** a2a.proto TaskPushNotificationConfig as returned to its owner: never the token or the credentials. */
function view(row) {
  const out = { id: row.id, taskId: row.task_id, url: row.url };
  if (row.auth_scheme) out.authentication = { scheme: row.auth_scheme };
  return out;
}

function audit(owner, action, detail) {
  try { logAudit(owner.id, null, action, detail, 'agent'); } catch (e) { log.warn(`[crew] audit write failed for ${action}: ${e.message}`); }
}

// ── Configs ─────────────────────────────────────────────────────────────────

export function createPushConfig(owner, agent, task, valid, tokenId) {
  const db = getDb();
  const id = crypto.randomBytes(16).toString('base64url');
  db.transaction(() => {
    const { n } = db.prepare('SELECT COUNT(*) AS n FROM crew_push_configs WHERE task_id = ? AND agent_id = ?').get(task.id, agent.id);
    if (n >= PUSH_LIMITS.CONFIGS_PER_TASK_PER_AGENT) {
      throw new PushConfigError(`at most ${PUSH_LIMITS.CONFIGS_PER_TASK_PER_AGENT} push notification configs per task`, 'taskPushNotificationConfig');
    }
    db.prepare(`INSERT INTO crew_push_configs (id, task_id, agent_id, token_id, url, token_enc, auth_scheme, auth_credentials_enc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      id, task.id, agent.id, tokenId, valid.url,
      valid.token ? encrypt(valid.token) : null,
      valid.scheme,
      valid.credentials ? encrypt(valid.credentials) : null,
    );
  })();
  cursors.set(id, cursorOf(task));
  audit(owner, 'crew.push.create', { task_id: task.id, agent_id: agent.id, config_id: id, host: new URL(valid.url).host });
  return view(db.prepare('SELECT * FROM crew_push_configs WHERE id = ?').get(id));
}

/** A config of `agent` on `task`, or null (the caller answers TaskNotFoundError, spec §3.1.8). */
export function getPushConfig(agent, task, configId) {
  if (typeof configId !== 'string') return null;
  const row = getDb().prepare('SELECT * FROM crew_push_configs WHERE id = ? AND task_id = ? AND agent_id = ?').get(configId, task.id, agent.id);
  return row ? view(row) : null;
}

export function listPushConfigs(agent, task) {
  return getDb().prepare('SELECT * FROM crew_push_configs WHERE task_id = ? AND agent_id = ? ORDER BY created_at').all(task.id, agent.id).map(view);
}

/** Idempotent (spec §3.1.10): deleting a config that is already gone is not an error. */
export function deletePushConfig(owner, agent, task, configId) {
  const n = getDb().prepare('DELETE FROM crew_push_configs WHERE id = ? AND task_id = ? AND agent_id = ?').run(String(configId ?? ''), task.id, agent.id).changes;
  cursors.delete(configId);
  if (n) audit(owner, 'crew.push.delete', { task_id: task.id, agent_id: agent.id, config_id: configId });
}

// ── The one outbound request ────────────────────────────────────────────────

/**
 * POST `body` to `rawUrl` under every rule in the header. Resolves (never
 * rejects) to { ok, status?, reason?, permanent? }. `reason` is a short code
 * fit for a log line: never the URL's query, a header, or a response body.
 *
 * `lookup`, `isBlocked` and `ca` exist for tests (to dial a local TLS server
 * on purpose); production passes none of them.
 */
export function postSafely(rawUrl, { headers = {}, body = '', timeoutMs = PUSH_LIMITS.TIMEOUT_MS, isBlocked = isBlockedAddress, lookup, ca } = {}) {
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
    if (payload.length > PUSH_LIMITS.REQUEST_MAX_BYTES) return resolve({ ok: false, reason: 'payload_too_large', permanent: true });
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    const req = https.request(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/a2a+json', 'Content-Length': payload.length, 'User-Agent': 'AppCrane-Crew-Push/1' },
      lookup: lookup || makeGuardedLookup({ isBlocked }),
      ca,
      timeout: timeoutMs,
      // No agent keep-alive: each delivery dials (and therefore re-checks) afresh.
      agent: false,
    }, (res) => {
      const status = res.statusCode || 0;
      let seen = 0;
      // Read nothing into memory; count, cap and drop.
      res.on('data', (chunk) => { seen += chunk.length; if (seen > PUSH_LIMITS.RESPONSE_MAX_BYTES) res.destroy(); });
      res.on('end', () => {});
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

// ── Delivery ────────────────────────────────────────────────────────────────

// Per config: the last state/message delivered, and a promise chain so one
// config's deliveries go out in order (spec §3.5.2 ordering, applied to push).
const cursors = new Map();
const chains = new Map();

function headersFor(row) {
  const h = {};
  if (row.auth_scheme) {
    const cred = row.auth_credentials_enc ? decrypt(row.auth_credentials_enc) : '';
    h.Authorization = cred ? `${row.auth_scheme} ${cred}` : row.auth_scheme;
  }
  if (row.token_enc) h['X-A2A-Notification-Token'] = decrypt(row.token_enc);
  return h;
}

function dropConfig(id, reason) {
  getDb().prepare('DELETE FROM crew_push_configs WHERE id = ?').run(id);
  cursors.delete(id);
  log.info(`[crew] push config ${id} removed: ${reason}`);
}

async function deliverWithRetry(row, payload, { post, delays }) {
  const body = JSON.stringify(payload);
  let last = null;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    if (attempt > 0) await new Promise((r) => { const t = setTimeout(r, delays[attempt - 1]); t.unref?.(); });
    // The row may have been deleted or disabled while we waited.
    const live = getDb().prepare('SELECT * FROM crew_push_configs WHERE id = ? AND disabled_at IS NULL').get(row.id);
    if (!live) return { ok: false, reason: 'config_gone' };
    // Re-checked before every attempt too: a retry 25 s later must not go out
    // on a token that was revoked in between.
    if (!pushConfigAuthorized(live)) { dropConfig(live.id, 'credential_gone'); return { ok: false, reason: 'credential_gone' }; }
    last = await post(live.url, { headers: headersFor(live), body });
    if (last.ok || last.permanent) break;
  }
  const db = getDb();
  if (last.ok) {
    db.prepare("UPDATE crew_push_configs SET consecutive_failures = 0, last_attempt_at = datetime('now'), last_status = ? WHERE id = ?").run(String(last.status), row.id);
  } else {
    db.prepare(`UPDATE crew_push_configs SET consecutive_failures = consecutive_failures + 1, last_attempt_at = datetime('now'), last_status = ?,
                disabled_at = CASE WHEN consecutive_failures + 1 >= ? THEN datetime('now') ELSE disabled_at END WHERE id = ?`)
      .run(last.reason, PUSH_LIMITS.MAX_CONSECUTIVE_FAILURES, row.id);
    // Config id and reason code only: never the URL, a header or a body.
    log.info(`[crew] push delivery failed for config ${row.id}: ${last.reason}`);
  }
  return last;
}

function onTaskEvent({ task_id, kind }, opts) {
  if (kind === 'deleted') return;
  const rows = getDb().prepare('SELECT * FROM crew_push_configs WHERE task_id = ? AND disabled_at IS NULL').all(task_id);
  for (const row of rows) {
    // Before rendering anything: is the credential behind this config still
    // live? A revoked token, a disabled or removed agent, a deactivated owner,
    // or an owner who lost Crew (app scope, agent identity) ends delivery and
    // removes the config with its stored secrets.
    if (!pushConfigAuthorized(row)) {
      dropConfig(row.id, 'credential_gone');
      continue;
    }
    const task = taskFor(row.agent_id, task_id);
    if (!task) continue;
    const from = cursors.get(row.id);
    let events;
    if (from) {
      const r = eventsSince(task, from);
      events = r.events;
      cursors.set(row.id, r.cursor);
    } else {
      // No cursor: the process restarted since the config was created, and
      // what was already delivered is unknown. One `{ task }` snapshot (a valid
      // StreamResponse, spec §4.3.3) instead of replaying the whole history;
      // the spec already tells receivers to expect duplicates.
      events = [{ task: toTask(task, { historyLength: 0 }) }];
      cursors.set(row.id, cursorOf(task));
    }
    if (!events.length) continue;
    const prev = chains.get(row.id) || Promise.resolve();
    const next = prev.then(async () => {
      for (const ev of events) await deliverWithRetry(row, ev, opts);
      // Spec §3.1.7: a config "MUST persist until task completion or explicit
      // deletion". A terminal task takes no more messages, so once its final
      // update has gone out the config (and its stored secrets) is removed.
      if (isTerminalCrewState(task.state)) {
        getDb().prepare('DELETE FROM crew_push_configs WHERE id = ?').run(row.id);
        cursors.delete(row.id);
      }
    }).catch((e) => log.warn(`[crew] push chain error for config ${row.id}: ${e.message}`));
    chains.set(row.id, next);
    next.finally(() => { if (chains.get(row.id) === next) chains.delete(row.id); });
  }
}

let stopFn = null;

/**
 * Start delivering. `post` and `delays` exist for tests; the server calls this
 * with neither. Returns a stop function. Idempotent: a second start replaces
 * the first listener.
 */
export function startCrewPush({ post = postSafely, delays = DEFAULT_RETRY_DELAYS_MS } = {}) {
  stopFn?.();
  const listener = (ev) => {
    try { onTaskEvent(ev, { post, delays }); } catch (e) { log.warn(`[crew] push dispatch failed: ${e.message}`); }
  };
  crewEvents.on('task', listener);
  stopFn = () => { crewEvents.off('task', listener); stopFn = null; };
  return stopFn;
}

/** For tests: wait until every queued delivery has finished. */
export async function drainPushQueue() {
  while (chains.size) await Promise.allSettled([...chains.values()]);
}
