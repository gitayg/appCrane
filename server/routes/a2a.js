import express, { Router } from 'express';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { resolveAgentToken } from '../services/crewTokens.js';
import {
  dispatch, A2AError, RPC, STREAMING_METHODS, SUPPORTED_VERSION, publicCard, agentCard, etagOf,
} from '../services/crewA2a.js';
import { crewEvents, taskFor } from '../services/crew.js';
import { toTask, cursorOf, eventsSince, isTerminalCrewState } from '../services/crewA2aView.js';
import log from '../utils/logger.js';

/**
 * The platform A2A endpoint (Crew, phase 2): POST /a2a speaks the A2A 1.0
 * JSON-RPC binding (spec §9), GET /a2a/agents/:name/card serves one crew
 * agent's card to an authenticated caller, and wellKnownAgentCard serves the
 * public card at /.well-known/agent-card.json (spec §8.2).
 *
 * Mounted in server/index.js BEFORE the global express.json() (which accepts
 * 50 MB for uploads): this router parses its own bodies with a 256 KB cap — a
 * Crew message is at most 16 KB plus a 64 KB artifact.
 *
 * ── Authentication ───────────────────────────────────────────────────────────
 * `Authorization: Bearer <crew agent token>` on every request; there is no
 * anonymous access to anything but the public card. Every failure — missing,
 * malformed, unknown, revoked, owner deactivated or not allowed Crew — is the
 * same HTTP 401 with a WWW-Authenticate challenge (spec §3.3.2: servers SHOULD
 * include challenge information) and one JSON-RPC error, so a probe learns
 * nothing about which tokens exist. The token is never logged.
 *
 * ── Version ──────────────────────────────────────────────────────────────────
 * Spec §3.6.2: "Agents MUST interpret empty value as 0.3 version" and return
 * VersionNotSupportedError for a version they do not serve. This endpoint
 * serves 1.0 only, so a request without `A2A-Version: 1.0` (header, or the
 * A2A-Version query parameter spec §3.6.1 allows) is refused with -32009.
 * Patch numbers are ignored as §3.6 requires.
 *
 * Mutual TLS (a client certificate from AppCrane's CA) is NOT accepted yet:
 * TLS terminates at Caddy, and the only CA AppCrane has is the managed-
 * database CA, whose certificates must not double as agent identities. See
 * the phase 2 notes in docs.
 */
const router = Router();

const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8')).version;
  } catch { return '0.0.0'; }
})();

const LIMITS = Object.freeze({
  REQUESTS_PER_MINUTE: 600,     // per agent token: polling GetTask every 100 ms is already abuse
  STREAMS_PER_AGENT: 10,
  STREAM_MAX_MS: 60 * 60 * 1000, // a stream ends after an hour; SubscribeToTask resumes it
  HEARTBEAT_MS: 15_000,
});

export function baseUrlOf(req) {
  const host = process.env.CRANE_DOMAIN;
  return host ? `https://${host}` : `${req.protocol}://${req.get('host')}`;
}

function rpcError(res, id, err, httpStatus = 200) {
  const e = err instanceof A2AError ? err : new A2AError(RPC.INTERNAL, 'Internal error');
  res.status(httpStatus).type('application/json').send(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: e.toJSON() }));
}

// ── Per-agent request budget (in memory; one process) ──────────────────────
const windows = new Map();
function overBudget(agentId) {
  const now = Date.now();
  const w = windows.get(agentId);
  if (!w || now - w.start >= 60_000) { windows.set(agentId, { start: now, n: 1 }); return false; }
  w.n += 1;
  return w.n > LIMITS.REQUESTS_PER_MINUTE;
}
const openStreams = new Map();

// ── Auth ────────────────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header);
  const found = m ? resolveAgentToken(m[1]) : null;
  if (!found) {
    res.set('WWW-Authenticate', 'Bearer realm="appcrane-crew", error="invalid_token"');
    return rpcError(res, null, new A2AError(RPC.UNAUTHENTICATED, 'Unauthenticated: present a Crew agent token as Authorization: Bearer <token>.'), 401);
  }
  req.crew = { owner: found.owner, agent: found.agent, tokenId: found.token_id, baseUrl: baseUrlOf(req), version: VERSION };
  if (overBudget(found.agent.id)) {
    res.set('Retry-After', '60');
    return rpcError(res, null, new A2AError(RPC.RATE_LIMITED, `Rate limited: at most ${LIMITS.REQUESTS_PER_MINUTE} A2A requests per agent per minute.`), 429);
  }
  next();
}

function versionOk(req) {
  const raw = String(req.headers['a2a-version'] ?? req.query['A2A-Version'] ?? '').trim();
  const m = /^(\d+)\.(\d+)(?:\.\d+)?$/.exec(raw);
  return !!m && `${m[1]}.${m[2]}` === SUPPORTED_VERSION ? null : (raw || '0.3 (no A2A-Version header)');
}

router.use(authenticate);
router.use(express.json({ limit: '256kb', type: ['application/json', 'application/a2a+json'] }));

// ── POST /a2a — JSON-RPC 2.0 ───────────────────────────────────────────────
router.post('/', async (req, res) => {
  const body = req.body;
  // Spec §9.3: a single JSON-RPC 2.0 request object. Batches are not part of
  // the A2A binding.
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.jsonrpc !== '2.0' || typeof body.method !== 'string'
      || !('id' in body) || !(typeof body.id === 'string' || typeof body.id === 'number' || body.id === null)) {
    return rpcError(res, body && !Array.isArray(body) && typeof body === 'object' ? body.id : null,
      new A2AError(RPC.INVALID_REQUEST, 'Request payload validation error'));
  }
  const { id, method, params } = body;
  const badVersion = versionOk(req);
  if (badVersion) {
    return rpcError(res, id, new A2AError(RPC.VERSION_NOT_SUPPORTED, `A2A protocol version ${badVersion} is not supported; this endpoint serves ${SUPPORTED_VERSION}. Send the header A2A-Version: ${SUPPORTED_VERSION}.`, { metadata: { supportedVersions: SUPPORTED_VERSION } }));
  }
  const ctx = req.crew;
  if (STREAMING_METHODS.has(method) && (openStreams.get(ctx.agent.id) || 0) >= LIMITS.STREAMS_PER_AGENT) {
    return rpcError(res, id, new A2AError(RPC.RATE_LIMITED, `At most ${LIMITS.STREAMS_PER_AGENT} open streams per agent; close one or use push notifications.`));
  }
  let result;
  try {
    result = await dispatch(ctx, method, params);
  } catch (e) {
    if (!(e instanceof A2AError)) log.warn(`[a2a] ${method} failed: ${e.message}`);
    return rpcError(res, id, e);
  }
  if (STREAMING_METHODS.has(method)) return serveStream(req, res, ctx, id, result.stream);
  res.type('application/json').send(JSON.stringify({ jsonrpc: '2.0', id, result }));
});

/**
 * Spec §9.4.2: HTTP 200, text/event-stream, each event
 * `data: {"jsonrpc":"2.0","id":<request id>,"result":<StreamResponse>}`.
 * Spec §3.1.2 / §3.1.6: the first event is the Task; status and artifact
 * updates follow in order; the stream closes when the task reaches a terminal
 * state. It also closes if the task disappears (agent removed, retention) or
 * the caller stops being able to see it.
 */
function serveStream(req, res, ctx, id, { taskId, historyLength }) {
  const agentId = ctx.agent.id;
  let cursor = null;
  let closed = false;
  openStreams.set(agentId, (openStreams.get(agentId) || 0) + 1);
  const send = (result) => { if (!closed) res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id, result })}\n\n`); };
  const close = () => {
    if (closed) return;
    closed = true;
    crewEvents.off('task', onEvent);
    clearInterval(beat);
    clearTimeout(maxLife);
    openStreams.set(agentId, Math.max(0, (openStreams.get(agentId) || 1) - 1));
    res.end();
  };
  function onEvent(ev) {
    if (ev.task_id !== taskId || closed) return;
    if (ev.kind === 'deleted') return close();
    const t = taskFor(agentId, taskId);
    if (!t) return close();
    const r = eventsSince(t, cursor);
    cursor = r.cursor;
    for (const e of r.events) send(e);
    if (isTerminalCrewState(t.state)) close();
  }
  // Listen before the snapshot: announcements are deferred to the next tick,
  // so nothing can slip between the snapshot and the subscription.
  crewEvents.on('task', onEvent);
  const beat = setInterval(() => { if (!closed) res.write(': keep-alive\n\n'); }, LIMITS.HEARTBEAT_MS);
  beat.unref?.();
  const maxLife = setTimeout(close, LIMITS.STREAM_MAX_MS);
  maxLife.unref?.();
  req.on('close', close);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const task = taskFor(agentId, taskId);
  if (!task) return close();
  cursor = cursorOf(task);
  send({ task: toTask(task, { historyLength }) });
  if (isTerminalCrewState(task.state)) close();
}

// ── GET /a2a/agents/:name/card — one crew agent's card (authenticated) ─────
router.get('/agents/:name/card', (req, res) => {
  const name = String(req.params.name || '').toLowerCase();
  const card = /^[a-z0-9][a-z0-9-]{1,39}$/.test(name) ? agentCard(req.crew, name) : null;
  if (!card) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No such agent.' } });
  res.set('Cache-Control', 'private, max-age=60');
  res.set('ETag', etagOf(card));
  res.json(card);
});

// Body-parser failures arrive here: spec §9.5 -32700 "Invalid JSON payload".
router.use((err, req, res, _next) => {
  if (err?.type === 'entity.parse.failed') return rpcError(res, null, new A2AError(RPC.PARSE_ERROR, 'Invalid JSON payload'));
  if (err?.type === 'entity.too.large') return rpcError(res, null, new A2AError(RPC.INVALID_REQUEST, 'Request payload validation error: body larger than 256 KB'), 413);
  log.warn(`[a2a] request failed: ${err?.message}`);
  return rpcError(res, null, new A2AError(RPC.INTERNAL, 'Internal error'), 500);
});

/** GET /.well-known/agent-card.json — public, cacheable (spec §8.6.1). */
export function wellKnownAgentCard(req, res) {
  const card = publicCard({ baseUrl: baseUrlOf(req), version: VERSION });
  const etag = etagOf(card);
  res.set('Cache-Control', 'public, max-age=300');
  res.set('ETag', etag);
  if (req.headers['if-none-match'] === etag) return res.status(304).end();
  res.json(card);
}

export default router;
