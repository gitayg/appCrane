import { createHash } from 'crypto';
import { isIP } from 'net';

// The shape of one app audit event (borrowed from WorkOS Audit Logs): action,
// occurred_at, actor, targets, context, metadata, plus an idempotency key.
// Everything is bounded here so a misbehaving app cannot grow the store or the
// chain with one request.

export const LIMITS = Object.freeze({
  actionMax: 64, idMax: 128, nameMax: 200, typeMax: 40, targetsMax: 20, userAgentMax: 512,
  metadataBytes: 4096, metadataDepth: 3, metadataKeys: 50, metadataString: 1000,
  futureSkewMs: 5 * 60_000, backfillMs: 90 * 86_400_000, descriptionMax: 300,
});
export const ACTION_RE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+){1,4}$/;
const TYPE_RE = /^[a-z][a-z0-9_.-]*$/;
const IDEM_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
// AppCrane vouches for these actor types, so an app cannot claim them:
// 'app' is the app itself, 'user' is an AppCrane user named by a signed identity.
export const RESERVED_ACTOR_TYPES = new Set(['app', 'user']);

function bad(message, code = 'VALIDATION') {
  return Object.assign(new Error(message), { status: 400, code });
}

function plainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

export function validAction(v) {
  return typeof v === 'string' && v.length <= LIMITS.actionMax && ACTION_RE.test(v);
}

function entity(v, field) {
  if (!plainObject(v)) throw bad(`${field} must be an object with type and id`);
  const type = v.type;
  if (typeof type !== 'string' || !type || type.length > LIMITS.typeMax || !TYPE_RE.test(type)) {
    throw bad(`${field}.type must be a lower-case name (letters, digits, _ . -) of at most ${LIMITS.typeMax} characters`);
  }
  const id = typeof v.id === 'number' && Number.isFinite(v.id) ? String(v.id) : v.id;
  if (typeof id !== 'string' || !id.trim() || id.length > LIMITS.idMax) throw bad(`${field}.id must be a string of 1 to ${LIMITS.idMax} characters`);
  if (v.name != null && (typeof v.name !== 'string' || v.name.length > LIMITS.nameMax)) throw bad(`${field}.name must be a string of at most ${LIMITS.nameMax} characters`);
  return { type, id: id.trim(), ...(v.name ? { name: v.name } : {}) };
}

function checkMetadata(v, depth, path) {
  if (v == null || typeof v === 'boolean') return;
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw bad(`${path} must be a finite number`); return; }
  if (typeof v === 'string') { if (v.length > LIMITS.metadataString) throw bad(`${path} is longer than ${LIMITS.metadataString} characters`); return; }
  if (depth >= LIMITS.metadataDepth) throw bad(`metadata nests deeper than ${LIMITS.metadataDepth} levels at ${path}`);
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  if (entries.length > LIMITS.metadataKeys) throw bad(`${path} holds more than ${LIMITS.metadataKeys} entries`);
  for (const [k, x] of entries) checkMetadata(x, depth + 1, `${path}.${k}`);
}

function occurredAt(v, now) {
  if (v == null) return new Date(now).toISOString();
  const t = typeof v === 'string' ? Date.parse(v) : NaN;
  if (!Number.isFinite(t)) throw bad('occurred_at must be an ISO 8601 timestamp');
  if (t > now + LIMITS.futureSkewMs) throw bad('occurred_at is in the future');
  if (t < now - LIMITS.backfillMs) throw bad('occurred_at is more than 90 days in the past');
  return new Date(t).toISOString();
}

/** Validate an event body. Returns the normalised event without the actor resolution (see resolveActor). */
export function validateEvent(body, { now = Date.now(), idempotencyHeader = null } = {}) {
  if (!plainObject(body)) throw bad('body must be a JSON object');
  if (!validAction(body.action)) throw bad('action must look like "invoice.paid": lower-case words joined by dots, at most 64 characters');
  let actor = null;
  if (body.actor != null) {
    actor = entity(body.actor, 'actor');
    if (RESERVED_ACTOR_TYPES.has(actor.type)) {
      throw bad(`actor.type '${actor.type}' is set by AppCrane: omit actor to act as the app, or forward the signed identity in "identity" to name an AppCrane user`, 'ACTOR_RESERVED');
    }
  }
  if (body.targets != null && !Array.isArray(body.targets)) throw bad('targets must be an array');
  const targets = (body.targets || []).map((t, i) => entity(t, `targets[${i}]`));
  if (targets.length > LIMITS.targetsMax) throw bad(`at most ${LIMITS.targetsMax} targets`);
  const context = {};
  if (body.context != null) {
    if (!plainObject(body.context)) throw bad('context must be an object');
    const { location, user_agent: ua } = body.context;
    if (location != null) {
      if (typeof location !== 'string' || !isIP(location)) throw bad('context.location must be an IP address');
      context.location = location;
    }
    if (ua != null) {
      if (typeof ua !== 'string' || ua.length > LIMITS.userAgentMax) throw bad(`context.user_agent must be a string of at most ${LIMITS.userAgentMax} characters`);
      context.user_agent = ua;
    }
  }
  let metadata = null;
  if (body.metadata != null) {
    if (!plainObject(body.metadata)) throw bad('metadata must be an object');
    checkMetadata(body.metadata, 0, 'metadata');
    metadata = JSON.stringify(body.metadata);
    if (Buffer.byteLength(metadata) > LIMITS.metadataBytes) throw bad(`metadata is larger than ${LIMITS.metadataBytes} bytes`);
  }
  const key = body.idempotency_key ?? idempotencyHeader ?? null;
  if (key != null && (typeof key !== 'string' || !IDEM_RE.test(key))) throw bad('idempotency_key must be 1 to 128 characters of letters, digits, _ . : -');
  if (body.identity != null && !plainObject(body.identity)) throw bad('identity must be an object of the X-AppCrane-* headers the app received');
  return {
    action: body.action, occurred_at: occurredAt(body.occurred_at, now), occurred_at_given: body.occurred_at != null, actor, targets, context, metadata,
    idempotency_key: key, identity: body.identity ?? null,
  };
}

/** Hash of what the event says, for telling a replay of an idempotency key from a reuse of it. */
export function payloadHash(ev) {
  return createHash('sha256').update(JSON.stringify([ev.action, ev.occurred_at_given ? ev.occurred_at : null, ev.actor_type, ev.actor_id,
    ev.targets, ev.context, ev.metadata])).digest('hex');
}
