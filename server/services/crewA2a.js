/**
 * The A2A 1.0 JSON-RPC binding for Crew (phase 2): method dispatch, parameter
 * validation and error mapping. HTTP, authentication and SSE framing live in
 * routes/a2a.js; task rendering in crewA2aView.js; every RULE (first contact,
 * blocks, budgets, secret scan, audit, retention, visibility) stays in
 * crew.js and is reached only through its exported functions.
 *
 * Source of the shapes: the A2A specification (a2a-protocol.org, "Latest
 * Released Version 1.0.0") and its normative proto, specification/a2a.proto
 * (package lf.a2a.v1), read for this change. Quoted where they decide
 * something.
 *
 * ── Addressing: one endpoint, many agents ───────────────────────────────────
 * a2a.proto AgentInterface.tenant: "An opaque string used for routing requests
 * to a specific agent or tenant when multiple agents are served behind a
 * single A2A endpoint. When set, clients MUST include this value in the
 * `tenant` field of all request messages". Each crew agent's card therefore
 * declares the platform endpoint with tenant = the agent's name, and
 * SendMessageRequest.tenant names the receiving agent of a NEW task. Task
 * operations (GetTask, CancelTask, ...) address a task by id; the tenant on
 * them is accepted and not needed, because the task already names both ends.
 *
 * ── Who the caller is ───────────────────────────────────────────────────────
 * Always the crew agent its token identifies (ctx.agent), acting through its
 * owner (ctx.owner). No parameter can name a different agent to act as.
 *
 * ── Replies over A2A (Crew relay extension) ─────────────────────────────────
 * A2A has no operation for a server-side agent to report progress on a task it
 * was handed, because in A2A the receiver IS the server. In Crew the receiver
 * is another client of this endpoint, so it reports through SendMessage on the
 * task (message.taskId) with message.metadata.taskState set to
 * TASK_STATE_WORKING | INPUT_REQUIRED | COMPLETED | FAILED, and a result as a
 * part carrying a `filename` (an artifact). The public card declares this as
 * extension CREW_RELAY_EXTENSION (not required: plain A2A clients that only
 * send and poll never need it).
 */
import crypto from 'crypto';
import {
  sendTask, reply, taskFor, listTasksFor, crewEvents, CREW_LIMITS, roster, touchAgentSeen,
} from './crew.js';
import { toTask, toCrewState, toA2aState, TERMINAL_A2A, INTERRUPTED_A2A, sqliteTime } from './crewA2aView.js';
import {
  validatePushConfig, PushConfigError, createPushConfig, getPushConfig, listPushConfigs, deletePushConfig,
} from './crewPush.js';

export const CREW_RELAY_EXTENSION = 'urn:appcrane:a2a:crew-relay:v1';
export const SUPPORTED_VERSION = '1.0';

// ── Errors (spec §9.5 and the §5.4 mapping table) ──────────────────────────

export const RPC = Object.freeze({
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  TASK_NOT_FOUND: -32001,
  TASK_NOT_CANCELABLE: -32002,
  PUSH_NOT_SUPPORTED: -32003,
  UNSUPPORTED_OPERATION: -32004,
  CONTENT_TYPE_NOT_SUPPORTED: -32005,
  EXTENDED_CARD_NOT_CONFIGURED: -32007,
  VERSION_NOT_SUPPORTED: -32009,
  // Spec §3.3.2 leaves authentication, authorization and rate limiting to a
  // "JSON-RPC custom error". These sit outside JSON-RPC's reserved
  // -32768..-32000 block, so they can never collide with a future A2A code.
  UNAUTHENTICATED: -31001,
  FORBIDDEN: -31003,
  RATE_LIMITED: -31029,
});

const REASONS = {
  [RPC.TASK_NOT_FOUND]: 'TASK_NOT_FOUND',
  [RPC.TASK_NOT_CANCELABLE]: 'TASK_NOT_CANCELABLE',
  [RPC.UNSUPPORTED_OPERATION]: 'UNSUPPORTED_OPERATION',
  [RPC.CONTENT_TYPE_NOT_SUPPORTED]: 'CONTENT_TYPE_NOT_SUPPORTED',
  [RPC.VERSION_NOT_SUPPORTED]: 'VERSION_NOT_SUPPORTED',
  [RPC.UNAUTHENTICATED]: 'UNAUTHENTICATED',
  [RPC.FORBIDDEN]: 'PERMISSION_DENIED',
  [RPC.RATE_LIMITED]: 'RATE_LIMITED',
};

export class A2AError extends Error {
  constructor(code, message, { field, metadata } = {}) {
    super(message);
    this.code = code;
    this.field = field;
    this.metadata = metadata;
  }

  /** JSON-RPC error object; `data` is an array of ProtoJSON Any objects (spec §9.5). */
  toJSON() {
    const data = [];
    if (this.field) {
      data.push({ '@type': 'type.googleapis.com/google.rpc.BadRequest', fieldViolations: [{ field: this.field, description: this.message }] });
    }
    if (REASONS[this.code]) {
      data.push({ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason: REASONS[this.code], domain: 'a2a-protocol.org', metadata: { ...(this.metadata || {}), timestamp: new Date().toISOString() } });
    }
    return { code: this.code, message: this.message, ...(data.length ? { data } : {}) };
  }
}

const invalid = (field, message) => new A2AError(RPC.INVALID_PARAMS, message, { field });
const notFound = (taskId) => new A2AError(RPC.TASK_NOT_FOUND, 'Task not found', { metadata: { taskId: String(taskId ?? '').slice(0, 64) } });

/**
 * crew.js speaks AppError (HTTP status + code). Mapped once, here:
 *   404 → TaskNotFoundError when a task was named, else InvalidParams (an
 *         unknown receiving agent is a bad `tenant`, not a missing task)
 *   409 TASK_CLOSED → UnsupportedOperationError (spec §3.1.1: messages to a
 *         task in a terminal state)
 *   400 → InvalidParams (validation, and the secret scan's refusal, whose
 *         message names the rule so the agent can tell its owner)
 *   403 → custom FORBIDDEN, 429 → custom RATE_LIMITED
 */
function fromCrewError(e, { taskId, field = 'message' } = {}) {
  if (e instanceof A2AError) return e;
  if (e instanceof PushConfigError) return invalid(`configuration.taskPushNotificationConfig.${e.field}`, `taskPushNotificationConfig: ${e.message}`);
  const status = e?.status;
  if (status === 404) return taskId ? notFound(taskId) : invalid('tenant', e.message);
  if (status === 409) return new A2AError(RPC.UNSUPPORTED_OPERATION, e.message, { metadata: taskId ? { taskId } : undefined });
  if (status === 400) return invalid(field, e.message);
  if (status === 403) return new A2AError(RPC.FORBIDDEN, e.message);
  if (status === 429) return new A2AError(RPC.RATE_LIMITED, e.message);
  return new A2AError(RPC.INTERNAL, 'Internal error');
}

// ── Parameter helpers ───────────────────────────────────────────────────────

function obj(v, field) {
  if (v == null) return {};
  if (typeof v !== 'object' || Array.isArray(v)) throw invalid(field, `${field} must be an object`);
  return v;
}

function requiredString(v, field, max = 128) {
  if (typeof v !== 'string' || !v) throw invalid(field, `${field} is required`);
  if (v.length > max) throw invalid(field, `${field} is longer than ${max} characters`);
  return v;
}

/** Spec §3.2.4: unset = server default, 0 = none, n > 0 = at most n. */
function historyLength(v, field) {
  if (v == null) return undefined;
  if (!Number.isInteger(v) || v < 0) throw invalid(field, `${field} must be a non-negative integer`);
  return v;
}

const CONTEXT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * a2a.proto Part is a oneof { text | raw | url | data } plus filename and
 * mediaType. Crew relays text: text parts are joined, a data part is kept as
 * its JSON text, and a part with a `filename` is the message's artifact.
 * raw and url parts are ContentTypeNotSupportedError (spec §3.1.1) — Crew
 * stores no files and fetches no URLs on an agent's behalf.
 */
function readParts(parts) {
  if (!Array.isArray(parts) || !parts.length) throw invalid('message.parts', 'At least one part is required');
  const texts = [];
  let artifact = null;
  parts.forEach((p, i) => {
    const f = `message.parts[${i}]`;
    if (!p || typeof p !== 'object' || Array.isArray(p)) throw invalid(f, `${f} must be a Part object`);
    if (p.raw != null || p.url != null) {
      throw new A2AError(RPC.CONTENT_TYPE_NOT_SUPPORTED, `${f}: Crew relays text and JSON parts only (text, data); files travel as a pointer both owners can reach.`);
    }
    let text;
    if (typeof p.text === 'string') text = p.text;
    else if (p.data !== undefined) text = JSON.stringify(p.data);
    else throw invalid(f, `${f} must carry text or data`);
    if (typeof p.filename === 'string' && p.filename) {
      if (artifact) throw invalid(f, 'At most one part with a filename (an artifact) per message');
      artifact = { name: p.filename, body: text };
    } else {
      texts.push(text);
    }
  });
  return { text: texts.join('\n\n'), artifact };
}

function readMessage(m) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) throw invalid('message', 'message is required');
  const messageId = requiredString(m.messageId, 'message.messageId');
  if (m.role !== 'ROLE_USER' && m.role !== 'ROLE_AGENT') throw invalid('message.role', 'message.role must be ROLE_USER or ROLE_AGENT');
  const { text, artifact } = readParts(m.parts);
  const metadata = obj(m.metadata, 'message.metadata');
  return { messageId, text, artifact, metadata, taskId: m.taskId, contextId: m.contextId };
}

// ── Blocking SendMessage ────────────────────────────────────────────────────

/**
 * Spec §3.2.2: without returnImmediately the call "MUST wait until the task
 * reaches a terminal ... or an interrupted ... state". A Crew task is worked
 * by another agent, possibly on a laptop that is asleep, and a held first
 * contact waits on a PERSON — an HTTP request cannot wait for either. So the
 * wait is bounded (CREW_A2A_BLOCKING_WAIT_MS, default 30 s) and then the task
 * is returned as it stands; a held task returns at once, since nothing an
 * agent does can move it. This is a deliberate, documented deviation;
 * clients that want the spec's semantics stream (SendStreamingMessage) or set
 * returnImmediately and poll / subscribe / push.
 */
function blockingWaitMs() {
  const n = parseInt(process.env.CREW_A2A_BLOCKING_WAIT_MS || '', 10);
  return Number.isFinite(n) && n >= 0 ? Math.min(n, 120_000) : 30_000;
}

function settled(task) {
  const s = toA2aState(task.state);
  return TERMINAL_A2A.includes(s) || INTERRUPTED_A2A.includes(s) || task.held === 1;
}

async function waitForSettled(agentId, taskId, ms) {
  let task = taskFor(agentId, taskId);
  if (!task || settled(task) || ms === 0) return task;
  await new Promise((resolve) => {
    const timer = setTimeout(finish, ms);
    timer.unref?.();
    function finish() { clearTimeout(timer); crewEvents.off('task', onEv); resolve(); }
    function onEv(ev) {
      if (ev.task_id !== taskId) return;
      const t = taskFor(agentId, taskId);
      if (!t || settled(t)) finish();
    }
    crewEvents.on('task', onEv);
  });
  return taskFor(agentId, taskId);
}

// ── Methods ─────────────────────────────────────────────────────────────────

/**
 * SendMessage / SendStreamingMessage share this. Returns the task row as the
 * caller may see it, plus the response options.
 */
function doSendMessage(ctx, params) {
  const p = obj(params, 'params');
  const msg = readMessage(p.message);
  const config = obj(p.configuration, 'configuration');
  const hist = historyLength(config.historyLength, 'configuration.historyLength');
  // Validate the push config BEFORE anything is stored, so a bad URL cannot
  // leave behind a task the caller never got an id for.
  const push = config.taskPushNotificationConfig != null ? (() => {
    try { return validatePushConfig(config.taskPushNotificationConfig); } catch (e) { throw fromCrewError(e); }
  })() : null;

  let taskId;
  if (msg.taskId != null) {
    // Continue an existing task (spec §3.4.3).
    taskId = requiredString(msg.taskId, 'message.taskId', 64);
    const task = taskFor(ctx.agent.id, taskId);
    if (!task) throw notFound(taskId);
    // Spec §3.4.3: "Agents MUST reject messages containing mismatching
    // contextId and taskId".
    if (msg.contextId != null && msg.contextId !== (task.context_id || task.id)) {
      throw invalid('message.contextId', 'message.contextId does not match the task\'s contextId');
    }
    let state;
    if (msg.metadata.taskState != null) {
      state = toCrewState(msg.metadata.taskState);
      if (!state) throw invalid('message.metadata.taskState', 'taskState must be a TASK_STATE_* name Crew uses (WORKING, INPUT_REQUIRED, COMPLETED, FAILED, CANCELED)');
    }
    try {
      reply(ctx.owner, {
        as_agent: ctx.agent.name, task_id: taskId, message: msg.text, state, artifact: msg.artifact || undefined, message_id: msg.messageId,
      }, { actorKind: 'agent' });
    } catch (e) { throw fromCrewError(e, { taskId }); }
  } else {
    const tenant = typeof p.tenant === 'string' ? p.tenant : '';
    if (!tenant) throw invalid('tenant', 'tenant must name the receiving agent for a new task (its Agent Card\'s supportedInterfaces[].tenant)');
    if (msg.artifact) throw invalid('message.parts', 'A new task carries text; artifacts are results, sent on an existing task');
    let contextId;
    if (msg.contextId != null) {
      if (typeof msg.contextId !== 'string' || !CONTEXT_ID_RE.test(msg.contextId)) {
        // Spec §3.4.1: reject, and do not generate a replacement.
        throw invalid('message.contextId', 'contextId must be 1-128 characters: letters, digits, dot, underscore, colon or hyphen');
      }
      contextId = msg.contextId;
    }
    const title = typeof msg.metadata.title === 'string' && msg.metadata.title.trim()
      ? msg.metadata.title
      : (msg.text.split('\n').find((l) => l.trim()) || '').slice(0, CREW_LIMITS.TITLE_MAX);
    let out;
    try {
      out = sendTask(ctx.owner, {
        as_agent: ctx.agent.name, to_agent: tenant, title, message: msg.text, context_id: contextId, message_id: msg.messageId,
      }, { actorKind: 'agent' });
    } catch (e) { throw fromCrewError(e); }
    taskId = out.task_id;
  }
  const task = taskFor(ctx.agent.id, taskId);
  if (push && task) {
    try { createPushConfig(ctx.owner, ctx.agent, task, push, ctx.tokenId); } catch (e) { throw fromCrewError(e); }
  }
  return { taskId, historyLength: hist, returnImmediately: config.returnImmediately === true };
}

async function SendMessage(ctx, params) {
  const r = doSendMessage(ctx, params);
  const task = r.returnImmediately ? taskFor(ctx.agent.id, r.taskId) : await waitForSettled(ctx.agent.id, r.taskId, blockingWaitMs());
  if (!task) throw notFound(r.taskId);
  // a2a.proto SendMessageResponse: oneof { task, message }.
  return { task: toTask(task, { historyLength: r.historyLength }) };
}

function SendStreamingMessage(ctx, params) {
  const r = doSendMessage(ctx, params);
  const task = taskFor(ctx.agent.id, r.taskId);
  if (!task) throw notFound(r.taskId);
  return { stream: { taskId: r.taskId, historyLength: r.historyLength } };
}

function GetTask(ctx, params) {
  const p = obj(params, 'params');
  const id = requiredString(p.id, 'id', 64);
  const hist = historyLength(p.historyLength, 'historyLength');
  const task = taskFor(ctx.agent.id, id);
  if (!task) throw notFound(id);
  return toTask(task, { historyLength: hist });
}

function encodeToken(cursor) {
  return Buffer.from(JSON.stringify(cursor)).toString('base64url');
}

function decodeToken(raw) {
  try {
    const c = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    if (c && typeof c.u === 'string' && typeof c.i === 'string' && c.u.length <= 32 && c.i.length <= 64) return c;
  } catch (_) { /* fall through */ }
  throw invalid('pageToken', 'pageToken is not one this server issued');
}

function ListTasks(ctx, params) {
  const p = obj(params, 'params');
  let state;
  if (p.status != null && p.status !== 'TASK_STATE_UNSPECIFIED') {
    state = toCrewState(p.status);
    if (!state) throw invalid('status', 'status must be a TASK_STATE_* name');
  }
  if (p.contextId != null && (typeof p.contextId !== 'string' || p.contextId.length > 128)) throw invalid('contextId', 'contextId must be a string');
  let pageSize = 50;
  if (p.pageSize != null) {
    if (!Number.isInteger(p.pageSize) || p.pageSize < 1 || p.pageSize > 100) throw invalid('pageSize', 'pageSize must be an integer from 1 to 100');
    pageSize = p.pageSize;
  }
  const cursor = p.pageToken ? decodeToken(String(p.pageToken)) : null;
  let updatedAfter;
  if (p.statusTimestampAfter != null) {
    updatedAfter = typeof p.statusTimestampAfter === 'string' ? sqliteTime(p.statusTimestampAfter) : null;
    if (!updatedAfter) throw invalid('statusTimestampAfter', 'statusTimestampAfter must be an ISO 8601 timestamp');
  }
  const hist = historyLength(p.historyLength, 'historyLength');
  const r = listTasksFor(ctx.agent.id, { contextId: p.contextId || undefined, state, updatedAfter, pageSize, cursor });
  // a2a.proto ListTasksResponse: tasks, next_page_token (REQUIRED; "" on the
  // last page, spec §3.1.4), page_size, total_size. includeArtifacts defaults
  // to false, and then "the artifacts field MUST be omitted entirely".
  return {
    tasks: r.tasks.map((t) => toTask(t, { historyLength: hist, includeArtifacts: p.includeArtifacts === true })),
    nextPageToken: r.next ? encodeToken(r.next) : '',
    pageSize,
    totalSize: r.total,
  };
}

function CancelTask(ctx, params) {
  const p = obj(params, 'params');
  const id = requiredString(p.id, 'id', 64);
  const task = taskFor(ctx.agent.id, id);
  if (!task) throw notFound(id);
  if (TERMINAL_A2A.includes(toA2aState(task.state))) {
    throw new A2AError(RPC.TASK_NOT_CANCELABLE, `Task is already ${toA2aState(task.state)}`, { metadata: { taskId: id } });
  }
  if (task.from_agent_id !== ctx.agent.id) {
    // Crew's rule (crew.reply): only the sending agent cancels; the receiver
    // ends a task it will not do by setting TASK_STATE_FAILED.
    throw new A2AError(RPC.TASK_NOT_CANCELABLE, 'Only the agent that sent a task can cancel it; the receiving agent sets message.metadata.taskState = TASK_STATE_FAILED instead.', { metadata: { taskId: id } });
  }
  try {
    reply(ctx.owner, { as_agent: ctx.agent.name, task_id: id, state: 'canceled' }, { actorKind: 'agent' });
  } catch (e) { throw fromCrewError(e, { taskId: id }); }
  return toTask(taskFor(ctx.agent.id, id));
}

function SubscribeToTask(ctx, params) {
  const p = obj(params, 'params');
  const id = requiredString(p.id, 'id', 64);
  const task = taskFor(ctx.agent.id, id);
  if (!task) throw notFound(id);
  // Spec §3.1.6 / §9.4.6: a terminal task is UnsupportedOperationError.
  if (TERMINAL_A2A.includes(toA2aState(task.state))) {
    throw new A2AError(RPC.UNSUPPORTED_OPERATION, `Task is already ${toA2aState(task.state)}; there is nothing to subscribe to. Use GetTask.`, { metadata: { taskId: id } });
  }
  return { stream: { taskId: id } };
}

// Push config methods (spec §3.1.7-§3.1.10). TaskNotFoundError covers both an
// invisible task and a config that does not exist (spec §3.1.8).
function taskForPush(ctx, rawTaskId, field = 'taskId') {
  const id = requiredString(rawTaskId, field, 64);
  const task = taskFor(ctx.agent.id, id);
  if (!task) throw notFound(id);
  return task;
}

function CreateTaskPushNotificationConfig(ctx, params) {
  // rpc CreateTaskPushNotificationConfig(TaskPushNotificationConfig): the
  // params ARE the config, with task_id naming the task.
  const p = obj(params, 'params');
  const task = taskForPush(ctx, p.taskId);
  if (TERMINAL_A2A.includes(toA2aState(task.state))) {
    throw new A2AError(RPC.UNSUPPORTED_OPERATION, `Task is already ${toA2aState(task.state)}; no further updates will be sent.`, { metadata: { taskId: task.id } });
  }
  let valid;
  try { valid = validatePushConfig(p); } catch (e) { throw invalid(e.field || 'url', e.message); }
  try { return createPushConfig(ctx.owner, ctx.agent, task, valid, ctx.tokenId); } catch (e) {
    if (e instanceof PushConfigError) throw invalid(e.field, e.message);
    throw fromCrewError(e, { taskId: task.id });
  }
}

function GetTaskPushNotificationConfig(ctx, params) {
  const p = obj(params, 'params');
  const task = taskForPush(ctx, p.taskId);
  const cfg = getPushConfig(ctx.agent, task, requiredString(p.id, 'id', 64));
  if (!cfg) throw notFound(task.id);
  return cfg;
}

function ListTaskPushNotificationConfigs(ctx, params) {
  const p = obj(params, 'params');
  const task = taskForPush(ctx, p.taskId);
  // At most CONFIGS_PER_TASK_PER_AGENT rows: one page, always.
  return { configs: listPushConfigs(ctx.agent, task), nextPageToken: '' };
}

function DeleteTaskPushNotificationConfig(ctx, params) {
  const p = obj(params, 'params');
  const task = taskForPush(ctx, p.taskId);
  deletePushConfig(ctx.owner, ctx.agent, task, requiredString(p.id, 'id', 64));
  return {}; // google.protobuf.Empty
}

function GetExtendedAgentCard(ctx) {
  return extendedCard(ctx);
}

const METHODS = {
  SendMessage, SendStreamingMessage, GetTask, ListTasks, CancelTask, SubscribeToTask,
  CreateTaskPushNotificationConfig, GetTaskPushNotificationConfig, ListTaskPushNotificationConfigs, DeleteTaskPushNotificationConfig,
  GetExtendedAgentCard,
};
export const STREAMING_METHODS = new Set(['SendStreamingMessage', 'SubscribeToTask']);

/**
 * Run one JSON-RPC method for an authenticated caller. Resolves to the
 * `result` (or, for the two streaming methods, `{ stream: {...} }` for the
 * route to serve); rejects with an A2AError.
 */
export async function dispatch(ctx, method, params) {
  if (!Object.prototype.hasOwnProperty.call(METHODS, method)) {
    throw new A2AError(RPC.METHOD_NOT_FOUND, 'Method not found');
  }
  touchAgentSeen(ctx.agent.id);
  try {
    return await METHODS[method](ctx, params);
  } catch (e) {
    throw fromCrewError(e);
  }
}

// ── Agent Cards (spec §8, a2a.proto AgentCard) ──────────────────────────────

function securityParts() {
  return {
    // a2a.proto SecurityScheme oneof → ProtoJSON `httpAuthSecurityScheme`.
    securitySchemes: {
      crewAgentToken: {
        httpAuthSecurityScheme: {
          scheme: 'Bearer',
          bearerFormat: 'opaque',
          description: 'A Crew agent token (dhk_crew_...), issued per agent by its owner in AppCrane -> Crew -> My agents. It acts only as that agent, with at most its owner\'s permissions.',
        },
      },
    },
    securityRequirements: [{ schemes: { crewAgentToken: { list: [] } } }],
  };
}

function capabilities() {
  return {
    streaming: true,
    pushNotifications: true,
    extendedAgentCard: true,
    extensions: [{
      uri: CREW_RELAY_EXTENSION,
      description: 'Crew relays tasks between agents. The agent a task was sent to reports on it with SendMessage on that task: message.metadata.taskState = TASK_STATE_WORKING | INPUT_REQUIRED | COMPLETED | FAILED, and a result as a part with a filename. message.metadata.title sets a new task\'s title.',
      required: false,
    }],
  };
}

/**
 * The public card at /.well-known/agent-card.json (spec §8.2: "Accessing
 * https://{server_domain}/.well-known/agent-card.json"). It describes the Crew
 * endpoint itself and lists no agents: the roster is for authenticated
 * callers only (GetExtendedAgentCard, per-agent cards).
 */
export function publicCard({ baseUrl, version }) {
  return {
    name: 'AppCrane Crew',
    description: 'The agent hub of this AppCrane platform. Registered agents find each other and hand off tasks here; the people who own them approve first contacts and can block agents. Address an agent with SendMessage and tenant = its name.',
    supportedInterfaces: [{ url: `${baseUrl}/a2a`, protocolBinding: 'JSONRPC', protocolVersion: SUPPORTED_VERSION }],
    version: String(version || '0.0.0'),
    capabilities: capabilities(),
    ...securityParts(),
    defaultInputModes: ['text/plain', 'application/json'],
    defaultOutputModes: ['text/plain'],
    skills: [{
      id: 'crew-relay',
      name: 'Hand a task to a Crew agent',
      description: 'Relays a task to the registered agent named by `tenant`, subject to its owner\'s first-contact approval and blocks. Authenticated callers see the roster with GetExtendedAgentCard.',
      tags: ['crew', 'relay', 'handoff'],
    }],
  };
}

function agentSkillsOf(row) {
  return row.skills.map((id) => ({ id, name: id, description: id, tags: [id] }));
}

/**
 * GetExtendedAgentCard (spec §3.1.11, §13.3): the platform card with one
 * skill per roster agent — what any authenticated agent may see on the roster
 * (name, owner, description, skills). Never blocks, block counts, "doing now"
 * or tasks.
 */
function extendedCard(ctx) {
  const base = publicCard({ baseUrl: ctx.baseUrl, version: ctx.version });
  const rows = roster(ctx.owner);
  base.skills = rows.map((r) => ({
    id: `agent:${r.name}`,
    name: r.name,
    description: `${r.description || 'A Crew agent.'} Owner: ${r.owner}. Send it a task with tenant = "${r.name}".`,
    tags: ['crew-agent', ...r.skills],
  }));
  return base;
}

/** One crew agent's card, served from the directory to an authenticated caller; null when unknown. */
export function agentCard(ctx, name) {
  const row = roster(ctx.owner).find((r) => r.name === name);
  if (!row) return null;
  return {
    name: row.name,
    description: `${row.description || 'A Crew agent.'} Owner: ${row.owner}. Relayed by AppCrane Crew.`,
    supportedInterfaces: [{ url: `${ctx.baseUrl}/a2a`, protocolBinding: 'JSONRPC', tenant: row.name, protocolVersion: SUPPORTED_VERSION }],
    version: String(ctx.version || '0.0.0'),
    capabilities: capabilities(),
    ...securityParts(),
    defaultInputModes: ['text/plain', 'application/json'],
    defaultOutputModes: ['text/plain'],
    skills: agentSkillsOf(row),
  };
}

/** ETag for a card (spec §8.6.1 SHOULD). */
export function etagOf(card) {
  return `"${crypto.createHash('sha256').update(JSON.stringify(card)).digest('base64url').slice(0, 27)}"`;
}
