/**
 * Crew tasks as A2A 1.0 objects (phase 2). Pure rendering: no rule about WHO
 * may see a task lives here — callers pass a task that crew.taskFor() already
 * returned for the viewing agent.
 *
 * Shapes follow the A2A 1.0 protocol buffer (specification/a2a.proto, package
 * lf.a2a.v1) serialised as ProtoJSON, as spec §5.5 requires: camelCase field
 * names, enum values as their SCREAMING_SNAKE_CASE names, timestamps as ISO
 * 8601 UTC strings with a Z (spec §5.6.1).
 */
import { taskMessages } from './crew.js';

// ── The one state mapping ───────────────────────────────────────────────────
//
// crew_tasks.state already uses the A2A state names in lowercase (migration
// 112). a2a.proto `enum TaskState` also has TASK_STATE_UNSPECIFIED and
// TASK_STATE_AUTH_REQUIRED; Crew never enters either (an agent's credentials
// are its owner's business, not something one agent asks another for), so
// they map to nothing and are refused as input.
const CREW_TO_A2A = Object.freeze({
  submitted:      'TASK_STATE_SUBMITTED',
  working:        'TASK_STATE_WORKING',
  input_required: 'TASK_STATE_INPUT_REQUIRED',
  completed:      'TASK_STATE_COMPLETED',
  failed:         'TASK_STATE_FAILED',
  canceled:       'TASK_STATE_CANCELED',
  rejected:       'TASK_STATE_REJECTED',
});
const A2A_TO_CREW = Object.freeze(Object.fromEntries(Object.entries(CREW_TO_A2A).map(([k, v]) => [v, k])));

export function toA2aState(crewState) {
  return CREW_TO_A2A[crewState] || 'TASK_STATE_UNSPECIFIED';
}

/** The crew state for an A2A state name, or null when Crew has no such state. */
export function toCrewState(a2aState) {
  return A2A_TO_CREW[a2aState] || null;
}

// Spec §3.1.2 / §3.1.6: streams close on these.
export const TERMINAL_A2A = Object.freeze(['TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED']);
// Spec §3.2.2: a blocking SendMessage returns at a terminal OR an interrupted state.
export const INTERRUPTED_A2A = Object.freeze(['TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_AUTH_REQUIRED']);

export function isTerminalCrewState(s) {
  return TERMINAL_A2A.includes(toA2aState(s));
}

/** SQLite's 'YYYY-MM-DD HH:MM:SS' (UTC) as spec §5.6.1's 'YYYY-MM-DDTHH:mm:ss.sssZ'. */
export function isoTime(sqliteTime) {
  if (!sqliteTime) return undefined;
  const d = new Date(String(sqliteTime).replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** An ISO 8601 timestamp as SQLite's datetime() text, for comparisons; null when unparsable. */
export function sqliteTime(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

// ── Messages, artifacts, tasks ──────────────────────────────────────────────

function messageId(m) {
  return m.message_id || `crew-msg-${m.id}`;
}

/**
 * a2a.proto Role: ROLE_USER is "from the client to the server", ROLE_AGENT
 * "from the server to the client". In a relayed Crew task the sender is the
 * client of the receiving agent, so the sender's messages are ROLE_USER and
 * the receiver's ROLE_AGENT — whoever is looking.
 */
function toMessage(task, m) {
  const text = m.body && m.body.trim() ? m.body : (m.artifact_name ? `[artifact: ${m.artifact_name}]` : '');
  // Phase 3: a PERSON's answer (actor_kind 'human') is always ROLE_USER — it
  // comes from the client side of the conversation, whichever agent's side
  // it was stored on — and is marked so an agent can tell it from its peer.
  const human = m.actor_kind === 'human';
  return {
    messageId: messageId(m),
    contextId: task.context_id || task.id,
    taskId: task.id,
    role: human || m.from_agent_id === task.from_agent_id ? 'ROLE_USER' : 'ROLE_AGENT',
    parts: [{ text }],
    ...(human ? { metadata: { actorKind: 'human' } } : {}),
  };
}

function toArtifact(m) {
  return {
    artifactId: `crew-artifact-${m.id}`,
    name: m.artifact_name,
    parts: [{ text: m.artifact_body || '', filename: m.artifact_name }],
  };
}

function statusOf(task, msgs) {
  const status = { state: toA2aState(task.state), timestamp: isoTime(task.updated_at) };
  // a2a.proto TaskStatus.message: "A message associated with the status". The
  // receiver's latest message is the question (input_required) or the reason
  // (failed); attached so a client polling GetTask sees why without history.
  if (task.state === 'input_required' || task.state === 'failed') {
    const last = msgs.at(-1);
    if (last && last.from_agent_id === task.to_agent_id && last.actor_kind !== 'human') status.message = toMessage(task, last);
  }
  return status;
}

/**
 * a2a.proto `Task` for one viewer. `historyLength` follows spec §3.2.4:
 * undefined = server default (here: every stored message, at most 200),
 * 0 = no history field at all, n = the n most recent. `includeArtifacts:false`
 * omits the artifacts field entirely, as spec §3.1.4 requires for ListTasks.
 * A rejected task carries neither: the only thing a rejected sender learns is
 * the state, exactly as appcrane_crew_inbox shows it.
 */
export function toTask(task, { historyLength, includeArtifacts = true } = {}) {
  const rejected = task.state === 'rejected';
  const msgs = rejected ? [] : taskMessages(task.id);
  const out = {
    id: task.id,
    contextId: task.context_id || task.id,
    status: statusOf(task, msgs),
  };
  if (includeArtifacts) out.artifacts = msgs.filter((m) => m.artifact_name).map(toArtifact);
  if (historyLength !== 0) {
    const shown = historyLength > 0 ? msgs.slice(-historyLength) : msgs;
    out.history = shown.map((m) => toMessage(task, m));
  }
  out.metadata = {
    title: task.title,
    fromAgent: task.from_agent,
    toAgent: task.to_agent,
    ...(task.held && task.state === 'submitted' ? { waitingForApproval: true } : {}),
    ...(task.action ? { action: task.action } : {}),
    ...(task.scope ? { scope: task.scope } : {}),
    ...(task.rule_id ? { approvedByRule: task.rule_id } : {}),
  };
  return out;
}

// ── Stream events ───────────────────────────────────────────────────────────

/** Where a stream (or push config) is: the last state and the last message id it has delivered. */
export function cursorOf(task) {
  const msgs = task.state === 'rejected' ? [] : taskMessages(task.id);
  return { state: task.state, lastMsgId: msgs.at(-1)?.id || 0 };
}

/**
 * The a2a.proto `StreamResponse` objects that bring a viewer from `cursor` to
 * the task as it is now, in the order they happened (spec §3.5.2: events MUST
 * NOT be reordered):
 *   - each new artifact → { artifactUpdate: TaskArtifactUpdateEvent }
 *   - each new plain message → { statusUpdate } carrying the message as
 *     status.message (spec §3.7: "Agents attach Messages to status update
 *     events to inform clients about task progress")
 *   - a state change with no message of its own → { statusUpdate }
 * Returns the events and the new cursor.
 */
export function eventsSince(task, cursor) {
  const contextId = task.context_id || task.id;
  const timestamp = isoTime(task.updated_at);
  const state = toA2aState(task.state);
  const fresh = task.state === 'rejected' ? [] : taskMessages(task.id).filter((m) => m.id > cursor.lastMsgId);
  const events = [];
  for (const m of fresh) {
    if (m.artifact_name) {
      events.push({ artifactUpdate: { taskId: task.id, contextId, artifact: toArtifact(m), append: false, lastChunk: true } });
    }
    if (m.body && m.body.trim()) {
      // The state as it was when this message was written (state_after), so a
      // burst of changes rendered at once still reads in order.
      const at = m.state_after ? toA2aState(m.state_after) : state;
      events.push({ statusUpdate: { taskId: task.id, contextId, status: { state: at, timestamp: isoTime(m.created_at) || timestamp, message: toMessage(task, m) } } });
    }
  }
  const stateChanged = task.state !== cursor.state;
  const lastStatus = [...events].reverse().find((e) => e.statusUpdate)?.statusUpdate.status.state;
  if (stateChanged && lastStatus !== state) {
    events.push({ statusUpdate: { taskId: task.id, contextId, status: { state, timestamp } } });
  }
  return { events, cursor: { state: task.state, lastMsgId: fresh.at(-1)?.id || cursor.lastMsgId } };
}
