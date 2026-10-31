/**
 * Crew: AppCrane answers tasks sent to an app coder ("<slug>-coder") by running
 * that app's coder session. The identities live in crewAppCoderAgents.js, the
 * prompt in crewAppCoderPrompt.js, the session plumbing in crewAppCoderRunner.js.
 *
 * ── When a task runs ────────────────────────────────────────────────────────
 * Only once Crew has let it through, by the rules every task obeys (crew.js
 * gateFor): blocks, first contact (held until the app coder's owner decides,
 * with the one e-mail), standing rules, declared approvals, and "production and
 * deletions always ask" — for an app coder that backstop also reads the task's
 * own words, since nothing else stands between delivery and a running coder.
 * Nothing here decides who may reach the coder; it reacts to crewEvents and
 * starts a turn for a task that is delivered (held = 0), open (submitted or
 * working), has no question pending for a person, and carries a message the
 * coder has not seen. A person's Approve or Reply on a question the coder asked
 * moves the task back to working, which is how a follow-up turn starts.
 *
 * ── Whose credential ────────────────────────────────────────────────────────
 * The turn runs as the app coder's owner (crew_agents.owner_user_id): the
 * person who allowed the first contact, approved the task, or owns the rule
 * that let it through — never the sending agent's owner. The owner is re-read
 * (identity sync) right before a turn starts; an owner change fails the open
 * tasks the previous owner approved instead of billing the new one.
 *
 * ── One at a time, refused when busy ────────────────────────────────────────
 * An app has one coder workspace. A task that arrives while another task for
 * the same app is running, while the owner's own session is mid-turn, or while
 * another person holds the app's coder is FAILED with a clear "busy, send it
 * again" reason rather than queued: a queued request would run later against
 * code that changed under it, its sender has no way to withdraw it from a
 * queue it cannot see, and an in-memory queue would be lost on restart. The
 * sender can retry; A2A clients handle a failed task.
 *
 * ── The answer ──────────────────────────────────────────────────────────────
 * The coder's final reply becomes the task's answer through crew.replyAsAppCoder,
 * so it passes the same secret scan as any agent's message: an answer that
 * looks like it carries a credential is withheld and the task fails saying so.
 * A reply ending in "QUESTION FOR REQUESTER: ..." sets input_required, routed
 * to the sending agent's owner as every Crew question is by default.
 */
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import { crewEvents, replyAsAppCoder, syncAppCoders, CREW_LIMITS } from './crew.js';
import { buildCoderTaskPrompt, parseCoderAnswer } from './crewAppCoderPrompt.js';
import { defaultCoderRunner } from './crewAppCoderRunner.js';

let runner = defaultCoderRunner;
let started = false;
const running = new Map();   // task id → AbortController of its turn
const inflight = new Set();  // promises of tryStart / turns, for whenIdle()

/** Tests inject a runner: ({ app, userId, prompt, taskId, signal }) → { ok, text } | { ok: false, reason, busy? }. */
export function setCoderRunner(fn) {
  runner = fn || defaultCoderRunner;
}

/** Resolves once no claim or turn is in flight (tests). */
export async function whenIdle() {
  while (inflight.size) await Promise.allSettled([...inflight]);
}

function track(p) {
  inflight.add(p);
  p.finally(() => inflight.delete(p));
  return p;
}

function audit(userId, appId, action, detail) {
  try {
    logAudit(userId, appId, action, detail, 'agent');
  } catch (e) {
    log.warn(`[crew] audit write failed for ${action}: ${e.message}`);
  }
}

function taskRow(db, taskId) {
  return db.prepare(`
    SELECT t.*, a.app_id, a.owner_user_id AS coder_owner_id, a.name AS coder_name
    FROM crew_tasks t JOIN crew_agents a ON a.id = t.to_agent_id WHERE t.id = ?`).get(taskId);
}

function runnable(db, t) {
  return !!t && t.app_id != null && t.held === 0 && ['submitted', 'working'].includes(t.state)
    && t.coder_status !== 'running'
    && !db.prepare("SELECT 1 FROM crew_decisions WHERE task_id = ? AND status = 'pending'").get(t.id);
}

function failTask(agentId, taskId, reason) {
  try {
    replyAsAppCoder(agentId, { task_id: taskId, state: 'failed', message: reason });
  } catch (e) {
    log.warn(`[crew] could not fail app coder task ${taskId}: ${e.message}`);
  }
}

/**
 * Claim a runnable task for a turn, inside one transaction so two events for
 * the same task (or two tasks for the same app) cannot both start one.
 * Returns null (nothing to do), { busy } or { task, messages }.
 */
function claim(db, taskId) {
  return db.transaction(() => {
    const t = taskRow(db, taskId);
    if (!runnable(db, t)) return null;
    const messages = db.prepare(`
      SELECT m.id, m.from_agent_id, m.actor_kind, m.body, a.name AS agent, u.name AS person
      FROM crew_messages m JOIN crew_agents a ON a.id = m.from_agent_id LEFT JOIN users u ON u.id = m.from_user_id
      WHERE m.task_id = ? AND m.id > COALESCE(?, 0) AND NOT (m.from_agent_id = ? AND m.actor_kind = 'agent')
      ORDER BY m.id ASC`).all(t.id, t.coder_seen_msg_id, t.to_agent_id);
    if (!messages.length) return null;
    const other = db.prepare("SELECT 1 FROM crew_tasks WHERE to_agent_id = ? AND coder_status = 'running' AND id <> ?").get(t.to_agent_id, t.id);
    if (other) return { busy: true, task: t };
    const maxId = db.prepare('SELECT MAX(id) AS id FROM crew_messages WHERE task_id = ?').get(t.id).id;
    db.prepare("UPDATE crew_tasks SET coder_status = 'running', coder_seen_msg_id = ?, coder_billed_user_id = ? WHERE id = ?")
      .run(maxId, t.coder_owner_id, t.id);
    return { task: t, messages };
  })();
}

async function tryStart(taskId) {
  const db = getDb();
  const before = taskRow(db, taskId);
  if (!runnable(db, before)) return;
  // The owner a turn bills to must be current: an ownership change fails the
  // tasks the previous owner approved (crewAppCoderAgents.js).
  syncAppCoders(db, before.app_id);
  const c = claim(db, taskId);
  if (!c) return;
  const t = c.task;
  if (c.busy) {
    failTask(t.to_agent_id, t.id, `${t.coder_name} is already working on another task for this app. One task runs at a time; send this one again when that one is done.`);
    return;
  }

  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(t.app_id);
  const sender = db.prepare(`SELECT a.name AS agent, a.owner_user_id, u.name AS person, u.email
                             FROM crew_agents a JOIN users u ON u.id = a.owner_user_id WHERE a.id = ?`).get(t.from_agent_id);
  const owner = db.prepare('SELECT name, email FROM users WHERE id = ?').get(t.coder_owner_id);
  const prompt = buildCoderTaskPrompt({
    task: t,
    app,
    sender: { agent: sender.agent, person: sender.person || 'another person', sameOwner: sender.owner_user_id === t.coder_owner_id },
    owner: owner?.name || 'the app owner',
    messages: c.messages.map((m) => (m.actor_kind === 'human'
      ? { kind: 'human', author: m.person || 'a person', body: m.body }
      : { kind: 'agent', author: m.agent, body: m.body })),
    followUp: t.coder_status === 'idle',
  });

  try {
    replyAsAppCoder(t.to_agent_id, { task_id: t.id, state: 'working' });
  } catch (e) {
    db.prepare("UPDATE crew_tasks SET coder_status = 'idle' WHERE id = ?").run(t.id);
    failTask(t.to_agent_id, t.id, `The coder could not take this task: ${e.message}`);
    return;
  }
  audit(t.coder_owner_id, app.id, 'crew.app_coder.run', {
    task_id: t.id, from_agent_id: t.from_agent_id, to_agent_id: t.to_agent_id,
    billed_user_id: t.coder_owner_id, prompt_chars: prompt.length, follow_up: t.coder_status === 'idle',
  });

  const ac = new AbortController();
  running.set(t.id, ac);
  let result;
  try {
    result = await runner({ app, userId: t.coder_owner_id, prompt, taskId: t.id, signal: ac.signal });
  } catch (e) {
    result = { ok: false, reason: `The coder turn failed: ${e.message}` };
  } finally {
    running.delete(t.id);
  }
  db.prepare("UPDATE crew_tasks SET coder_status = 'idle', coder_session_id = COALESCE(?, coder_session_id) WHERE id = ?")
    .run(result?.sessionId ?? null, t.id);
  finishTurn(db, t, app, result || { ok: false, reason: 'The coder turn ended without a result.' });
}

function finishTurn(db, t, app, result) {
  const now = db.prepare('SELECT state FROM crew_tasks WHERE id = ?').get(t.id);
  if (!now || !['submitted', 'working', 'input_required'].includes(now.state)) {
    audit(t.coder_owner_id, app.id, 'crew.app_coder.done', { task_id: t.id, outcome: 'task_closed', state: now?.state ?? 'deleted' });
    return;
  }
  if (!result.ok) {
    audit(t.coder_owner_id, app.id, 'crew.app_coder.done', { task_id: t.id, outcome: result.busy ? 'busy' : 'failed' });
    failTask(t.to_agent_id, t.id, result.reason || 'The coder turn failed.');
    return;
  }
  const { state, message } = parseCoderAnswer(result.text);
  const args = { task_id: t.id, state };
  if (Buffer.byteLength(message, 'utf8') > CREW_LIMITS.BODY_MAX_BYTES - 200) {
    // Too long for one message: a shortened message plus the whole answer as
    // an artifact (64 KB), the place Crew keeps a result document.
    args.message = `${Buffer.from(message, 'utf8').subarray(0, CREW_LIMITS.BODY_MAX_BYTES - 400).toString('utf8').replace(/�+$/, '')}\n\n(The full answer is attached as the artifact coder-answer.md.)`;
    args.artifact = { name: 'coder-answer.md', body: Buffer.from(message, 'utf8').subarray(0, CREW_LIMITS.ARTIFACT_MAX_BYTES).toString('utf8').replace(/�+$/, '') };
  } else {
    args.message = message;
  }
  if (state === 'input_required') args.ask = 'sender_owner';
  try {
    replyAsAppCoder(t.to_agent_id, args);
    audit(t.coder_owner_id, app.id, 'crew.app_coder.done', { task_id: t.id, outcome: state, answer_chars: message.length });
  } catch (e) {
    audit(t.coder_owner_id, app.id, 'crew.app_coder.done', { task_id: t.id, outcome: 'answer_refused', code: e.code || null });
    failTask(t.to_agent_id, t.id, e.code === 'SECRET_IN_MESSAGE'
      ? `The coder's answer was withheld: it contained what looks like a credential, and Crew never relays one. Ask ${app.slug}'s owner to look at the coder session instead.`
      : `The coder's answer could not be sent: ${e.message}`);
  }
}

function onTaskEvent({ task_id: taskId, kind }) {
  const ac = running.get(taskId);
  if (ac) {
    // A running task that was canceled, blocked away or deleted stops its turn.
    const t = kind === 'deleted' ? null : getDb().prepare('SELECT state FROM crew_tasks WHERE id = ?').get(taskId);
    if (!t || ['canceled', 'rejected', 'failed', 'completed'].includes(t.state)) ac.abort();
    return;
  }
  if (kind === 'deleted') return;
  track(tryStart(taskId).catch((e) => log.warn(`[crew] app coder task ${taskId}: ${e.message}`)));
}

/**
 * Start answering app coder tasks: reconcile the identities, fail turns a
 * restart cut off (their session is gone: builderSession.recoverOrphans paused
 * it), listen for task events and pick up anything already runnable.
 */
export function startCrewAppCoder({ runner: injected } = {}) {
  if (injected) setCoderRunner(injected);
  const db = getDb();
  syncAppCoders(db);
  for (const t of db.prepare("SELECT t.id, t.to_agent_id FROM crew_tasks t WHERE t.coder_status = 'running'").all()) {
    db.prepare("UPDATE crew_tasks SET coder_status = 'idle' WHERE id = ?").run(t.id);
    failTask(t.to_agent_id, t.id, 'AppCrane restarted while the coder was working on this task, so the turn was lost. Send the task again.');
  }
  if (!started) {
    started = true;
    crewEvents.on('task', onTaskEvent);
  }
  const pending = db.prepare(`
    SELECT t.id FROM crew_tasks t JOIN crew_agents a ON a.id = t.to_agent_id
    WHERE a.app_id IS NOT NULL AND t.held = 0 AND t.state IN ('submitted', 'working') AND COALESCE(t.coder_status, '') <> 'running'
    ORDER BY t.created_at ASC`).all();
  for (const { id } of pending) track(tryStart(id).catch((e) => log.warn(`[crew] app coder task ${id}: ${e.message}`)));
}
