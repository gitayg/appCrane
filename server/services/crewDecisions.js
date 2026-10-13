/**
 * Crew, phase 3: a person answering a question an agent routed to them.
 *
 * A decision row (crew_decisions) names exactly ONE person (decider_user_id):
 * the owner of the task's sending agent when the receiving agent asked
 * 'sender_owner', its own owner for 'my_owner', or the receiving person for a
 * task that declared an action ('declared'). Only that person may decide —
 * not the other party, not a platform admin. Seeing a task (an admin sees the
 * roster, the other owner sees their own Crew log) is not deciding it.
 *
 *   approve        → task back to working; "Approved" stored as a message from
 *                    the person (actor_kind 'human', A2A role user)
 *   approve_always → approve, plus a standing rule for (the other agent,
 *                    action, scope), optionally expiring; refused for
 *                    production / deletions and when either field is missing
 *   reply          → the person's text, as a human message; task back to
 *                    working so the agent picks it up
 *   decline        → task rejected (declined = 1: the asking agent still sees
 *                    it, unlike a silent block)
 *
 * Nothing here sends e-mail: ongoing work lives in the dashboard (operator
 * decision; e-mail is for first contact only). Audit rows carry ids, the
 * decision and lengths — never the reply text.
 */
import { getDb } from '../db.js';
import {
  fail, audit, announce, oneLine, assertNoSecret, assertBodySize, closePendingDecisions, CREW_LIMITS,
} from './crew.js';
import { createRuleRow, auditRuleCreate, listRules, revokeRule, updateRuleExpiry, normalizeAction, normalizeScope } from './crewRules.js';

const DECISIONS = ['approve', 'approve_always', 'reply', 'decline'];

function decisionFor(db, user, decisionId) {
  const d = typeof decisionId === 'string' && decisionId.length <= 64
    ? db.prepare('SELECT * FROM crew_decisions WHERE id = ?').get(decisionId) : null;
  // One answer for "no such question", "not yours" and "already answered":
  // a decision id must not reveal whether it exists to someone else.
  if (!d || d.decider_user_id !== user.id) fail(404, 'NOT_FOUND', 'No question waiting for you with that id.');
  return d;
}

export function decideTask(user, decisionId, { decision, message, expires_in_days } = {}) {
  const db = getDb();
  if (!DECISIONS.includes(decision)) fail(400, 'VALIDATION', `decision must be one of ${DECISIONS.join(', ')}.`);
  const d = decisionFor(db, user, decisionId);
  const task = db.prepare('SELECT * FROM crew_tasks WHERE id = ?').get(d.task_id);
  if (d.status !== 'pending' || !task || task.state !== 'input_required' || task.held) {
    fail(409, 'NOT_PENDING', 'This question has already been answered, or the task moved on without it.');
  }
  const text = String(message ?? '');
  if (decision === 'reply') {
    if (!text.trim()) fail(400, 'VALIDATION', 'Write the reply the agent should get.');
    assertBodySize('reply', text, CREW_LIMITS.BODY_MAX_BYTES);
    assertNoSecret('reply', text);
  }
  const person = oneLine(user.name || user.email || 'the owner', 80);
  // The person's message is stored on the agent of THEIR side of the task:
  // the sender for 'sender_owner', the receiver for 'my_owner' / 'declared'.
  // actor_kind 'human' + from_user_id say who actually wrote it.
  const sideAgentId = d.ask === 'sender_owner' ? task.from_agent_id : task.to_agent_id;
  const body = decision === 'reply' ? text
    : decision === 'decline' ? `Declined by ${person}.`
    : `Approved by ${person}.`;
  const nextState = decision === 'decline' ? 'rejected' : 'working';

  const out = db.transaction(() => {
    let rule = null;
    let created = false;
    if (decision === 'approve_always') {
      const first = db.prepare('SELECT body FROM crew_messages WHERE task_id = ? ORDER BY id ASC LIMIT 1').get(task.id);
      ({ rule, created } = createRuleRow(db, user, {
        agentId: d.subject_agent_id, action: d.action, scope: d.scope, expiresInDays: expires_in_days,
        fromDecisionId: d.id, texts: [task.title, first?.body || ''],
      }));
    }
    const status = decision === 'decline' ? 'declined' : decision === 'reply' ? 'replied' : 'approved';
    db.prepare("UPDATE crew_decisions SET status = ?, decided_at = datetime('now'), created_rule_id = ? WHERE id = ?").run(status, rule?.id ?? null, d.id);
    closePendingDecisions(db, [task.id]);
    db.prepare(`INSERT INTO crew_messages (task_id, from_agent_id, body, state_after, actor_kind, from_user_id)
                VALUES (?, ?, ?, ?, 'human', ?)`).run(task.id, sideAgentId, body, nextState, user.id);
    db.prepare(`UPDATE crew_tasks SET state = ?, declined = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(nextState, decision === 'decline' ? 1 : 0, task.id);
    return { rule, created };
  })();

  audit(user, `crew.decision.${decision}`, {
    decision_id: d.id, task_id: task.id, ask: d.ask, state_to: nextState,
    ...(decision === 'reply' ? { message_len: text.length } : {}),
    ...(out.rule ? { rule_id: out.rule.id } : {}),
  }, 'human');
  if (out.rule && out.created) auditRuleCreate(user, out.rule, 'from_approval');
  announce(task.id, 'status');
  return {
    decision_id: d.id, task_id: task.id, decision, state: nextState,
    ...(out.rule ? { rule: { id: out.rule.id, action: out.rule.action, scope: out.rule.scope, expires_at: out.rule.expires_at } } : {}),
  };
}

/**
 * The in-app notification: what is waiting for this person. Pending
 * questions routed to them plus first contacts they have not decided — the
 * Crew nav badge counts these. Never e-mailed.
 */
export function waitingForMe(user) {
  const db = getDb();
  const questions = db.prepare(`
    SELECT d.id, d.task_id, d.ask, d.action, d.scope, d.created_at, t.title, aa.name AS asked_by
    FROM crew_decisions d JOIN crew_tasks t ON t.id = d.task_id JOIN crew_agents aa ON aa.id = d.asked_by_agent_id
    WHERE d.decider_user_id = ? AND d.status = 'pending' AND t.state = 'input_required' AND t.held = 0
    ORDER BY d.created_at DESC LIMIT 50`).all(user.id);
  const firstContacts = db.prepare(`
    SELECT COUNT(*) AS n FROM crew_tasks t JOIN crew_agents ta ON ta.id = t.to_agent_id JOIN crew_agents fa ON fa.id = t.from_agent_id
    WHERE ta.owner_user_id = ? AND fa.owner_user_id <> ? AND t.held = 1 AND t.state = 'submitted'
      AND EXISTS (SELECT 1 FROM crew_connections c WHERE c.from_agent_id = t.from_agent_id AND c.to_owner_id = ? AND c.state = 'pending')`)
    .get(user.id, user.id, user.id).n;
  return {
    waiting: questions.length + firstContacts,
    questions: questions.map((q) => ({ ...q, title: oneLine(q.title, 120) })),
    first_contacts: firstContacts,
  };
}

// ── Standing rules for the dashboard (own only) ─────────────────────────────

export function myRules(user) {
  return { rules: listRules(getDb(), user) };
}

/** Add a rule by hand (Rules & blocks → Add a rule). */
export function addRule(user, { agent, action, scope, expires_in_days } = {}) {
  const db = getDb();
  const name = String(agent ?? '').trim().toLowerCase();
  const row = name ? db.prepare('SELECT id FROM crew_agents WHERE name = ?').get(name) : null;
  if (!row) fail(404, 'NOT_FOUND', `No agent named "${oneLine(name, 40)}" is registered.`);
  const a = normalizeAction(action);
  const s = normalizeScope(scope);
  if (s) assertNoSecret('scope', s);
  const { rule, created } = db.transaction(() => createRuleRow(db, user, { agentId: row.id, action: a, scope: s, expiresInDays: expires_in_days }))();
  if (created) auditRuleCreate(user, rule, 'by_hand');
  return { rule: listRules(db, user).find((r) => r.id === rule.id), created };
}

export function editRule(user, ruleId, { expires_in_days } = {}) {
  return { rule: updateRuleExpiry(getDb(), user, ruleId, expires_in_days) };
}

export function removeRule(user, ruleId) {
  return revokeRule(getDb(), user, ruleId);
}
