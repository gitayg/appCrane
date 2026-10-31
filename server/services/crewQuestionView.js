/**
 * Crew: what a person approves when they answer a declared question.
 *
 * SECURITY FIX (review of v2.129.2): the Crew log showed at most a budget of
 * the messages a declared question was about, but the approval covered every
 * message up to an id — so a production or deletion line past the cut was
 * approved unseen. Now the question's coverage IS its display: planQuestion
 * picks the messages at ask time within one budget, the ones that set off the
 * always-ask rule first, and only messages shown in full are covered; the
 * stored plan (crew_decisions.covers_json, migration 165) is what the Crew log
 * renders (renderQuestion) and what an approval covers (approvedMessageIds).
 * One plan, so the two cannot drift.
 *
 *   - The first message in the order is always shown whole, whatever its
 *     length: the person always sees the line that triggered the ask, and
 *     every question covers at least one message, so asking again always
 *     makes progress.
 *   - Messages left out stay unapproved; after the answer the app coder's
 *     backstop (crewAppCoder.js) checks them again and asks again if one
 *     still mentions production or deleting. The question says how many.
 */
import { alwaysAskReason } from './crewRules.js';

export const QUESTION_BUDGET = Object.freeze({ perMessage: 600, total: 1200, messages: 20 });

/** One display line: control characters out, whitespace collapsed (as crew.oneLine, uncut). */
// Invisible format characters (bidi overrides, zero-width, tag characters) are
// removed so the text the owner reads is the text they approve, and '|' is
// taken out of message text so the separator between messages cannot be faked.
export function displayLine(body) {
  return String(body ?? '')
    .replace(/\p{Cf}+/gu, '')
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ')
    .replace(/\|/g, '/')
    .replace(/\s+/g, ' ').trim();
}

/**
 * The messages `deciderId` has approved on a task: those covered by a declared
 * question of theirs they approved or answered. Questions asked before
 * migration 165 (covers_msg_id only, v2.129.2) cover up to that id.
 */
export function approvedMessageIds(db, taskId, deciderId) {
  const ids = new Set();
  let upTo = 0;
  const rows = db.prepare(`SELECT covers_msg_id, covers_json FROM crew_decisions
                           WHERE task_id = ? AND ask = 'declared' AND status IN ('approved', 'replied') AND decider_user_id = ?`).all(taskId, deciderId);
  for (const d of rows) {
    if (d.covers_json) {
      try { for (const id of JSON.parse(d.covers_json).ids || []) ids.add(id); } catch (_) { /* covers nothing */ }
    } else if (d.covers_msg_id != null) {
      upTo = Math.max(upTo, d.covers_msg_id);
    }
  }
  return { has: (id) => id <= upTo || ids.has(id) };
}

/**
 * The plan for a new declared question on `task` for `deciderId`: the task's
 * messages its agent has not yet worked on, that this person has not approved,
 * from anyone but the receiving side. Returns { ids, more } — ids in display
 * order, every one shown in full; more = how many were left out.
 */
export function planQuestion(db, task, deciderId) {
  const approved = approvedMessageIds(db, task.id, deciderId);
  const candidates = db.prepare(`SELECT id, body FROM crew_messages
                                 WHERE task_id = ? AND id > COALESCE(?, 0) AND from_agent_id <> ? ORDER BY id ASC`)
    .all(task.id, task.coder_seen_msg_id ?? null, task.to_agent_id)
    .filter((m) => !approved.has(m.id))
    .map((m) => ({ id: m.id, len: displayLine(m.body).length, trigger: !!alwaysAskReason({ texts: [m.body] }) }));
  const order = [...candidates.filter((m) => m.trigger), ...candidates.filter((m) => !m.trigger)];
  const ids = [];
  let used = 0;
  order.forEach((m, i) => {
    if (ids.length >= QUESTION_BUDGET.messages) return;
    const whole = i === 0;
    if (!whole && (m.len > QUESTION_BUDGET.perMessage || used + m.len > QUESTION_BUDGET.total)) return;
    ids.push(m.id);
    used += m.len;
  });
  return { ids, more: candidates.length - ids.length };
}

/** The question text the Crew log shows for a stored plan: exactly the covered messages, in full. */
export function renderQuestion(db, coversJson) {
  let plan;
  try { plan = JSON.parse(coversJson); } catch (_) { return null; }
  const get = db.prepare('SELECT body FROM crew_messages WHERE id = ?');
  const lines = (plan.ids || []).map((id) => get.get(id)).filter(Boolean).map((m) => displayLine(m.body));
  if (!lines.length) return null;
  const more = plan.more > 0
    ? ` (${plan.more} more message${plan.more === 1 ? '' : 's'} will be asked about separately.)`
    : '';
  return `${lines.join(' | ')}${more}`;
}
