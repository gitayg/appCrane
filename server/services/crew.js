/**
 * Crew, phase 1 (v2.105.0): AppCrane's platform-wide agent-to-agent hub.
 *
 * Agents register once, find each other on a roster, and hand off tasks through
 * an inbox they read over MCP. The people who own them see every exchange in
 * the dashboard and decide the one thing that is theirs to decide: whether
 * someone else's agent may send work to theirs at all.
 *
 * ── Who acts ─────────────────────────────────────────────────────────────────
 * An agent is NOT an identity. It is a named row owned by a person
 * (crew_agents.owner_user_id), and every call that names an agent must be made
 * by that person's own credential — agentForCaller() is the single check, and
 * it refuses platform admins too: an admin may SEE every agent, but acting as
 * someone else's agent would put words in another person's mouth.
 *
 * ── No laundering ────────────────────────────────────────────────────────────
 * Phase 1 executes NOTHING on a receiver's behalf. A task is text addressed to
 * an agent; the receiving agent reads it with its own owner's key and does
 * whatever it does with its own owner's permissions. So a task can never make a
 * more privileged peer act for a less privileged sender — the sender's identity
 * travels with the task (from_agent → its owner) and is shown to the receiver,
 * and nothing here turns a task into an action. Any later phase that executes
 * on receipt must keep that property explicitly.
 *
 * ── First contact ────────────────────────────────────────────────────────────
 * Agents of the same person talk freely. Between different people, a connection
 * is keyed per (sending AGENT, receiving PERSON):
 *   - per sending agent, because the trust decision is about one specific agent:
 *     a person can own a careful test runner and a lead scraper, and allowing
 *     one must not let every agent that person registers later in;
 *   - per receiving person, not per receiving agent, because the person is the
 *     one deciding — one e-mail per person, however many of their agents the
 *     sender addresses.
 * The first task on a new connection is HELD (state 'submitted', held = 1, not
 * visible to the receiver's agents) and the receiving person gets exactly ONE
 * e-mail for that connection, ever (crew_connections.notified_at, set in the
 * same transaction that creates the row). Its links only open the dashboard:
 * decisions are made through the authenticated API, never by an unauthenticated
 * GET, so a mail scanner pre-fetching links cannot allow anything.
 *   Allow      → connection allowed, every held task released; no more e-mail.
 *   Allow once → this one task released; the connection stays pending, so the
 *                next task is held again (in the dashboard, still no e-mail).
 *   Refuse     → connection refused, held tasks rejected. Treated exactly like a
 *                block for that sender until the person allows it later (the
 *                Rules & blocks tab lists refused agents with an Allow button):
 *                re-asking every time would turn "no" into a nag channel.
 *   Block      → block row + held tasks rejected. A block wins over an earlier
 *                Allow, and is checked first.
 * Rejections are silent: the sender sees 'rejected' with no reason, and the
 * receiving person is not notified. Refused and blocked look identical to the
 * sender on purpose.
 *
 * ── Seams for phase 3 ────────────────────────────────────────────────────────
 * Standing rules and INPUT_REQUIRED approvals routed to people are NOT built.
 * gateFor() is the one place that decides a new task's fate; a rule lookup goes
 * there, between the block check and the connection check. input_required is a
 * valid state an agent can set today; phase 3 adds who gets asked.
 *
 * ── Retention ────────────────────────────────────────────────────────────────
 * Tasks and messages are deleted 30 days after their last update
 * (purgeExpiredCrewHistory, run daily). Audit rows are NOT deleted: they hold
 * ids, states and lengths — never a message body or a title — so they can
 * outlive the content under the platform's normal audit retention.
 *
 * ── Phase 2: A2A is another door into the same rules ────────────────────────
 * services/crewA2a.js speaks the A2A JSON-RPC binding and calls sendTask /
 * reply / taskFor / listTasksFor here with the agent its token identifies; it
 * re-implements none of the gate, budget, secret or audit rules. Every change
 * to a task is announced on `crewEvents` (after the transaction commits) so
 * SSE streams and push notifications see the same events whichever door the
 * change came through.
 *
 * ── Security fixes after phase 1 (review of v2.105.0) ───────────────────────
 *   - Blocks and refusals survive the blocked person removing their agent and
 *     registering the same name again (crew_decision_tombstones).
 *   - First-contact e-mail is capped per (sending PERSON, receiving person):
 *     one per 24 hours, however many agents the sender registers
 *     (crew_first_contact_emails). Later first contacts still wait in the
 *     receiver's Crew log; they just do not e-mail.
 *   - assertCrewCaller(): Crew has no app, so a key limited to some apps
 *     (mcp_app_scope) gets no Crew over MCP or A2A, and an agent identity
 *     (users.kind = 'agent') cannot own or act as a crew agent anywhere — a
 *     crew agent must belong to a person who can answer a first contact.
 *
 * ── Security fixes after phase 2 (review of v2.106.0) ───────────────────────
 *   - held = 1 means "never released": a sender cancelling its held task no
 *     longer clears it, so the receiver's agents never see the withdrawn
 *     request, and no decision releases a cancelled task.
 *   - While held, the sender may only cancel: no messages or artifacts that
 *     "Allow once" would release unseen.
 *   - Block and Refuse reject every OPEN task of that agent with the person,
 *     not only held ones, so an earlier Allow cannot outlive a block.
 */
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';
import { enqueueEmail } from './emailQueue.js';
import { findSecret } from './crewSecrets.js';
import log from '../utils/logger.js';

export const CREW_LIMITS = Object.freeze({
  TASKS_PER_HOUR: 60,          // per sending agent
  MESSAGES_PER_HOUR: 300,      // per agent, sends and replies together
  PENDING_FIRST_CONTACTS: 20,  // per sending person, connections awaiting a decision
  AGENTS_PER_OWNER: 25,
  TITLE_MAX: 200,
  BODY_MAX_BYTES: 16 * 1024,
  ARTIFACT_NAME_MAX: 200,
  ARTIFACT_MAX_BYTES: 64 * 1024,
  CARD_MAX_BYTES: 16 * 1024,
  SKILLS_MAX: 20,
  RETENTION_DAYS: 30,
});

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const SKILL_ID_RE = /^[a-z0-9][a-z0-9._-]{0,39}$/;
const OPEN_STATES = ['submitted', 'working', 'input_required'];
const TERMINAL_STATES = ['completed', 'failed', 'canceled', 'rejected'];
// States the RECEIVING agent may move a task to. The sender may only cancel.
const RECEIVER_STATES = ['working', 'completed', 'failed', 'input_required'];

// ── Small helpers ───────────────────────────────────────────────────────────

function fail(status, code, message) {
  throw new AppError(message, status, code);
}

function newTaskId() {
  return crypto.randomBytes(16).toString('base64url');
}

/** Control characters out, whitespace collapsed: titles land in e-mail subjects and table cells. */
function oneLine(s, max) {
  const t = String(s ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max) : t;
}

export function normalizeAgentName(raw) {
  const name = String(raw ?? '').trim().toLowerCase();
  if (!NAME_RE.test(name)) {
    fail(400, 'VALIDATION', 'Agent name must be 2-40 characters: lowercase letters, digits and hyphens, starting with a letter or digit (for example "qa-runner").');
  }
  return name;
}

function assertNoSecret(where, text) {
  const rule = findSecret(text);
  if (rule) {
    fail(400, 'SECRET_IN_MESSAGE',
      `Refused: the ${where} contains what looks like a credential (${rule}). Crew stores messages for 30 days and shows them to another person's agent, so secrets are never relayed. Remove it and send a reference instead (for example the name of the secret in AppCrane).`);
  }
}

function assertBodySize(where, text, maxBytes) {
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    fail(400, 'VALIDATION', `The ${where} is larger than ${Math.round(maxBytes / 1024)} KB. Send a summary, or put the content somewhere both owners can reach and send a pointer.`);
  }
}

function parseCard(json) {
  try { return JSON.parse(json || '{}') || {}; } catch { return {}; }
}

function normalizeSkills(input) {
  if (input == null || input === '') return [];
  let list = input;
  if (typeof list === 'string') list = list.split(',').map((s) => s.trim()).filter(Boolean);
  if (!Array.isArray(list)) fail(400, 'VALIDATION', 'skills must be a list of {id, description} or of skill names.');
  if (list.length > CREW_LIMITS.SKILLS_MAX) fail(400, 'VALIDATION', `At most ${CREW_LIMITS.SKILLS_MAX} skills.`);
  return list.map((s) => {
    const id = String(typeof s === 'string' ? s : s?.id ?? '').trim().toLowerCase();
    if (!SKILL_ID_RE.test(id)) fail(400, 'VALIDATION', `Skill id "${oneLine(id, 60)}" must be 1-40 characters: lowercase letters, digits, dot, underscore or hyphen.`);
    const description = typeof s === 'object' && s ? oneLine(s.description, 200) : '';
    return description ? { id, description } : { id };
  });
}

function normalizeCapabilities(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  // Only the A2A booleans; anything else in a pasted card is not ours to store.
  const out = {};
  for (const k of ['streaming', 'pushNotifications', 'stateTransitionHistory']) {
    if (typeof input[k] === 'boolean') out[k] = input[k];
  }
  return out;
}

function touchAgent(db, agentId) {
  db.prepare("UPDATE crew_agents SET last_seen_at = datetime('now') WHERE id = ?").run(agentId);
}

// ── Events (phase 2) ────────────────────────────────────────────────────────

/**
 * One event per change to a task: { task_id, kind } with kind one of
 * 'created' | 'status' | 'message' | 'artifact' | 'released' | 'deleted'.
 * Emitted on the next tick, after the transaction that made the change has
 * committed, so a listener that re-reads the task sees the new row, and a
 * listener that throws can never fail the agent's call. Listeners re-read the
 * task through taskFor() for their own agent: an event carries no content and
 * no visibility decision of its own.
 */
export const crewEvents = new EventEmitter();
crewEvents.setMaxListeners(0);

function announce(taskIds, kind) {
  const ids = (Array.isArray(taskIds) ? taskIds : [taskIds]).filter(Boolean);
  if (!ids.length) return;
  setImmediate(() => {
    for (const task_id of ids) {
      try { crewEvents.emit('task', { task_id, kind }); } catch (e) { log.warn(`[crew] event listener failed: ${e.message}`); }
    }
  });
}

// ── Who may use Crew at all (security fix after v2.105.0) ───────────────────

/**
 * Mirrors mcpTools.mcpScope(): an explicit users.mcp_app_scope (a JSON array,
 * including [] = locked out) restricts the caller to those apps. Unparsable
 * means "no scope", exactly as mcpScope treats it, so the two never disagree.
 */
function hasExplicitAppScope(user) {
  const raw = user?.mcp_app_scope;
  if (raw == null || raw === '') return false;
  try { return Array.isArray(JSON.parse(raw)); } catch { return false; }
}

/**
 * The caller-level gate every Crew entry point passes (MCP tools via callTool,
 * A2A via the token's owner, the dashboard via routes/crew.js).
 *
 * - An agent identity (users.kind = 'agent') is refused on every channel. A
 *   crew agent's owner is the person who answers first contacts, blocks and
 *   (later) approvals; an identity that is itself an agent has nobody behind
 *   it to decide, and letting it own crew agents would let one agent register
 *   others and launder its permissions through them.
 * - A key limited to some apps (mcp_app_scope) is refused over 'mcp' and
 *   'a2a'. Crew is platform-wide and belongs to no app, so nothing in it is
 *   inside such a scope: the operator who limited the key to two apps did not
 *   mean "and also the whole platform's agent directory and inboxes". The
 *   dashboard ('dashboard') is a person's own browser session, which
 *   mcp_app_scope has never governed.
 */
export function assertCrewCaller(user, channel) {
  if (!user) fail(401, 'UNAUTHORIZED', 'Not authenticated.');
  if (user.kind === 'agent') {
    fail(403, 'FORBIDDEN', 'Forbidden: Crew agents belong to people. This is an agent identity, which cannot own or act as a crew agent; use the personal key of the person the agent works for.');
  }
  if ((channel === 'mcp' || channel === 'a2a') && hasExplicitAppScope(user)) {
    fail(403, 'FORBIDDEN', 'Forbidden: this key is limited to specific apps (MCP app scope), and Crew is platform-wide, so it is outside that scope. Use an unscoped personal key for Crew.');
  }
}

function audit(user, action, detail, actorKind) {
  try {
    logAudit(user.id, null, action, detail, actorKind);
  } catch (e) {
    log.warn(`[crew] audit write failed for ${action}: ${e.message}`);
    if (process.env.APPCRANE_AUDIT_REQUIRED === '1') throw e;
  }
}

/**
 * MCP audit rows record tool arguments. For Crew tools that would put message
 * bodies and titles into audit_log (redactAuditArgs only truncates), so they
 * are replaced by their lengths before mcpTools.auditMcpCall persists them.
 */
export function redactCrewArgs(toolName, args) {
  if (!String(toolName).startsWith('appcrane_crew_') || !args || typeof args !== 'object') return args;
  const out = { ...args };
  for (const k of ['title', 'message']) {
    if (typeof out[k] === 'string') out[k] = `[${out[k].length} chars]`;
  }
  if (out.artifact && typeof out.artifact === 'object') {
    out.artifact = { name_len: String(out.artifact.name ?? '').length, body_len: String(out.artifact.body ?? '').length };
  }
  return out;
}

// ── Agents ──────────────────────────────────────────────────────────────────

function agentByName(db, name) {
  return db.prepare('SELECT * FROM crew_agents WHERE name = ?').get(name);
}

/**
 * The agent `name`, provided the caller owns it. THE ownership check for every
 * call that acts as an agent. Platform admins get no exemption: seeing is not
 * acting.
 */
export function agentForCaller(db, user, rawName) {
  const name = normalizeAgentName(rawName);
  const agent = agentByName(db, name);
  if (!agent) fail(404, 'NOT_FOUND', `No agent named "${name}" is registered.`);
  if (agent.owner_user_id !== user.id) {
    fail(403, 'FORBIDDEN', `Forbidden: agent "${name}" belongs to another person. An agent acts only through its owner's own key.`);
  }
  return agent;
}

function agentView(db, a) {
  const card = parseCard(a.card_json);
  const owner = db.prepare('SELECT name, email FROM users WHERE id = ?').get(a.owner_user_id);
  return {
    name: a.name,
    kind: a.kind,
    owner: owner?.name || owner?.email || 'unknown',
    description: card.description || '',
    skills: Array.isArray(card.skills) ? card.skills : [],
    capabilities: card.capabilities || {},
    knows_about: a.knows_about || '',
    status: a.status,
    last_seen_at: a.last_seen_at,
    created_at: a.created_at,
  };
}

/**
 * Register (or re-register) an agent owned by the caller. Re-registering a
 * name you already own updates its card: a local agent re-registers at the
 * start of every session, and that must not fail. A name owned by someone else
 * is refused.
 *
 * `card_json` (hosted form only) is a pasted A2A Agent Card. Fetching a card
 * from a URL is deliberately NOT supported in phase 1: the server would make
 * an outbound request to an address chosen by any logged-in user (SSRF into
 * the host's network). Fields given explicitly win over the pasted card.
 */
export function registerAgent(user, input, { kind, actorKind }) {
  const db = getDb();
  let pasted = {};
  if (input.card_json != null && input.card_json !== '') {
    const raw = typeof input.card_json === 'string' ? input.card_json : JSON.stringify(input.card_json);
    assertBodySize('agent card', raw, CREW_LIMITS.CARD_MAX_BYTES);
    try { pasted = JSON.parse(raw); } catch { fail(400, 'VALIDATION', 'The agent card is not valid JSON.'); }
    if (!pasted || typeof pasted !== 'object' || Array.isArray(pasted)) fail(400, 'VALIDATION', 'The agent card must be a JSON object.');
  }
  const name = normalizeAgentName(input.name ?? pasted.name);
  const description = oneLine(input.description ?? pasted.description, 500);
  const skills = normalizeSkills(input.skills ?? pasted.skills);
  const capabilities = normalizeCapabilities(input.capabilities ?? pasted.capabilities);
  const knowsAbout = oneLine(input.knows_about, 500) || null;
  for (const [where, text] of [['description', description], ['knows_about', knowsAbout || ''], ['skills', JSON.stringify(skills)]]) {
    assertNoSecret(where, text);
  }
  const card = JSON.stringify({ name, description, skills, capabilities });

  const result = db.transaction(() => {
    const existing = agentByName(db, name);
    if (existing && existing.owner_user_id !== user.id) {
      fail(409, 'NAME_TAKEN', `The agent name "${name}" is already registered by another person. Names are unique across the platform; pick another.`);
    }
    if (existing) {
      db.prepare(`UPDATE crew_agents SET card_json = ?, knows_about = ?, kind = ?, last_seen_at = datetime('now') WHERE id = ?`)
        .run(card, knowsAbout, kind, existing.id);
      return { id: existing.id, created: false };
    }
    const n = db.prepare('SELECT COUNT(*) AS n FROM crew_agents WHERE owner_user_id = ?').get(user.id).n;
    if (n >= CREW_LIMITS.AGENTS_PER_OWNER) {
      fail(429, 'RATE_LIMITED', `You already have ${n} agents registered (the limit is ${CREW_LIMITS.AGENTS_PER_OWNER}). Remove one you no longer use.`);
    }
    const id = db.prepare(`INSERT INTO crew_agents (name, owner_user_id, kind, card_json, knows_about, last_seen_at)
                           VALUES (?, ?, ?, ?, ?, datetime('now'))`).run(name, user.id, kind, card, knowsAbout).lastInsertRowid;
    restoreDecisions(db, user.id, name, id);
    return { id, created: true };
  })();

  audit(user, result.created ? 'crew.agent.register' : 'crew.agent.update',
    { agent_id: result.id, agent: name, kind, skills: skills.length }, actorKind);
  return { ...agentView(db, db.prepare('SELECT * FROM crew_agents WHERE id = ?').get(result.id)), created: result.created };
}

/**
 * SECURITY FIX (review of v2.105.0). Before an agent row is deleted, every
 * block and refusal OTHER people placed on it is written down by (owner, name),
 * because both are keyed by agent id and cascade away with the row — which let
 * a blocked person remove the agent, register the same name, and start over
 * with a fresh first contact and a fresh e-mail.
 */
function tombstoneDecisions(db, agent) {
  const ins = db.prepare(`INSERT OR IGNORE INTO crew_decision_tombstones (decider_user_id, agent_owner_id, agent_name, kind)
                          VALUES (?, ?, ?, ?)`);
  for (const b of db.prepare('SELECT owner_user_id FROM crew_blocks WHERE blocked_agent_id = ?').all(agent.id)) {
    ins.run(b.owner_user_id, agent.owner_user_id, agent.name, 'block');
  }
  for (const c of db.prepare("SELECT to_owner_id FROM crew_connections WHERE from_agent_id = ? AND state = 'refused'").all(agent.id)) {
    ins.run(c.to_owner_id, agent.owner_user_id, agent.name, 'refused');
  }
}

/**
 * The other half: the same owner registering the same name gets its blocks and
 * refusals back, as live rows, in the transaction that creates it. A refusal
 * comes back with notified_at set, so it can never produce an e-mail. A
 * DIFFERENT owner who later takes the freed name inherits nothing — the
 * decision was about that person's agent.
 */
function restoreDecisions(db, ownerId, name, agentId) {
  const rows = db.prepare('SELECT * FROM crew_decision_tombstones WHERE agent_owner_id = ? AND agent_name = ?').all(ownerId, name);
  for (const t of rows) {
    if (t.kind === 'block') {
      db.prepare('INSERT OR IGNORE INTO crew_blocks (owner_user_id, blocked_agent_id) VALUES (?, ?)').run(t.decider_user_id, agentId);
    } else {
      db.prepare(`INSERT OR IGNORE INTO crew_connections (from_agent_id, from_owner_id, to_owner_id, state, notified_at, decided_at)
                  VALUES (?, ?, ?, 'refused', datetime('now'), datetime('now'))`).run(agentId, ownerId, t.decider_user_id);
    }
  }
  if (rows.length) db.prepare('DELETE FROM crew_decision_tombstones WHERE agent_owner_id = ? AND agent_name = ?').run(ownerId, name);
}

/** Remove one of the caller's own agents. Its tasks go with it (they are 30-day history). */
export function removeAgent(user, rawName, { actorKind }) {
  const db = getDb();
  const agent = agentForCaller(db, user, rawName);
  const taskIds = db.prepare('SELECT id FROM crew_tasks WHERE from_agent_id = ? OR to_agent_id = ?').all(agent.id, agent.id).map((r) => r.id);
  db.transaction(() => {
    tombstoneDecisions(db, agent);
    db.prepare('DELETE FROM crew_agents WHERE id = ?').run(agent.id);
  })();
  audit(user, 'crew.agent.remove', { agent_id: agent.id, agent: agent.name }, actorKind);
  // Open SSE streams on those tasks close on 'deleted' instead of idling.
  announce(taskIds, 'deleted');
  return { removed: agent.name };
}

/**
 * The roster: every registered agent, with its owner. Status and "doing now"
 * come from tasks that were actually accepted into an inbox (held and
 * rejected tasks are never shown to third parties — a held title is a request
 * the receiving person has not agreed to see broadcast).
 */
export function roster(user, { skill } = {}) {
  const db = getDb();
  const wantSkill = skill ? String(skill).trim().toLowerCase() : '';
  const agents = db.prepare(`
    SELECT a.*, u.name AS owner_name, u.email AS owner_email
    FROM crew_agents a JOIN users u ON u.id = a.owner_user_id
    ORDER BY a.name`).all();
  const myBlocks = new Set(db.prepare('SELECT blocked_agent_id FROM crew_blocks WHERE owner_user_id = ?').all(user.id).map((r) => r.blocked_agent_id));
  const blockCounts = isAdmin(user)
    ? new Map(db.prepare('SELECT blocked_agent_id AS id, COUNT(*) AS n FROM crew_blocks GROUP BY blocked_agent_id').all().map((r) => [r.id, r.n]))
    : null;
  const current = db.prepare(`
    SELECT title, state, updated_at FROM crew_tasks
    WHERE to_agent_id = ? AND held = 0 AND state IN ('working', 'input_required')
    ORDER BY updated_at DESC LIMIT 1`);
  const last = db.prepare(`
    SELECT title, state, updated_at FROM crew_tasks
    WHERE to_agent_id = ? AND held = 0 AND state IN ('completed', 'failed')
    ORDER BY updated_at DESC LIMIT 1`);

  const rows = [];
  for (const a of agents) {
    const card = parseCard(a.card_json);
    const skills = Array.isArray(card.skills) ? card.skills : [];
    if (wantSkill && !skills.some((s) => s.id === wantSkill || s.id.includes(wantSkill))) continue;
    const now = current.get(a.id);
    const prev = now ? null : last.get(a.id);
    let status = now ? (now.state === 'input_required' ? 'waiting_for_input' : 'working') : 'idle';
    if (myBlocks.has(a.id)) status = 'blocked_by_you';
    const row = {
      name: a.name,
      owner: a.owner_name || a.owner_email || 'unknown',
      is_mine: a.owner_user_id === user.id,
      runs_as: a.kind,
      description: card.description || '',
      skills: skills.map((s) => s.id),
      knows_about: a.knows_about || '',
      status,
      doing_now: now ? now.title : null,
      last_task: prev ? { title: prev.title, state: prev.state, at: prev.updated_at } : null,
      last_seen_at: a.last_seen_at,
    };
    if (blockCounts) row.blocked_by_count = blockCounts.get(a.id) || 0;
    rows.push(row);
  }
  return rows;
}

/**
 * "Is anyone already on this?" — matches the words of `query` against the
 * titles of OPEN, accepted tasks and against agents' knows_about/description.
 * Plain substring matching in JS on purpose: no user text ever becomes SQL.
 */
export function whoIsOn(_user, query) {
  const db = getDb();
  const words = [...new Set(String(query ?? '').toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3))].slice(0, 12);
  if (!words.length) fail(400, 'VALIDATION', 'Give a query of at least one word of 3+ letters, for example "stock count migration".');
  const score = (text) => {
    const t = String(text || '').toLowerCase();
    return words.reduce((n, w) => n + (t.includes(w) ? 1 : 0), 0);
  };
  const tasks = db.prepare(`
    SELECT t.id, t.title, t.state, t.updated_at, ta.name AS agent, u.name AS owner, fa.name AS requested_by
    FROM crew_tasks t
    JOIN crew_agents ta ON ta.id = t.to_agent_id
    JOIN crew_agents fa ON fa.id = t.from_agent_id
    JOIN users u ON u.id = ta.owner_user_id
    WHERE t.held = 0 AND t.state IN ('submitted', 'working', 'input_required')
    ORDER BY t.updated_at DESC LIMIT 500`).all();
  const working_on = tasks
    .map((t) => ({ score: score(t.title), agent: t.agent, owner: t.owner, requested_by: t.requested_by, task_title: t.title, state: t.state, updated_at: t.updated_at }))
    .filter((t) => t.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 20);
  const agents = db.prepare(`
    SELECT a.name, a.knows_about, a.card_json, u.name AS owner FROM crew_agents a JOIN users u ON u.id = a.owner_user_id`).all();
  const knows_about = agents
    .map((a) => {
      const card = parseCard(a.card_json);
      return { score: score(`${a.knows_about || ''} ${card.description || ''}`), agent: a.name, owner: a.owner, knows_about: a.knows_about || '', description: card.description || '' };
    })
    .filter((a) => a.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 20);
  return { query: words.join(' '), working_on, knows_about };
}

// ── Flood control ───────────────────────────────────────────────────────────

function assertTaskBudget(db, agentId) {
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM crew_tasks WHERE from_agent_id = ? AND created_at >= datetime('now', '-1 hour')").get(agentId);
  if (n >= CREW_LIMITS.TASKS_PER_HOUR) {
    fail(429, 'RATE_LIMITED', `This agent has sent ${n} tasks in the last hour (the limit is ${CREW_LIMITS.TASKS_PER_HOUR}). Wait, or combine the work into fewer tasks.`);
  }
}

function assertMessageBudget(db, agentId) {
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM crew_messages WHERE from_agent_id = ? AND created_at >= datetime('now', '-1 hour')").get(agentId);
  if (n >= CREW_LIMITS.MESSAGES_PER_HOUR) {
    fail(429, 'RATE_LIMITED', `This agent has sent ${n} messages in the last hour (the limit is ${CREW_LIMITS.MESSAGES_PER_HOUR}). Wait before sending more.`);
  }
}

function assertPendingFirstContactBudget(db, ownerId) {
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM crew_connections WHERE from_owner_id = ? AND state = 'pending'").get(ownerId);
  if (n >= CREW_LIMITS.PENDING_FIRST_CONTACTS) {
    fail(429, 'RATE_LIMITED', `Your agents have ${n} first-contact requests still waiting for other people to decide (the limit is ${CREW_LIMITS.PENDING_FIRST_CONTACTS}). Wait for answers before contacting more people.`);
  }
}

// ── Sending ─────────────────────────────────────────────────────────────────

/**
 * Decide what happens to a new task from `from` to `to`. Returns one of:
 *   { verdict: 'deliver' }                       same owner, or an allowed connection
 *   { verdict: 'reject' }                        blocked, or a refused connection (silent)
 *   { verdict: 'hold', connection, isNew }       first contact pending a decision
 * Phase 3's standing rules slot in after the block check.
 */
function gateFor(db, from, to) {
  if (from.owner_user_id === to.owner_user_id) return { verdict: 'deliver' };
  const blocked = db.prepare('SELECT 1 FROM crew_blocks WHERE owner_user_id = ? AND blocked_agent_id = ?').get(to.owner_user_id, from.id);
  if (blocked) return { verdict: 'reject', reason: 'blocked' };
  const conn = db.prepare('SELECT * FROM crew_connections WHERE from_agent_id = ? AND to_owner_id = ?').get(from.id, to.owner_user_id);
  if (conn?.state === 'allowed') return { verdict: 'deliver' };
  if (conn?.state === 'refused') return { verdict: 'reject', reason: 'refused' };
  if (conn) return { verdict: 'hold', connection: conn, isNew: false };
  return { verdict: 'hold', connection: null, isNew: true };
}

function dashboardLink(path) {
  const host = process.env.CRANE_DOMAIN;
  return host ? `https://${host}${path}` : `AppCrane → ${path}`;
}

export const FIRST_CONTACT_EMAIL_WINDOW = '-1 day';

/**
 * SECURITY FIX (review of v2.105.0): has the sending PERSON already caused a
 * first-contact e-mail to this receiving person in the last 24 hours? Counted
 * in crew_first_contact_emails, which does not cascade from agents, so
 * removing and re-registering agents cannot reset it.
 */
function firstContactEmailedRecently(db, fromOwnerId, toOwnerId) {
  return !!db.prepare("SELECT 1 FROM crew_first_contact_emails WHERE from_owner_id = ? AND to_owner_id = ? AND sent_at >= datetime('now', ?)")
    .get(fromOwnerId, toOwnerId, FIRST_CONTACT_EMAIL_WINDOW);
}

function firstContactEmail(db, conn, from, to, title) {
  const receiver = db.prepare('SELECT name, email FROM users WHERE id = ?').get(to.owner_user_id);
  const sender = db.prepare('SELECT name, email FROM users WHERE id = ?').get(from.owner_user_id);
  if (!receiver?.email) return false;
  const senderName = oneLine(sender?.name || sender?.email || 'Another person', 80);
  const link = dashboardLink(`/crew#log`);
  const text = [
    `${from.name}, owned by ${senderName}, asked to send tasks to your agent ${to.name}.`,
    `Agents of different people need your approval before they can work together.`,
    ``,
    `First request: "${oneLine(title, 140)}"`,
    ``,
    `Decide in AppCrane (Allow, Allow once, Refuse or Block ${from.name}):`,
    link,
    ``,
    `This is the only e-mail Crew sends about ${from.name}: when a new connection starts.`,
    `Everything after that appears in AppCrane → Crew.`,
  ].join('\n');
  try {
    enqueueEmail({
      to: receiver.email,
      subject: `[AppCrane] ${senderName}'s agent wants to work with your agent`,
      text,
      source: 'crew-first-contact',
      // Belt to notified_at's braces. emailQueue dedupes only per app, so
      // notified_at (set once, in the transaction that creates the
      // connection) is what actually guarantees one e-mail.
      idempotencyKey: `crew-first-contact:${conn.from_agent_id}:${conn.to_owner_id}`,
    });
    return true;
  } catch (e) {
    // A receiver with no deliverable address (an agent identity, a deactivated
    // user) still sees the request in the dashboard. Never fail the send.
    log.warn(`[crew] first-contact e-mail not queued for connection ${conn.id}: ${e.message}`);
    return false;
  }
}

/**
 * Send a task from one of the caller's agents to any registered agent.
 * The sender always gets a task id and a state; a refused or blocked sender
 * gets 'rejected' and nothing else.
 */
export function sendTask(user, { as_agent, to_agent, title, message, context_id, message_id }, { actorKind }) {
  const db = getDb();
  const from = agentForCaller(db, user, as_agent);
  const toName = normalizeAgentName(to_agent);
  const to = agentByName(db, toName);
  if (!to) fail(404, 'NOT_FOUND', `No agent named "${toName}" is registered. appcrane_crew_roster lists them.`);
  if (to.id === from.id) fail(400, 'VALIDATION', 'An agent cannot send a task to itself.');
  const cleanTitle = oneLine(title, CREW_LIMITS.TITLE_MAX);
  if (!cleanTitle) fail(400, 'VALIDATION', 'title is required: one line saying what you want done.');
  const body = String(message ?? '');
  if (!body.trim()) fail(400, 'VALIDATION', 'message is required: the details the other agent needs.');
  assertBodySize('message', body, CREW_LIMITS.BODY_MAX_BYTES);
  assertNoSecret('title', cleanTitle);
  assertNoSecret('message', body);

  const out = db.transaction(() => {
    assertTaskBudget(db, from.id);
    assertMessageBudget(db, from.id);
    const gate = gateFor(db, from, to);
    const id = newTaskId();
    touchAgent(db, from.id);

    if (gate.verdict === 'reject') {
      // No message stored: nobody will ever read it, and keeping a blocked
      // sender's text for 30 days serves no one.
      db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state) VALUES (?, ?, ?, ?, 'rejected')").run(id, from.id, to.id, cleanTitle);
      return { id, state: 'rejected', audit: { reason: gate.reason } };
    }

    let connection = gate.connection;
    let emailed = false;
    if (gate.verdict === 'hold' && gate.isNew) {
      assertPendingFirstContactBudget(db, from.owner_user_id);
      const connId = db.prepare(`INSERT INTO crew_connections (from_agent_id, from_owner_id, to_owner_id, state)
                                 VALUES (?, ?, ?, 'pending')`).run(from.id, from.owner_user_id, to.owner_user_id).lastInsertRowid;
      connection = db.prepare('SELECT * FROM crew_connections WHERE id = ?').get(connId);
    }
    const held = gate.verdict === 'hold' ? 1 : 0;
    // context_id: the A2A caller's contextId when it gave one (validated in
    // crewA2a.js), else the task's own id — every task is its own context.
    db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state, held, context_id) VALUES (?, ?, ?, ?, 'submitted', ?, ?)").run(id, from.id, to.id, cleanTitle, held, context_id || id);
    db.prepare("INSERT INTO crew_messages (task_id, from_agent_id, body, message_id, state_after) VALUES (?, ?, ?, ?, 'submitted')").run(id, from.id, body, message_id || null);

    // At most one e-mail per connection: only when notified_at is still NULL,
    // and set in this same transaction. notified_at is set even when the
    // per-person cap below suppresses the e-mail: it means "this connection
    // has had its chance to e-mail", and must not e-mail on a later task.
    if (held && connection && !connection.notified_at) {
      if (!firstContactEmailedRecently(db, from.owner_user_id, to.owner_user_id)) {
        emailed = firstContactEmail(db, connection, from, to, cleanTitle);
        if (emailed) {
          db.prepare('INSERT INTO crew_first_contact_emails (from_owner_id, to_owner_id) VALUES (?, ?)').run(from.owner_user_id, to.owner_user_id);
        }
      }
      db.prepare("UPDATE crew_connections SET notified_at = datetime('now') WHERE id = ? AND notified_at IS NULL").run(connection.id);
    }
    return { id, state: 'submitted', held: !!held, connection_id: connection?.id ?? null, emailed, newConnection: !!gate.isNew };
  })();

  audit(user, out.state === 'rejected' ? 'crew.task.rejected' : 'crew.task.send', {
    task_id: out.id, from_agent_id: from.id, to_agent_id: to.id, title_len: cleanTitle.length,
    message_len: body.length, held: !!out.held, ...(out.audit || {}),
  }, actorKind);
  if (out.newConnection) {
    audit(user, 'crew.first_contact', { connection_id: out.connection_id, from_agent_id: from.id, to_owner_id: to.owner_user_id, task_id: out.id, emailed: out.emailed }, actorKind);
  }
  announce(out.id, 'created');

  const res = { task_id: out.id, state: out.state, to_agent: to.name };
  if (out.held) {
    res.note = `${to.name} belongs to another person who has not yet accepted tasks from ${from.name}. The task is held until they decide; check its state later with appcrane_crew_inbox (sent tasks).`;
  }
  return res;
}

// ── Inbox and replies ───────────────────────────────────────────────────────

function messagesFor(db, taskId) {
  return db.prepare(`
    SELECT m.id, a.name AS from_agent, m.body, m.artifact_name, m.artifact_body, m.created_at
    FROM crew_messages m JOIN crew_agents a ON a.id = m.from_agent_id
    WHERE m.task_id = ? ORDER BY m.id DESC LIMIT 50`).all(taskId).reverse()
    .map((m) => {
      const out = { from_agent: m.from_agent, body: m.body, created_at: m.created_at };
      if (m.artifact_name) out.artifact = { name: m.artifact_name, body: m.artifact_body };
      return out;
    });
}

/**
 * Open tasks addressed to the caller's agent (with their messages), plus the
 * tasks it sent recently so it can collect answers. Held tasks are invisible
 * to the receiver until the receiving person decides.
 */
export function inbox(user, { as_agent }, { touch = true } = {}) {
  const db = getDb();
  const agent = agentForCaller(db, user, as_agent);
  // SECURITY FIX (review of v2.105.0): appcrane_crew_inbox is marked readOnly,
  // so a read-only MCP key may call it — and it wrote last_seen_at. The MCP
  // handler passes touch:false for a read-only key, keeping that promise.
  if (touch) touchAgent(db, agent.id);
  const received = db.prepare(`
    SELECT t.id, t.title, t.state, t.created_at, t.updated_at, fa.name AS from_agent, u.name AS from_owner
    FROM crew_tasks t JOIN crew_agents fa ON fa.id = t.from_agent_id JOIN users u ON u.id = fa.owner_user_id
    WHERE t.to_agent_id = ? AND t.held = 0 AND t.state IN ('submitted', 'working', 'input_required')
    ORDER BY t.created_at ASC LIMIT 50`).all(agent.id)
    .map((t) => ({ task_id: t.id, title: t.title, state: t.state, from_agent: t.from_agent, from_owner: t.from_owner, created_at: t.created_at, updated_at: t.updated_at, messages: messagesFor(db, t.id) }));
  const sent = db.prepare(`
    SELECT t.id, t.title, t.state, t.held, t.created_at, t.updated_at, ta.name AS to_agent, u.name AS to_owner
    FROM crew_tasks t JOIN crew_agents ta ON ta.id = t.to_agent_id JOIN users u ON u.id = ta.owner_user_id
    WHERE t.from_agent_id = ? ORDER BY t.updated_at DESC LIMIT 20`).all(agent.id)
    .map((t) => ({
      task_id: t.id, title: t.title, state: t.state, to_agent: t.to_agent, to_owner: t.to_owner,
      waiting_for_approval: !!t.held && t.state === 'submitted', created_at: t.created_at, updated_at: t.updated_at,
      messages: t.state === 'rejected' ? [] : messagesFor(db, t.id),
    }));
  return { agent: agent.name, received, sent };
}

// ── Task reads for the A2A door (phase 2) ──────────────────────────────────

/**
 * THE rule for whether one agent may see one task, shared by reply() and every
 * A2A read. The sender always sees its task (including 'rejected', which is the
 * only answer a blocked sender gets). The receiver sees it only once it has
 * been released (held = 0) and never when it was rejected: a held task is a
 * request its owner has not agreed to receive, and a rejection is silent.
 */
export function taskVisibleTo(task, agentId) {
  if (!task) return false;
  if (task.from_agent_id === agentId) return true;
  return task.to_agent_id === agentId && task.held === 0 && task.state !== 'rejected';
}

const TASK_SELECT = `
  SELECT t.*, fa.name AS from_agent, ta.name AS to_agent
  FROM crew_tasks t JOIN crew_agents fa ON fa.id = t.from_agent_id JOIN crew_agents ta ON ta.id = t.to_agent_id`;

/** One task as `agentId` may see it, or null — the same null for "no such task" and "not yours". */
export function taskFor(agentId, taskId) {
  if (typeof taskId !== 'string' || !taskId || taskId.length > 64) return null;
  const task = getDb().prepare(`${TASK_SELECT} WHERE t.id = ?`).get(taskId);
  return taskVisibleTo(task, agentId) ? task : null;
}

/** Every message of a task, oldest first, with what the A2A view needs. Capped like messagesFor(). */
export function taskMessages(taskId, limit = 200) {
  return getDb().prepare(`
    SELECT * FROM (
      SELECT m.id, m.from_agent_id, m.body, m.artifact_name, m.artifact_body, m.message_id, m.state_after, m.created_at
      FROM crew_messages m WHERE m.task_id = ? ORDER BY m.id DESC LIMIT ?
    ) ORDER BY id ASC`).all(taskId, limit);
}

/**
 * Tasks visible to `agentId`, most recently updated first (A2A ListTasks,
 * spec §3.1.4: "Tasks MUST be sorted by last update time in descending
 * order" with cursor pagination). The visibility predicate is taskVisibleTo()
 * written as SQL; the cursor is the (updated_at, id) of the last row, so a
 * page boundary is stable while rows are added.
 */
export function listTasksFor(agentId, { contextId, state, updatedAfter, pageSize = 50, cursor } = {}) {
  const where = ['(t.from_agent_id = ? OR (t.to_agent_id = ? AND t.held = 0 AND t.state <> \'rejected\'))'];
  const args = [agentId, agentId];
  if (contextId) { where.push('t.context_id = ?'); args.push(contextId); }
  if (state) { where.push('t.state = ?'); args.push(state); }
  if (updatedAfter) { where.push('t.updated_at > ?'); args.push(updatedAfter); }
  const db = getDb();
  const total = db.prepare(`SELECT COUNT(*) AS n FROM crew_tasks t WHERE ${where.join(' AND ')}`).get(...args).n;
  if (cursor) { where.push('(t.updated_at < ? OR (t.updated_at = ? AND t.id < ?))'); args.push(cursor.u, cursor.u, cursor.i); }
  const rows = db.prepare(`${TASK_SELECT} WHERE ${where.join(' AND ')} ORDER BY t.updated_at DESC, t.id DESC LIMIT ?`).all(...args, pageSize + 1);
  const more = rows.length > pageSize;
  const page = more ? rows.slice(0, pageSize) : rows;
  const last = page.at(-1);
  return { tasks: page, total, next: more && last ? { u: last.updated_at, i: last.id } : null };
}

/** A crew agent by id with its owner's users row, for the A2A token door. */
export function agentWithOwner(agentId) {
  const db = getDb();
  const agent = db.prepare('SELECT * FROM crew_agents WHERE id = ?').get(agentId);
  if (!agent) return null;
  const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(agent.owner_user_id);
  return owner ? { agent, owner } : null;
}

export function touchAgentSeen(agentId) {
  touchAgent(getDb(), agentId);
}

/**
 * Reply on a task, optionally moving its state. The receiving agent may set
 * working | input_required | completed | failed; the sending agent may add a
 * message (e.g. answer input_required) or cancel. A closed task takes nothing.
 */
export function reply(user, { as_agent, task_id, message, state, artifact, message_id }, { actorKind }) {
  const db = getDb();
  const agent = agentForCaller(db, user, as_agent);
  const task = typeof task_id === 'string' ? db.prepare('SELECT * FROM crew_tasks WHERE id = ?').get(task_id) : null;
  const isSender = !!task && task.from_agent_id === agent.id;
  const isReceiver = !isSender && taskVisibleTo(task, agent.id);
  // Same answer for "no such task" and "not yours": task ids must not be probeable.
  if (!isReceiver && !isSender) fail(404, 'NOT_FOUND', `No task ${oneLine(task_id, 40)} for agent ${agent.name}.`);
  if (TERMINAL_STATES.includes(task.state)) fail(409, 'TASK_CLOSED', `Task is already ${task.state}; start a new task instead.`);
  // SECURITY FIX (review of v2.106.0): a held task is a request the receiving
  // person has not agreed to receive, and "Allow once" releases it as it stood
  // when they decided. So while it is held the sender may only withdraw it: a
  // message or artifact added now would ride out on a decision made without it.
  if (isSender && task.held && (String(state ?? '') !== 'canceled' || String(message ?? '').trim() || artifact != null)) {
    fail(409, 'HELD', 'This task is still waiting for the receiving person\'s approval. Until they decide, the only change you can make is to cancel it (state "canceled", no message).');
  }

  let nextState = null;
  if (state != null && state !== '') {
    nextState = String(state);
    if (isReceiver && !RECEIVER_STATES.includes(nextState)) fail(400, 'VALIDATION', `state must be one of ${RECEIVER_STATES.join(', ')}.`);
    if (!isReceiver && nextState !== 'canceled') fail(403, 'FORBIDDEN', 'Only the receiving agent sets a task\'s progress; the sending agent may only cancel it.');
    if (task.held && nextState !== 'canceled') fail(409, 'HELD', 'This task is still waiting for the receiving person\'s approval.');
  }
  const body = String(message ?? '');
  let art = null;
  if (artifact != null) {
    if (typeof artifact !== 'object' || Array.isArray(artifact)) fail(400, 'VALIDATION', 'artifact must be {name, body}.');
    const name = oneLine(artifact.name, CREW_LIMITS.ARTIFACT_NAME_MAX);
    const abody = String(artifact.body ?? '');
    if (!name || !abody) fail(400, 'VALIDATION', 'artifact needs both a name and a body.');
    assertBodySize('artifact', abody, CREW_LIMITS.ARTIFACT_MAX_BYTES);
    assertNoSecret('artifact', `${name}\n${abody}`);
    art = { name, body: abody };
  }
  if (!body.trim() && !nextState && !art) fail(400, 'VALIDATION', 'Send a message, an artifact or a state change.');
  assertBodySize('message', body, CREW_LIMITS.BODY_MAX_BYTES);
  assertNoSecret('message', body);

  db.transaction(() => {
    if (body.trim() || art) {
      assertMessageBudget(db, agent.id);
      db.prepare('INSERT INTO crew_messages (task_id, from_agent_id, body, artifact_name, artifact_body, message_id, state_after) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(task.id, agent.id, body, art?.name ?? null, art?.body ?? null, message_id || null, nextState || task.state);
    }
    // held is left as it is. SECURITY FIX (review of v2.106.0): cancelling a
    // held task used to clear held, and taskVisibleTo() then showed the
    // never-approved title and body to the receiver's agents (A2A GetTask /
    // ListTasks): a sender could get any text past first contact by sending
    // and cancelling. held = 1 means "never released", whatever the state.
    db.prepare(`UPDATE crew_tasks SET state = COALESCE(?, state), updated_at = datetime('now') WHERE id = ?`)
      .run(nextState, task.id);
    touchAgent(db, agent.id);
  })();

  audit(user, 'crew.task.reply', {
    task_id: task.id, agent_id: agent.id, role: isReceiver ? 'receiver' : 'sender',
    state_from: task.state, state_to: nextState || task.state, message_len: body.length, artifact: !!art,
  }, actorKind);
  announce(task.id, art ? 'artifact' : nextState ? 'status' : 'message');
  return { task_id: task.id, state: nextState || task.state };
}

// ── The dashboard side: log, decisions, blocks ─────────────────────────────

/**
 * Tasks involving the caller's agents, newest activity first. A rejected task
 * is shown only to its SENDER's owner: rejections are silent to the receiver.
 * Bodies are not sent whole — the dashboard shows a preview.
 */
export function crewLog(user, { limit = 100 } = {}) {
  const db = getDb();
  const n = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 200);
  const rows = db.prepare(`
    SELECT t.*, fa.name AS from_agent, fa.owner_user_id AS from_owner_id, fu.name AS from_owner,
           ta.name AS to_agent, ta.owner_user_id AS to_owner_id, tu.name AS to_owner,
           (SELECT COUNT(*) FROM crew_messages m WHERE m.task_id = t.id) AS message_count,
           (SELECT body FROM crew_messages m WHERE m.task_id = t.id ORDER BY m.id ASC LIMIT 1) AS first_body,
           (SELECT artifact_name FROM crew_messages m WHERE m.task_id = t.id AND artifact_name IS NOT NULL ORDER BY m.id DESC LIMIT 1) AS artifact_name
    FROM crew_tasks t
    JOIN crew_agents fa ON fa.id = t.from_agent_id JOIN users fu ON fu.id = fa.owner_user_id
    JOIN crew_agents ta ON ta.id = t.to_agent_id   JOIN users tu ON tu.id = ta.owner_user_id
    WHERE fa.owner_user_id = ? OR (ta.owner_user_id = ? AND t.state <> 'rejected')
    ORDER BY t.updated_at DESC, t.created_at DESC LIMIT ?`).all(user.id, user.id, n);
  const connStmt = db.prepare('SELECT id, state FROM crew_connections WHERE from_agent_id = ? AND to_owner_id = ?');
  return rows.map((t) => {
    const mineSent = t.from_owner_id === user.id;
    const mineReceived = t.to_owner_id === user.id;
    const entry = {
      task_id: t.id, title: t.title, state: t.state,
      direction: mineSent && mineReceived ? 'own' : mineSent ? 'sent' : 'received',
      from_agent: t.from_agent, from_owner: t.from_owner, to_agent: t.to_agent, to_owner: t.to_owner,
      preview: t.first_body ? oneLine(t.first_body, 280) : null,
      message_count: t.message_count, artifact_name: t.artifact_name || null,
      created_at: t.created_at, updated_at: t.updated_at,
      awaiting_your_decision: false,
    };
    // A held task the sender cancelled stays held (never released) but waits
    // for nobody: offering a decision on it would release a withdrawn request.
    if (t.held && t.state === 'submitted') {
      entry.waiting_for_approval = true;
      if (mineReceived && !mineSent) {
        const c = connStmt.get(t.from_agent_id, user.id);
        if (c) { entry.connection_id = c.id; entry.awaiting_your_decision = true; }
      }
    }
    return entry;
  });
}

const DECISIONS = ['allow', 'allow_once', 'refuse', 'block'];

/**
 * SECURITY FIX (review of v2.106.0): "a block wins over an allow". Block and
 * Refuse used to reject only HELD tasks, so a sender that had been allowed
 * kept every task it already had open with this person and went on writing
 * into them through reply() (up to 300 messages an hour) after being blocked.
 * Now every OPEN task from that agent to the person's agents is rejected too:
 * the sender sees 'rejected' (no reason, as for any block) and reply() refuses
 * a closed task. Finished tasks are history and are left alone.
 */
const OPEN_FROM_SENDER = `state IN ('submitted', 'working', 'input_required')`;

/**
 * The receiving person's decision on a first contact. Only that person may
 * decide — not the sender, not a platform admin (an admin deciding would be
 * acting for someone else).
 */
export function decideConnection(user, connectionId, decision, { task_id } = {}) {
  const db = getDb();
  if (!DECISIONS.includes(decision)) fail(400, 'VALIDATION', `decision must be one of ${DECISIONS.join(', ')}.`);
  const id = parseInt(connectionId, 10);
  const conn = Number.isFinite(id) ? db.prepare('SELECT * FROM crew_connections WHERE id = ?').get(id) : null;
  if (!conn || conn.to_owner_id !== user.id) fail(404, 'NOT_FOUND', 'No such first-contact request for you.');
  const myAgentIds = `SELECT id FROM crew_agents WHERE owner_user_id = ?`;
  // Only a task still waiting (held AND submitted) can be released: a held
  // task its sender cancelled was withdrawn, and releasing it would show the
  // receiver's agents a request nobody now stands behind.
  const WAITING = `held = 1 AND state = 'submitted'`;

  const affectedIds = decision.startsWith('allow')
    ? db.prepare(`SELECT id FROM crew_tasks WHERE ${WAITING} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds})`).all(conn.from_agent_id, user.id).map((r) => r.id)
    : db.prepare(`SELECT id FROM crew_tasks WHERE ${OPEN_FROM_SENDER} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds})`).all(conn.from_agent_id, user.id).map((r) => r.id);
  const result = db.transaction(() => {
    if (decision === 'allow') {
      db.prepare("UPDATE crew_connections SET state = 'allowed', decided_at = datetime('now') WHERE id = ?").run(conn.id);
      const r = db.prepare(`UPDATE crew_tasks SET held = 0, updated_at = datetime('now')
                            WHERE ${WAITING} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds})`).run(conn.from_agent_id, user.id);
      return { state: 'allowed', released: r.changes };
    }
    if (decision === 'allow_once') {
      if (conn.state !== 'pending') fail(409, 'NOT_PENDING', `This connection is ${conn.state}; "allow once" applies to a pending request.`);
      const task = task_id
        ? db.prepare(`SELECT id FROM crew_tasks WHERE id = ? AND ${WAITING} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds})`).get(String(task_id), conn.from_agent_id, user.id)
        : db.prepare(`SELECT id FROM crew_tasks WHERE ${WAITING} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds}) ORDER BY created_at ASC LIMIT 1`).get(conn.from_agent_id, user.id);
      if (!task) fail(404, 'NOT_FOUND', 'No held task to allow on this request.');
      db.prepare("UPDATE crew_tasks SET held = 0, updated_at = datetime('now') WHERE id = ?").run(task.id);
      return { state: 'pending', released: 1, task_id: task.id };
    }
    // refuse and block both reject, silently, everything of the sender's that
    // is still open with this person — held or already released (see
    // OPEN_FROM_SENDER).
    db.prepare("UPDATE crew_connections SET state = 'refused', decided_at = datetime('now') WHERE id = ?").run(conn.id);
    const r = db.prepare(`UPDATE crew_tasks SET held = 0, state = 'rejected', updated_at = datetime('now')
                          WHERE ${OPEN_FROM_SENDER} AND from_agent_id = ? AND to_agent_id IN (${myAgentIds})`).run(conn.from_agent_id, user.id);
    if (decision === 'block') {
      db.prepare('INSERT OR IGNORE INTO crew_blocks (owner_user_id, blocked_agent_id) VALUES (?, ?)').run(user.id, conn.from_agent_id);
    }
    return { state: 'refused', rejected: r.changes, blocked: decision === 'block' };
  })();

  audit(user, `crew.connection.${decision}`, { connection_id: conn.id, from_agent_id: conn.from_agent_id, ...result }, 'human');
  announce(decision === 'allow_once' ? result.task_id : affectedIds, decision.startsWith('allow') ? 'released' : 'status');
  return { connection_id: conn.id, decision, ...result };
}

/** Block an agent directly (from the roster). Rejects anything it has waiting on you. */
export function blockAgent(user, rawName) {
  const db = getDb();
  const name = normalizeAgentName(rawName);
  const agent = agentByName(db, name);
  if (!agent) fail(404, 'NOT_FOUND', `No agent named "${name}" is registered.`);
  if (agent.owner_user_id === user.id) fail(400, 'VALIDATION', 'You cannot block your own agent; remove it instead.');
  const openIds = db.prepare(`SELECT id FROM crew_tasks WHERE ${OPEN_FROM_SENDER} AND from_agent_id = ? AND to_agent_id IN (SELECT id FROM crew_agents WHERE owner_user_id = ?)`).all(agent.id, user.id).map((r) => r.id);
  const rejected = db.transaction(() => {
    db.prepare('INSERT OR IGNORE INTO crew_blocks (owner_user_id, blocked_agent_id) VALUES (?, ?)').run(user.id, agent.id);
    return db.prepare(`UPDATE crew_tasks SET held = 0, state = 'rejected', updated_at = datetime('now')
                       WHERE ${OPEN_FROM_SENDER} AND from_agent_id = ? AND to_agent_id IN (SELECT id FROM crew_agents WHERE owner_user_id = ?)`).run(agent.id, user.id).changes;
  })();
  audit(user, 'crew.block', { agent_id: agent.id, rejected }, 'human');
  announce(openIds, 'status');
  return { blocked: agent.name };
}

/** The caller's blocks and refused connections (Rules & blocks tab). */
export function listBlocks(user) {
  const db = getDb();
  const blocks = db.prepare(`
    SELECT b.id, b.created_at, a.name AS agent, u.name AS owner,
           (SELECT COUNT(*) FROM crew_tasks t WHERE t.from_agent_id = a.id AND t.state = 'rejected'
              AND t.updated_at >= b.created_at
              AND t.to_agent_id IN (SELECT id FROM crew_agents WHERE owner_user_id = b.owner_user_id)) AS refused_since
    FROM crew_blocks b JOIN crew_agents a ON a.id = b.blocked_agent_id JOIN users u ON u.id = a.owner_user_id
    WHERE b.owner_user_id = ? ORDER BY b.created_at DESC`).all(user.id);
  const refused = db.prepare(`
    SELECT c.id AS connection_id, c.decided_at, a.name AS agent, u.name AS owner
    FROM crew_connections c JOIN crew_agents a ON a.id = c.from_agent_id JOIN users u ON u.id = a.owner_user_id
    WHERE c.to_owner_id = ? AND c.state = 'refused'
      AND NOT EXISTS (SELECT 1 FROM crew_blocks b WHERE b.owner_user_id = c.to_owner_id AND b.blocked_agent_id = c.from_agent_id)
    ORDER BY c.decided_at DESC`).all(user.id);
  return { blocks, refused };
}

export function unblock(user, blockId) {
  const db = getDb();
  const id = parseInt(blockId, 10);
  const row = Number.isFinite(id) ? db.prepare('SELECT * FROM crew_blocks WHERE id = ?').get(id) : null;
  if (!row || row.owner_user_id !== user.id) fail(404, 'NOT_FOUND', 'No such block of yours.');
  db.prepare('DELETE FROM crew_blocks WHERE id = ?').run(id);
  audit(user, 'crew.unblock', { block_id: id, agent_id: row.blocked_agent_id }, 'human');
  return { unblocked: true };
}

// ── Retention ───────────────────────────────────────────────────────────────

/**
 * Delete Crew history older than RETENTION_DAYS: tasks by last update (their
 * messages cascade), and old messages inside tasks still active. audit_log is
 * not touched.
 */
export function purgeExpiredCrewHistory(db = getDb()) {
  const cutoff = `-${CREW_LIMITS.RETENTION_DAYS} days`;
  return db.transaction(() => {
    const messages = db.prepare("DELETE FROM crew_messages WHERE created_at < datetime('now', ?)").run(cutoff).changes;
    const tasks = db.prepare("DELETE FROM crew_tasks WHERE updated_at < datetime('now', ?)").run(cutoff).changes;
    // Only the last 24 hours matter to the e-mail cap; 30 days is plenty.
    db.prepare("DELETE FROM crew_first_contact_emails WHERE sent_at < datetime('now', ?)").run(cutoff);
    return { tasks, messages };
  })();
}

let _timer = null;

/**
 * Daily retention, same shape as the request digest scheduler: an hourly tick
 * that runs once per calendar day, with the last-run date persisted in settings
 * so a restart neither skips nor doubles a day.
 */
export function startCrewRetentionScheduler() {
  if (_timer) return;
  const tick = () => {
    try {
      const db = getDb();
      const today = new Date().toISOString().slice(0, 10);
      const last = db.prepare("SELECT value FROM settings WHERE key = 'crew_retention_last_run'").get()?.value;
      if (last === today) return;
      const r = purgeExpiredCrewHistory(db);
      db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES ('crew_retention_last_run', ?, datetime('now'))
                  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`).run(today);
      if (r.tasks || r.messages) log.info(`[crew] retention removed ${r.tasks} task(s) and ${r.messages} message(s) older than ${CREW_LIMITS.RETENTION_DAYS} days`);
    } catch (e) {
      log.warn(`[crew] retention tick failed: ${e.message}`);
    }
  };
  tick();
  _timer = setInterval(tick, 60 * 60 * 1000);
  _timer.unref?.();
}
