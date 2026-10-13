/**
 * Crew, phase 3: standing rules and the "always ask" rule.
 *
 * A standing rule is a person saying "agent X may do <action> on <scope>
 * without asking me". It is owned by that person (owner_user_id), names one
 * agent, one action and one scope, may expire, and is revoked in one click.
 * Rules exist to answer questions that would otherwise go to their owner:
 *
 *   - a task sent with a declared action + scope to the owner's agents
 *     (crew.gateFor, after the block and first-contact checks), and
 *   - an agent's INPUT_REQUIRED question routed to the owner (crew.reply).
 *
 * ── Matching ─────────────────────────────────────────────────────────────────
 * Exact equality on (owner, agent, action, scope), live (not revoked, not
 * expired). No wildcards, no prefixes: "sandbox" does not cover "sandbox-2",
 * because a rule the person did not literally write must not be read into one
 * they did. Both action and scope must be DECLARED: a task or question that
 * leaves either out matches nothing, so a sender cannot reach a rule by being
 * vague.
 *
 * ── Always ask ───────────────────────────────────────────────────────────────
 * Production and deletions never get a standing rule (operator decision).
 * alwaysAskReason() is checked before any rule lookup and on rule creation:
 *   - scope: anything containing "prod" (production, prod, prod-eu, preprod —
 *     over-matching only means a person is asked);
 *   - action: anything containing delete / drop / remov / destroy / truncat /
 *     purge / wipe / erase;
 *   - and, as a backstop for a sender that declares a harmless action and
 *     scope but writes the real intent in words, the same words in the title
 *     and the question text.
 * The backstop is deliberately crude and one-sided: a false positive costs
 * one click, a false negative would let a rule approve a production deletion.
 */
import crypto from 'crypto';
import { AppError } from '../utils/errors.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

const ACTION_RE = /^[a-z0-9][a-z0-9._-]{0,39}$/;
export const SCOPE_MAX = 60;
export const RULE_MAX_DAYS = 365;
export const RULES_PER_OWNER = 200;

function fail(status, code, message) {
  throw new AppError(message, status, code);
}

function audit(userId, action, detail, actorKind) {
  try {
    logAudit(userId, null, action, detail, actorKind);
  } catch (e) {
    log.warn(`[crew] audit write failed for ${action}: ${e.message}`);
    if (process.env.APPCRANE_AUDIT_REQUIRED === '1') throw e;
  }
}

export function newOpaqueId() {
  return crypto.randomBytes(16).toString('base64url');
}

/** An action as declared: a skill-like id, lowercase. null when not given. */
export function normalizeAction(raw) {
  if (raw == null || raw === '') return null;
  const a = String(raw).trim().toLowerCase();
  if (!ACTION_RE.test(a)) fail(400, 'VALIDATION', 'action must be 1-40 characters: lowercase letters, digits, dot, underscore or hyphen (a skill name such as "migrate").');
  return a;
}

/** A scope as declared: free text, one line, lowercase, at most 60 chars. null when not given. */
export function normalizeScope(raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
  if (!s) return null;
  if (s.length > SCOPE_MAX) fail(400, 'VALIDATION', `scope is at most ${SCOPE_MAX} characters (for example "sandbox").`);
  return s;
}

const PROD_FIELD = /prod/i;
const DELETE_FIELD = /delet|drop|remov|destroy|truncat|purge|wipe|erase/i;
const PROD_WORDS = /\b(prod|production|prd)\b/i;
const DELETE_WORDS = /\b(delet\w*|drop\w*|remov\w*|destroy\w*|truncat\w*|purg\w*|wip(e|es|ed|ing)|eras\w*|rm)\b/i;

/**
 * 'production' | 'deletion' when no standing rule may cover this, else null.
 * `texts` are the free-text backstop (title, question).
 */
export function alwaysAskReason({ action, scope, texts = [] }) {
  if (scope && PROD_FIELD.test(scope)) return 'production';
  if (action && DELETE_FIELD.test(action)) return 'deletion';
  for (const t of texts) {
    const s = String(t ?? '');
    if (PROD_WORDS.test(s)) return 'production';
    if (DELETE_WORDS.test(s)) return 'deletion';
  }
  return null;
}

const LIVE = `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))`;

/**
 * The live rule of `ownerId` that lets `agentId` do `action` on `scope`, or
 * null. Callers have already applied blocks and first contact (rules never
 * bypass either); a block is re-checked here anyway, because "blocking ends
 * every standing rule for that agent" must hold even if a revoke was missed.
 */
export function matchRule(db, { ownerId, agentId, action, scope, texts = [] }) {
  if (!action || !scope) return null;
  if (alwaysAskReason({ action, scope, texts })) return null;
  const blocked = db.prepare('SELECT 1 FROM crew_blocks WHERE owner_user_id = ? AND blocked_agent_id = ?').get(ownerId, agentId);
  if (blocked) return null;
  return db.prepare(`SELECT * FROM crew_rules WHERE owner_user_id = ? AND agent_id = ? AND action = ? AND scope = ? AND ${LIVE}`)
    .get(ownerId, agentId, action, scope) || null;
}

/** Count one use, inside the caller's transaction. The audit row is written by the caller after commit. */
export function recordRuleUse(db, ruleId) {
  db.prepare("UPDATE crew_rules SET use_count = use_count + 1, last_used_at = datetime('now') WHERE id = ?").run(ruleId);
}

export function auditRuleUse(actingUserId, rule, detail, actorKind) {
  audit(actingUserId, 'crew.rule.use', { rule_id: rule.id, rule_owner_id: rule.owner_user_id, agent_id: rule.agent_id, ...detail }, actorKind);
}

function expiryFrom(days) {
  if (days == null || days === '' || days === 0 || days === '0') return null;
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > RULE_MAX_DAYS) fail(400, 'VALIDATION', `expires_in_days must be a whole number from 1 to ${RULE_MAX_DAYS}, or empty for no expiry.`);
  return n;
}

/**
 * Create a rule owned by `user`. Used by hand (Rules & blocks) and by
 * "Approve and always allow" (fromDecisionId). Runs inside the caller's
 * transaction when one is open (better-sqlite3 nests). Returns the rule row.
 */
export function createRuleRow(db, user, { agentId, action, scope, expiresInDays, fromDecisionId = null, texts = [] }) {
  if (!action || !scope) fail(400, 'VALIDATION', 'A standing rule needs an action and a scope (who may do what, where).');
  const reason = alwaysAskReason({ action, scope, texts });
  if (reason) {
    fail(400, 'ALWAYS_ASKS', reason === 'production'
      ? 'Production always asks: a standing rule cannot cover a production scope.'
      : 'Deletions always ask: a standing rule cannot cover an action that deletes.');
  }
  const blocked = db.prepare('SELECT 1 FROM crew_blocks WHERE owner_user_id = ? AND blocked_agent_id = ?').get(user.id, agentId);
  if (blocked) fail(409, 'BLOCKED', 'You blocked this agent. Unblock it before giving it a standing rule.');
  const days = expiryFrom(expiresInDays);
  const existing = db.prepare('SELECT * FROM crew_rules WHERE owner_user_id = ? AND agent_id = ? AND action = ? AND scope = ? AND revoked_at IS NULL')
    .get(user.id, agentId, action, scope);
  if (existing) {
    // Same rule again: refresh its expiry rather than fail. An expired live
    // row is the same rule coming back.
    db.prepare(`UPDATE crew_rules SET expires_at = ${days ? `datetime('now', ?)` : 'NULL'} WHERE id = ?`)
      .run(...(days ? [`+${days} days`, existing.id] : [existing.id]));
    return { rule: db.prepare('SELECT * FROM crew_rules WHERE id = ?').get(existing.id), created: false };
  }
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM crew_rules WHERE owner_user_id = ? AND revoked_at IS NULL').get(user.id);
  if (n >= RULES_PER_OWNER) fail(429, 'RATE_LIMITED', `You have ${n} standing rules (the limit is ${RULES_PER_OWNER}). Revoke some you no longer need.`);
  const id = newOpaqueId();
  db.prepare(`INSERT INTO crew_rules (id, owner_user_id, agent_id, action, scope, expires_at, from_decision_id)
              VALUES (?, ?, ?, ?, ?, ${days ? `datetime('now', ?)` : 'NULL'}, ?)`)
    .run(...[id, user.id, agentId, action, scope, ...(days ? [`+${days} days`] : []), fromDecisionId]);
  return { rule: db.prepare('SELECT * FROM crew_rules WHERE id = ?').get(id), created: true };
}

export function auditRuleCreate(user, rule, how) {
  audit(user.id, 'crew.rule.create', {
    rule_id: rule.id, agent_id: rule.agent_id, action: rule.action, scope: rule.scope,
    expires_at: rule.expires_at, how, from_decision_id: rule.from_decision_id,
  }, 'human');
}

function ruleView(r) {
  const expired = !!(r.expires_at && r.expired);
  return {
    id: r.id, agent: r.agent, agent_owner: r.agent_owner, action: r.action, scope: r.scope,
    expires_at: r.expires_at, expired, from_decision: !!r.from_decision_id,
    use_count: r.use_count, last_used_at: r.last_used_at, created_at: r.created_at,
  };
}

const RULE_SELECT = `
  SELECT r.*, a.name AS agent, u.name AS agent_owner,
         (r.expires_at IS NOT NULL AND r.expires_at <= datetime('now')) AS expired
  FROM crew_rules r JOIN crew_agents a ON a.id = r.agent_id JOIN users u ON u.id = a.owner_user_id`;

/** The caller's own live rules (expired ones included, marked). Never anyone else's, admins included. */
export function listRules(db, user) {
  return db.prepare(`${RULE_SELECT} WHERE r.owner_user_id = ? AND r.revoked_at IS NULL ORDER BY r.created_at DESC`).all(user.id).map(ruleView);
}

function ownRule(db, user, ruleId) {
  const row = typeof ruleId === 'string' && ruleId.length <= 64
    ? db.prepare('SELECT * FROM crew_rules WHERE id = ? AND revoked_at IS NULL').get(ruleId) : null;
  // Same answer for "no such rule" and "not yours".
  if (!row || row.owner_user_id !== user.id) fail(404, 'NOT_FOUND', 'No such standing rule of yours.');
  return row;
}

/** Change a rule's expiry (Edit). Who/what/where are the rule's identity: change those by revoking and adding. */
export function updateRuleExpiry(db, user, ruleId, expiresInDays) {
  const row = ownRule(db, user, ruleId);
  const days = expiryFrom(expiresInDays);
  db.prepare(`UPDATE crew_rules SET expires_at = ${days ? `datetime('now', ?)` : 'NULL'} WHERE id = ?`)
    .run(...(days ? [`+${days} days`, row.id] : [row.id]));
  audit(user.id, 'crew.rule.update', { rule_id: row.id, expires_in_days: days }, 'human');
  return ruleView(db.prepare(`${RULE_SELECT} WHERE r.id = ?`).get(row.id));
}

export function revokeRule(db, user, ruleId) {
  const row = ownRule(db, user, ruleId);
  db.prepare("UPDATE crew_rules SET revoked_at = datetime('now') WHERE id = ?").run(row.id);
  audit(user.id, 'crew.rule.revoke', { rule_id: row.id, agent_id: row.agent_id, reason: 'revoked' }, 'human');
  return { revoked: row.id };
}

/**
 * Blocking (or refusing) an agent ends every standing rule its blocker gave it
 * (plan: "Blocking also ends any standing rule for that agent"). Inside the
 * caller's transaction; returns the revoked ids for the caller to audit.
 */
export function revokeRulesForAgent(db, ownerId, agentId) {
  const ids = db.prepare('SELECT id FROM crew_rules WHERE owner_user_id = ? AND agent_id = ? AND revoked_at IS NULL').all(ownerId, agentId).map((r) => r.id);
  if (ids.length) db.prepare("UPDATE crew_rules SET revoked_at = datetime('now') WHERE owner_user_id = ? AND agent_id = ? AND revoked_at IS NULL").run(ownerId, agentId);
  return ids;
}

export function auditRulesRevokedByBlock(userId, ids, agentId) {
  for (const id of ids) audit(userId, 'crew.rule.revoke', { rule_id: id, agent_id: agentId, reason: 'blocked' }, 'human');
}

/** For display in the Crew log: the rule a task ran under, owner-agnostic. */
export function ruleSummary(db, ruleId) {
  if (!ruleId) return null;
  const r = db.prepare(`${RULE_SELECT} WHERE r.id = ?`).get(ruleId);
  if (!r) return { id: ruleId, removed: true };
  return { id: r.id, agent: r.agent, action: r.action, scope: r.scope, revoked: !!r.revoked_at, owner_user_id: r.owner_user_id };
}
