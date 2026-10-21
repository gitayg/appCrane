/**
 * Crew agent tokens (phase 2): the credential an A2A caller presents as
 * `Authorization: Bearer <token>`.
 *
 * ── What a token is ──────────────────────────────────────────────────────────
 * One token identifies exactly ONE crew agent. It acts only as that agent and
 * only through that agent's owner: resolveAgentToken() returns the owner's
 * current users row and the agent, and crewA2a.js passes that agent's name as
 * `as_agent` into the same crew.js functions MCP uses — so agentForCaller()
 * still checks ownership, and a token never acts as another agent of the same
 * owner. Nothing in the request can name a different agent to act as.
 *
 * ── Storage ──────────────────────────────────────────────────────────────────
 * `dhk_crew_` + 32 random bytes (base64url). Only SHA-256(token) is stored; the
 * token is returned once, at issue. The lookup is by hash (an index probe on a
 * value the caller cannot steer toward a stored row without knowing a token),
 * and the matched hash is compared again with timingSafeEqual so equality
 * never short-circuits on attacker-controlled bytes. The `dhk_<x>_` shape is
 * deliberate: crewSecrets.js's appcrane-key rule refuses a message carrying
 * one, so an agent cannot relay its token to another agent through Crew.
 *
 * ── Lifecycle ────────────────────────────────────────────────────────────────
 * Issued when a hosted agent is registered from the dashboard, rotated (revoke
 * + issue, one transaction, at most one live token per agent by a partial
 * unique index) or revoked from My agents. Removing the agent deletes its
 * tokens. An owner who is deactivated, deleted, turned into an app-scoped
 * MCP caller or an agent identity stops authenticating at once, because the
 * owner row is re-read on every request.
 */
import crypto from 'crypto';
import { getDb } from '../db.js';
import { hashApiKey } from './encryption.js';
import { agentForCaller, agentWithOwner, assertCrewCaller } from './crew.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

const PREFIX = 'dhk_crew_';

function audit(user, action, detail) {
  try { logAudit(user.id, null, action, detail, 'human'); } catch (e) { log.warn(`[crew] audit write failed for ${action}: ${e.message}`); }
}

/**
 * Push configs are bound to the token that created them. Revoking or rotating
 * a token deletes the agent's configs in the SAME transaction, so a revoked
 * credential stops receiving task content at once — not at the next event.
 */
function dropPushConfigs(db, agentId) {
  db.prepare('DELETE FROM crew_push_configs WHERE agent_id = ?').run(agentId);
}

function issue(db, agentId) {
  const token = PREFIX + crypto.randomBytes(32).toString('base64url');
  const hint = token.slice(PREFIX.length, PREFIX.length + 6);
  db.prepare("UPDATE crew_agent_tokens SET revoked_at = datetime('now') WHERE agent_id = ? AND revoked_at IS NULL").run(agentId);
  dropPushConfigs(db, agentId);
  db.prepare('INSERT INTO crew_agent_tokens (agent_id, token_hash, hint) VALUES (?, ?, ?)').run(agentId, hashApiKey(token), hint);
  return { token, hint };
}

/** Issue (or rotate) the token of one of the caller's agents. Returns the token ONCE. */
export function rotateAgentToken(user, rawName) {
  const db = getDb();
  const agent = agentForCaller(db, user, rawName);
  const out = db.transaction(() => issue(db, agent.id))();
  audit(user, 'crew.token.issue', { agent_id: agent.id, hint: out.hint });
  return { agent: agent.name, token: out.token, hint: out.hint, note: 'Shown once. Store it where the agent reads its secrets; AppCrane keeps only a hash.' };
}

/** Issue a first token for a freshly registered agent (called by the dashboard register route). */
export function issueInitialToken(user, agentName) {
  return rotateAgentToken(user, agentName);
}

export function revokeAgentToken(user, rawName) {
  const db = getDb();
  const agent = agentForCaller(db, user, rawName);
  const n = db.transaction(() => {
    const changed = db.prepare("UPDATE crew_agent_tokens SET revoked_at = datetime('now') WHERE agent_id = ? AND revoked_at IS NULL").run(agent.id).changes;
    dropPushConfigs(db, agent.id);
    return changed;
  })();
  audit(user, 'crew.token.revoke', { agent_id: agent.id, revoked: n });
  return { agent: agent.name, revoked: n > 0 };
}

/** Token status for the caller's agents (My agents): never the token, only its hint and dates. */
export function tokenStatusFor(user) {
  return getDb().prepare(`
    SELECT a.name AS agent, t.hint, t.created_at, t.last_used_at, t.expires_at
    FROM crew_agents a JOIN crew_agent_tokens t ON t.agent_id = a.id AND t.revoked_at IS NULL
    WHERE a.owner_user_id = ?`).all(user.id);
}

/**
 * Is push-config `row` still backed by a live credential? The same checks a
 * fresh A2A request would pass: the exact token that created it is live and
 * belongs to the agent, the agent is active, its owner is active and still
 * allowed Crew over A2A (not an agent identity, no app scope). crewPush.js
 * calls this before rendering anything for a delivery.
 */
export function pushConfigAuthorized(row) {
  const tok = getDb().prepare("SELECT agent_id FROM crew_agent_tokens WHERE id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))").get(row.token_id);
  if (!tok || tok.agent_id !== row.agent_id) return false;
  const found = agentWithOwner(row.agent_id);
  if (!found || !found.owner.active || found.agent.status !== 'active') return false;
  try { assertCrewCaller(found.owner, 'a2a'); } catch { return false; }
  return true;
}

/**
 * The agent and owner a presented token stands for, or null. null for every
 * failure (unknown, revoked, malformed, owner inactive, owner not allowed Crew)
 * so the caller answers one indistinguishable 401.
 */
export function resolveAgentToken(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(PREFIX) || raw.length > 128) return null;
  const db = getDb();
  const hash = hashApiKey(raw);
  const row = db.prepare("SELECT id, agent_id, token_hash FROM crew_agent_tokens WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))").get(hash);
  if (!row) return null;
  const a = Buffer.from(row.token_hash, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const found = agentWithOwner(row.agent_id);
  if (!found || !found.owner.active || found.agent.status !== 'active') return null;
  try { assertCrewCaller(found.owner, 'a2a'); } catch { return null; }
  try { db.prepare("UPDATE crew_agent_tokens SET last_used_at = datetime('now') WHERE id = ?").run(row.id); } catch (_) {}
  return { ...found, token_id: row.id };
}
