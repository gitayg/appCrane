/**
 * Crew: the app coder identities ("<slug>-coder").
 *
 * Every Crane-hosted app (source_type 'managed', repo_backend 'local': the apps
 * the coder works on, see routes/coder.js coderGaps) gets one crew agent that
 * other agents address like any other. AppCrane, not a person's agent, answers
 * its tasks by running the app's coder session (services/crewAppCoder.js).
 *
 * ── Lazy, and self-healing ──────────────────────────────────────────────────
 * The rows are reconciled from the apps table (syncAppCoderAgents) at startup,
 * whenever the roster is read and before a task is addressed to a "-coder"
 * name — not created in each of the many app-creation paths (create, managed,
 * adopt, catalogue, upload conversion, repo migration), any one of which would
 * be the path that forgot. A rename or an ownership change is picked up the
 * same way; app deletion also removes the row at once (appDelete.js).
 *
 * ── Whose agent it is ───────────────────────────────────────────────────────
 * A crew agent has exactly one owner, the person who answers first contacts and
 * whose credential a coder turn bills to. An app can have several owners, so
 * the app coder belongs to ONE of them: the app's creator while they are still
 * an owner, otherwise the owner granted first. When that changes, every open
 * task the previous owner approved is failed (not handed to the new owner's
 * subscription), the previous owner's first-contact rows and pending questions
 * for this app coder are deleted, and the new owner answers first contacts
 * afresh.
 *
 * ── What it can never be ────────────────────────────────────────────────────
 * Nobody acts AS an app coder — not its owner, not a platform admin
 * (crew.agentForCaller refuses it), so it has no inbox, token or removal of its
 * own. Its name is reserved: a person cannot register "<slug>-coder" for an
 * existing app. Slugs longer than 34 characters get no app coder (crew names
 * are at most 40), and a name a person registered before the app existed stays
 * theirs: that app gets no app coder until the name is free.
 */
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

export const APP_CODER_SUFFIX = '-coder';
const NAME_MAX = 40;

export function appCoderName(slug) {
  const name = `${String(slug || '')}${APP_CODER_SUFFIX}`;
  return name.length <= NAME_MAX && /^[a-z0-9][a-z0-9-]{1,39}$/.test(name) ? name : null;
}

/** True when `name` is "<slug>-coder" for an app that exists (any app, hosted or not). */
export function isReservedAppCoderName(db, name) {
  const n = String(name || '');
  if (!n.endsWith(APP_CODER_SUFFIX)) return false;
  const slug = n.slice(0, -APP_CODER_SUFFIX.length);
  return !!db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(slug);
}

/** The one owner an app coder belongs to, or null when the app has no owner. */
export function appCoderOwnerId(db, app) {
  const owners = db.prepare(`
    SELECT r.user_id FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1 AND COALESCE(u.kind, 'human') <> 'agent'
    ORDER BY r.rowid ASC`).all(app.id).map((r) => r.user_id);
  if (!owners.length) return null;
  return owners.includes(app.created_by) ? app.created_by : owners[0];
}

function cardFor(app) {
  return JSON.stringify({
    name: appCoderName(app.slug),
    description: `The coder of the app "${app.slug}". Send it a change to make or a question about the app's code: once its owner approves your agent, AppCrane runs the app's coder session with your task, billed to the owner, and replies with the coder's answer. Changes stay unreleased until the owner releases them.`,
    skills: [
      { id: 'code-change', description: `Make a change to ${app.slug}'s code (left unreleased for its owner to review).` },
      { id: 'code-question', description: `Answer a question about ${app.slug}'s code.` },
    ],
    capabilities: {},
  });
}

function hostedApps(db) {
  return db.prepare("SELECT * FROM apps WHERE source_type = 'managed' AND repo_backend = 'local'").all();
}

/**
 * Fail the open tasks of an app coder whose owner changed. Returns their ids.
 * A running task is left to finish: its turn already runs on the credential of
 * the owner who approved it.
 */
function failOpenTasks(db, agentId, reason) {
  const ids = db.prepare(`SELECT id FROM crew_tasks WHERE to_agent_id = ? AND state IN ('submitted', 'working', 'input_required')
                          AND COALESCE(coder_status, '') <> 'running'`).all(agentId).map((r) => r.id);
  for (const id of ids) {
    db.prepare("INSERT INTO crew_messages (task_id, from_agent_id, body, state_after) VALUES (?, ?, ?, 'failed')").run(id, agentId, reason);
    db.prepare("UPDATE crew_tasks SET state = 'failed', updated_at = datetime('now') WHERE id = ?").run(id);
    db.prepare("UPDATE crew_decisions SET status = 'closed', decided_at = datetime('now') WHERE task_id = ? AND status = 'pending'").run(id);
  }
  return ids;
}

/** Delete an app's coder identity; its tasks go with it. Returns the task ids, for the caller to announce. */
export function deleteAppCoderRows(db, appId) {
  const agent = db.prepare('SELECT id FROM crew_agents WHERE app_id = ?').get(appId);
  if (!agent) return [];
  const ids = db.prepare('SELECT id FROM crew_tasks WHERE from_agent_id = ? OR to_agent_id = ?').all(agent.id, agent.id).map((r) => r.id);
  db.prepare('DELETE FROM crew_agents WHERE id = ?').run(agent.id);
  return ids;
}

function audit(userId, appId, action, detail) {
  try {
    logAudit(userId, appId, action, detail, 'agent');
  } catch (e) {
    log.warn(`[crew] audit write failed for ${action}: ${e.message}`);
  }
}

/**
 * Bring one app's coder identity in line with the app, inside
 * syncAppCoderAgents' transaction. Returns { changedTaskIds, deletedTaskIds }.
 */
function syncOne(db, app, existing, eligible) {
  const out = { changedTaskIds: [], deletedTaskIds: [] };
  const ownerId = eligible ? appCoderOwnerId(db, app) : null;
  const name = eligible ? appCoderName(app.slug) : null;
  if (!ownerId || !name) {
    if (existing) {
      out.deletedTaskIds = deleteAppCoderRows(db, app.id);
      audit(existing.owner_user_id, app.id, 'crew.app_coder.remove', { agent_id: existing.id, agent: existing.name, reason: !eligible ? 'not_crane_hosted' : !ownerId ? 'no_owner' : 'name_too_long' });
    }
    return out;
  }
  if (!existing) {
    const taken = db.prepare('SELECT id FROM crew_agents WHERE name = ?').get(name);
    if (taken) {
      log.warn(`[crew] app ${app.slug} gets no app coder: the agent name "${name}" is registered by a person`);
      return out;
    }
    const id = db.prepare(`INSERT INTO crew_agents (name, owner_user_id, kind, card_json, knows_about, app_id)
                           VALUES (?, ?, 'hosted', ?, ?, ?)`).run(name, ownerId, cardFor(app), `app ${app.slug}`, app.id).lastInsertRowid;
    audit(ownerId, app.id, 'crew.app_coder.create', { agent_id: id, agent: name });
    return out;
  }
  if (existing.name !== name) {
    const taken = db.prepare('SELECT id FROM crew_agents WHERE name = ? AND id <> ?').get(name, existing.id);
    if (taken) {
      log.warn(`[crew] app coder ${existing.name} keeps its old name: "${name}" is registered by a person`);
    } else {
      db.prepare('UPDATE crew_agents SET name = ?, card_json = ?, knows_about = ? WHERE id = ?').run(name, cardFor(app), `app ${app.slug}`, existing.id);
      audit(existing.owner_user_id, app.id, 'crew.app_coder.rename', { agent_id: existing.id, from: existing.name, to: name });
    }
  }
  if (existing.owner_user_id !== ownerId) {
    out.changedTaskIds = failOpenTasks(db, existing.id,
      `${app.slug}'s owner changed, so this task (approved by the previous owner) was not run. Send it again: the new owner decides whether your agent may use this app's coder.`);
    db.prepare('UPDATE crew_agents SET owner_user_id = ? WHERE id = ?').run(ownerId, existing.id);
    // SECURITY FIX (review of v2.129.0): the previous owner's first-contact
    // decisions for this app coder (allowed, pending or refused) go, so the
    // new owner decides afresh and the previous owner cannot release anything.
    db.prepare('DELETE FROM crew_connections WHERE to_agent_id = ?').run(existing.id);
    db.prepare(`UPDATE crew_decisions SET status = 'closed', decided_at = datetime('now')
                WHERE status = 'pending' AND decider_user_id = ? AND task_id IN (SELECT id FROM crew_tasks WHERE to_agent_id = ?)`)
      .run(existing.owner_user_id, existing.id);
    // The previous owner's standing rules stop applying by themselves: rules
    // are matched against the receiving agent's CURRENT owner (crew.gateFor).
    audit(ownerId, app.id, 'crew.app_coder.owner_change', { agent_id: existing.id, from_user_id: existing.owner_user_id, to_user_id: ownerId, failed_tasks: out.changedTaskIds.length });
  }
  return out;
}

/**
 * Reconcile every app coder with the apps table. `appId` limits it to one app.
 * Returns the task ids whose rows changed or went, for the caller to announce
 * on crewEvents (crew.js owns the emitter; this module stays below it).
 */
export function syncAppCoderAgents({ db = getDb(), appId = null } = {}) {
  const changed = [];
  const deleted = [];
  db.transaction(() => {
    const apps = appId == null
      ? hostedApps(db)
      : db.prepare("SELECT * FROM apps WHERE id = ? AND source_type = 'managed' AND repo_backend = 'local'").all(appId);
    const eligibleIds = new Set(apps.map((a) => a.id));
    for (const app of apps) {
      const existing = db.prepare('SELECT * FROM crew_agents WHERE app_id = ?').get(app.id);
      const r = syncOne(db, app, existing, true);
      changed.push(...r.changedTaskIds);
      deleted.push(...r.deletedTaskIds);
    }
    // App coders whose app is gone or no longer Crane-hosted.
    const stale = appId == null
      ? db.prepare('SELECT * FROM crew_agents WHERE app_id IS NOT NULL').all().filter((a) => !eligibleIds.has(a.app_id))
      : (eligibleIds.has(appId) ? [] : db.prepare('SELECT * FROM crew_agents WHERE app_id = ?').all(appId));
    for (const agent of stale) {
      const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(agent.app_id) || { id: agent.app_id, slug: agent.name };
      const r = syncOne(db, app, agent, false);
      deleted.push(...r.deletedTaskIds);
    }
  })();
  return { changed, deleted };
}
