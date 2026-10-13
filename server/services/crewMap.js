/**
 * The Crew communication map (phase 2): who sends tasks to whom, as counts.
 *
 * ── What it may show ────────────────────────────────────────────────────────
 * Nodes are the roster (every person sees every registered agent, as on the
 * Roster tab). Edges are AGGREGATES of crew_tasks from the last 30 days —
 * counts per state, a pending-first-contact count and the last activity time.
 * Never a title, a body, a task id or an artifact name: the map is visible to
 * everyone, and what a task is about belongs to the two people involved.
 *
 * Which tasks are counted depends on the viewer, by the same rules as the
 * rest of Crew:
 *   - A HELD task (first contact not yet decided) counts only for the two
 *     owners involved. The roster hides held tasks from third parties: it is a
 *     request the receiving person has not agreed to have broadcast.
 *   - A REJECTED task counts only for the sender's owner (who sees 'rejected'
 *     in their own log anyway) and for the receiving owner. Third parties see
 *     none: an edge made only of rejections would tell everyone that someone
 *     blocked or refused that agent.
 *   - `blocked` / `refused` flags are set ONLY for the person who blocked or
 *     refused. The blocked sender sees plain 'rejected' counts, exactly as in
 *     its log — never the word blocked — and nobody else sees anything.
 * An edge with nothing left to count for the viewer is omitted.
 */
import { getDb } from '../db.js';
import { CREW_LIMITS } from './crew.js';

const STATES = ['submitted', 'working', 'input_required', 'completed', 'failed', 'canceled', 'rejected'];

export function crewMap(user) {
  const db = getDb();
  const agents = db.prepare(`
    SELECT a.id, a.name, a.kind, a.owner_user_id, u.name AS owner_name, u.email AS owner_email
    FROM crew_agents a JOIN users u ON u.id = a.owner_user_id ORDER BY a.name`).all();

  // Owners get a small opaque index for colouring. User ids are not exposed:
  // nothing on this map needs them, and the index is stable per response.
  const ownerIndex = new Map();
  for (const a of [...agents].sort((x, y) => String(x.owner_name || '').localeCompare(String(y.owner_name || '')) || x.owner_user_id - y.owner_user_id)) {
    if (!ownerIndex.has(a.owner_user_id)) ownerIndex.set(a.owner_user_id, ownerIndex.size);
  }
  const byId = new Map(agents.map((a) => [a.id, a]));
  const nodes = agents.map((a) => ({
    name: a.name,
    owner: a.owner_name || a.owner_email || 'unknown',
    owner_key: ownerIndex.get(a.owner_user_id),
    is_mine: a.owner_user_id === user.id,
    runs_as: a.kind,
  }));

  // Grouped in SQL by (from, to, state, held): titles and bodies are never
  // even selected, so no later change to the shaping below can leak them.
  const rows = db.prepare(`
    SELECT from_agent_id, to_agent_id, state, held, COUNT(*) AS n, MAX(updated_at) AS last_at
    FROM crew_tasks
    WHERE created_at >= datetime('now', ?)
    GROUP BY from_agent_id, to_agent_id, state, held`).all(`-${CREW_LIMITS.RETENTION_DAYS} days`);

  const myBlocks = new Set(db.prepare('SELECT blocked_agent_id FROM crew_blocks WHERE owner_user_id = ?').all(user.id).map((r) => r.blocked_agent_id));
  const myRefused = new Set(db.prepare("SELECT from_agent_id FROM crew_connections WHERE to_owner_id = ? AND state = 'refused'").all(user.id).map((r) => r.from_agent_id));

  const edges = new Map();
  for (const r of rows) {
    const from = byId.get(r.from_agent_id);
    const to = byId.get(r.to_agent_id);
    if (!from || !to) continue;
    const participant = from.owner_user_id === user.id || to.owner_user_id === user.id;
    if (r.held && !participant) continue;
    if (r.state === 'rejected' && !participant) continue;
    const key = `${from.id}>${to.id}`;
    let e = edges.get(key);
    if (!e) {
      e = { from: from.name, to: to.name, total: 0, pending_first_contact: 0, last_activity: null, states: Object.fromEntries(STATES.map((s) => [s, 0])) };
      edges.set(key, e);
    }
    e.total += r.n;
    e.states[r.state] += r.n;
    // A held task its sender cancelled stays held (never released) but is no
    // longer waiting on anyone.
    if (r.held && r.state === 'submitted') e.pending_first_contact += r.n;
    if (!e.last_activity || r.last_at > e.last_activity) e.last_activity = r.last_at;
    if (to.owner_user_id === user.id) {
      if (myBlocks.has(from.id)) e.blocked = true;
      else if (myRefused.has(from.id)) e.refused = true;
    }
  }
  return { window_days: CREW_LIMITS.RETENTION_DAYS, nodes, edges: [...edges.values()] };
}
