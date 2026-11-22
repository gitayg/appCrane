// Who changed a person's app access, read back from audit_log.
//
// Only audit rows that name both the app and the person whose access changed
// count, within a short window around the change. If no row matches, or rows
// name more than one actor, the answer is null and the e-mail says nothing
// about who made the change rather than guess.

const BEFORE_S = 5;
const AFTER_S = 60;
const MCP_TOOLS = new Set(['appcrane_grant_app_access', 'appcrane_revoke_app_access']);

function parse(detail) {
  try { return JSON.parse(detail); } catch (_) { return null; }
}

function namesTarget(row, target) {
  const d = parse(row.detail);
  if (!d) return false;
  if (row.action === 'app-set-role') return String(d.body?.user_id ?? '') === String(target.id);
  if (row.action === 'access-review-decision') return Number(d.target_user_id) === target.id;
  if (row.action.startsWith('mcp.') && MCP_TOOLS.has(d.tool) && d.ok === true) {
    const who = String(d.args?.user ?? '');
    return who !== '' && [String(target.id), target.email, target.username].includes(who);
  }
  return false;
}

/** The actor's display name, 'you' when it was the person themselves, or null. */
export function findAccessActor(db, { appId, target, firstAt, lastAt }) {
  const rows = db.prepare(`
    SELECT user_id, action, detail FROM audit_log
    WHERE app_id = ? AND user_id IS NOT NULL
      AND (action IN ('app-set-role', 'access-review-decision') OR action LIKE 'mcp.appcrane_%')
      AND created_at >= datetime(?, '-${BEFORE_S} seconds') AND created_at <= datetime(?, '+${AFTER_S} seconds')
  `).all(appId, firstAt, lastAt);
  const actors = new Set(rows.filter((r) => namesTarget(r, target)).map((r) => r.user_id));
  if (actors.size !== 1) return null;
  const [actorId] = actors;
  if (actorId === target.id) return 'you';
  const u = db.prepare('SELECT name, username FROM users WHERE id = ?').get(actorId);
  return (u?.name || u?.username || '').trim() || null;
}
