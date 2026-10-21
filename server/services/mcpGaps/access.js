// Authz helpers for the tools in this directory. mcpTools.js keeps
// getAppForUser private, so resolveMcpApp mirrors it rule for rule: the
// mcp_app_scope ceiling first, a personal MCP key covers only apps its user
// owns (platform admins excepted), otherwise platform admin or an app_users row.
// callTool still applies the read-only, coder and scope gates before any of
// these handlers run; the checks here hold even when it does not.

import { getDb } from '../../db.js';
import { isAdmin } from '../../utils/roles.js';
import { isCoderKey } from '../coderMcpKey.js';

function mcpScope(user) {
  const raw = user?.mcp_app_scope;
  if (raw == null || raw === '') return null;
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.map(String) : null;
  } catch (_) {
    return null;
  }
}

export function resolveMcpApp(user, slug) {
  if (typeof slug !== 'string' || !slug) throw new Error('slug is required');
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) throw new Error(`App not found: ${slug}`);
  const scope = mcpScope(user);
  if (scope && !scope.includes(slug)) throw new Error(`Forbidden: app ${slug} is outside this key's MCP scope`);
  if (user._mcpUserKey) {
    if (isAdmin(user)) return app;
    const owns = db.prepare("SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ? AND app_role = 'owner'").get(app.id, user.id);
    if (!owns) throw new Error(`Forbidden: this personal MCP key only covers apps you own; ${slug} is not one`);
    return app;
  }
  if (scope) return app;
  if (isAdmin(user)) return app;
  const member = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  if (!member) throw new Error(`Forbidden: no access to app ${slug}`);
  return app;
}

export function isReadOnlyCaller(user) {
  return !!(user?.mcp_read_only || user?._mcpUserKey?.read_only);
}

export function assertWriteCaller(user, what) {
  if (isCoderKey(user, user?._mcpUserKey)) throw new Error(`Forbidden: the coder's AppCrane connection cannot ${what}`);
  if (isReadOnlyCaller(user)) throw new Error(`Forbidden: this MCP key is read-only and cannot ${what}`);
}
