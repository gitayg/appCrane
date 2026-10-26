import { getDb } from '../db.js';
import { isAdmin } from '../utils/roles.js';
import { listTools, getToolCatalog, isMcpLockedOut } from './mcpTools.js';
import { grantLifetimeDays } from './oauthStore.js';

// What an MCP OAuth connection approved by this user can actually do, for the
// consent screen. Computed from the same functions that answer the token's
// tools/list (listTools with an OAuth-shaped key), and from the app rule the
// MCP tools apply to a key: a platform admin reaches every app, anyone else the
// apps they own, both inside users.mcp_app_scope when it is set.

const APP_LIST_MAX = 25;

function scopeList(raw) {
  if (raw == null || raw === '') return null;
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a.map(String) : null; } catch (_) { return null; }
}

function reachableApps(db, user) {
  const admin = isAdmin(user);
  const slugs = admin
    ? db.prepare('SELECT slug FROM apps ORDER BY slug').all().map(r => r.slug)
    : db.prepare(`SELECT DISTINCT a.slug FROM apps a JOIN app_user_roles aur ON aur.app_id = a.id
                  WHERE aur.user_id = ? AND aur.app_role = 'owner' ORDER BY a.slug`).all(user.id).map(r => r.slug);
  const ceiling = scopeList(user.mcp_app_scope);
  return { slugs: ceiling ? slugs.filter(s => ceiling.includes(s)) : slugs, limited: !!ceiling, all: admin && !ceiling };
}

function toolsFor(user, readOnly) {
  return listTools(user, { id: 'oauth-consent-preview', read_only: readOnly, oauth: {} }).map(t => t.name);
}

/** { role, apps, tools, lines_full, lines_read_only, lifetime_days, expires_at } */
export function consentScope(userId, now = new Date()) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const days = grantLifetimeDays(db);
  const expiresAt = new Date(now.getTime() + days * 86400000).toISOString();
  const lifetime = `Acts as you until you revoke it, and for at most ${days} days (until ${expiresAt.slice(0, 10)}); then the app has to ask again. Revoke it any time under MCP, Connected apps.`;
  if (!user || isMcpLockedOut(user)) {
    const none = ['Nothing: your MCP access is switched off (empty MCP app scope), so every tool call will be refused.', lifetime];
    return { role: user?.role || null, apps: { all: false, count: 0, list: [], limited: true }, tools: { full: 0, read_only: 0, admin: [], secret: [] }, lines_full: none, lines_read_only: none, lifetime_days: days, expires_at: expiresAt };
  }
  const admin = isAdmin(user);
  const apps = reachableApps(db, user);
  const full = toolsFor(user, false);
  const read = toolsFor(user, true);
  const catalog = new Map(getToolCatalog().map(t => [t.name, t]));
  const adminTools = full.filter(n => ['admin', 'platform_admin'].includes(catalog.get(n)?.requiredRole));
  const secretTools = full.filter(n => catalog.get(n)?.readOnly && !read.includes(n));
  const shown = apps.slugs.slice(0, APP_LIST_MAX).join(', ') + (apps.slugs.length > APP_LIST_MAX ? ` and ${apps.slugs.length - APP_LIST_MAX} more` : '');

  const appLine = apps.all
    ? `EVERY app on this AppCrane (${apps.slugs.length}), including apps you are not a member of, because you are a platform admin.`
    : apps.slugs.length === 0
      ? (admin ? 'No apps: your MCP app scope lists none that exist.' : 'No apps yet: a connection reaches only the apps you own, and you own none.')
      : `${admin ? 'These apps (your MCP app scope)' : (apps.limited ? 'The apps you own that your MCP app scope allows' : 'Only the apps you own')}: ${shown}.`;
  const adminLine = adminTools.length
    ? `Platform administration: ${adminTools.length} admin tool${adminTools.length === 1 ? '' : 's'} (${adminTools.slice(0, 6).map(n => n.replace(/^appcrane_/, '')).join(', ')}${adminTools.length > 6 ? ', ...' : ''}).`
    : null;
  const adminReadLine = adminTools.filter(n => read.includes(n)).length
    ? `Platform-wide reads: ${adminTools.filter(n => read.includes(n)).length} admin tool${adminTools.filter(n => read.includes(n)).length === 1 ? '' : 's'} that change nothing.`
    : null;
  const lines_full = [
    appLine,
    `Read AND change them: ${full.length} tools, including deploys, environment variables and access.`,
    adminLine,
    secretTools.length ? `Read plaintext secrets and files inside app containers (${secretTools.join(', ')}).` : null,
    lifetime,
  ].filter(Boolean);
  const lines_read_only = [
    appLine,
    `Read only: ${read.length} tools that change nothing. Tools that reveal plaintext secrets or file contents are refused.`,
    adminReadLine,
    lifetime,
  ].filter(Boolean);
  return {
    role: user.role,
    apps: { all: apps.all, count: apps.slugs.length, list: apps.slugs.slice(0, APP_LIST_MAX), limited: apps.limited },
    tools: { full: full.length, read_only: read.length, admin: adminTools, secret: secretTools },
    lines_full, lines_read_only, lifetime_days: days, expires_at: expiresAt,
  };
}
