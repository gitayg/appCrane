import { getDb } from '../db.js';
import { ALL_SCOPES, SCOPE, expandScopes, parseScopeString } from './mcpScopes.js';

// Named scope sets ("blueprints") for agent credentials, and the one function
// that turns what a credential stores into what it may do at this moment.

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;
const LEGACY = new Set([SCOPE.FULL, SCOPE.READ]);

const bad = (m) => Object.assign(new Error(m), { status: 400 });

function view(row) {
  if (!row) return null;
  return {
    id: row.id, name: row.name, description: row.description, scopes: parseScopeString(row.scopes),
    apps: row.apps == null ? null : JSON.parse(row.apps), builtin: !!row.builtin,
    created_at: row.created_at, updated_at: row.updated_at,
  };
}

export function listBlueprints(db = getDb()) {
  return db.prepare('SELECT * FROM mcp_scope_blueprints ORDER BY builtin DESC, name').all().map(view);
}

export function getBlueprint(id, db = getDb()) {
  if (id == null) return null;
  return view(db.prepare('SELECT * FROM mcp_scope_blueprints WHERE id = ?').get(id));
}

export function findBlueprint(ref, db = getDb()) {
  if (Number.isInteger(ref)) return getBlueprint(ref, db);
  if (typeof ref === 'string') return view(db.prepare('SELECT * FROM mcp_scope_blueprints WHERE name = ?').get(ref));
  return null;
}

function cleanScopes(v) {
  const list = Array.isArray(v) ? v : parseScopeString(v);
  if (!list.length || list.length > ALL_SCOPES.length) throw bad(`scopes must list 1 to ${ALL_SCOPES.length} of: ${ALL_SCOPES.join(', ')}`);
  for (const s of list) if (!ALL_SCOPES.includes(s)) throw bad(`unknown scope ${JSON.stringify(String(s)).slice(0, 60)}; known: ${ALL_SCOPES.join(', ')}`);
  return [...new Set(list)].join(' ');
}

function cleanApps(v) {
  if (v == null) return null;
  if (!Array.isArray(v) || v.length > 200 || v.some((s) => typeof s !== 'string' || !SLUG_RE.test(s))) {
    throw bad('apps must be null (every app the user can reach) or an array of up to 200 app slugs');
  }
  return JSON.stringify([...new Set(v)]);
}

export function createBlueprint(body, userId, db = getDb()) {
  const b = body || {};
  if (typeof b.name !== 'string' || !NAME_RE.test(b.name)) throw bad('name must be 1-40 lowercase letters, digits or dashes');
  if (b.description != null && (typeof b.description !== 'string' || b.description.length > 300)) throw bad('description must be a string of at most 300 characters');
  if (findBlueprint(b.name, db)) throw Object.assign(new Error(`a blueprint named ${b.name} already exists`), { status: 409 });
  const id = db.prepare('INSERT INTO mcp_scope_blueprints (name, description, scopes, apps, created_by) VALUES (?, ?, ?, ?, ?)')
    .run(b.name, b.description || '', cleanScopes(b.scopes), cleanApps(b.apps), userId ?? null).lastInsertRowid;
  return getBlueprint(id, db);
}

export function updateBlueprint(id, body, db = getDb()) {
  const cur = getBlueprint(id, db);
  if (!cur) return null;
  const b = body || {};
  if (b.description != null && (typeof b.description !== 'string' || b.description.length > 300)) throw bad('description must be a string of at most 300 characters');
  db.prepare("UPDATE mcp_scope_blueprints SET description = ?, scopes = ?, apps = ?, updated_at = datetime('now') WHERE id = ?").run(
    b.description ?? cur.description,
    b.scopes === undefined ? cur.scopes.join(' ') : cleanScopes(b.scopes),
    b.apps === undefined ? (cur.apps == null ? null : JSON.stringify(cur.apps)) : cleanApps(b.apps),
    id,
  );
  return getBlueprint(id, db);
}

export function deleteBlueprint(id, db = getDb()) {
  const cur = getBlueprint(id, db);
  if (!cur) return null;
  if (cur.builtin) throw bad('a built-in blueprint can be edited but not deleted');
  db.prepare('DELETE FROM mcp_scope_blueprints WHERE id = ?').run(id);
  return cur;
}

/** A stored scope string is legacy when it is exactly what the pre-blueprint server issued. */
export function isLegacyScope(scope) {
  return scope == null || LEGACY.has(scope);
}

/**
 * What a credential may do now. `scope` is the grant's scope string (null for
 * a dhk_mcp_* key), `blueprintId` its blueprint. Null means legacy: no scope
 * checks, today's role-based behaviour. Otherwise { scopes, apps, blueprint }:
 * scopes is the expanded set the credential asked for, intersected with the
 * blueprint's current scopes; apps is the blueprint's app list or null.
 */
export function effectiveScopes({ scope = null, blueprintId = null } = {}, db = getDb()) {
  if (blueprintId == null && isLegacyScope(scope)) return null;
  const asked = expandScopes(scope == null ? [SCOPE.FULL] : parseScopeString(scope));
  if (blueprintId == null) return { scopes: asked, apps: null, blueprint: null };
  const bp = getBlueprint(blueprintId, db);
  if (!bp) return { scopes: new Set(), apps: [], blueprint: null };
  const allowed = expandScopes(bp.scopes);
  return { scopes: new Set([...asked].filter((s) => allowed.has(s))), apps: bp.apps, blueprint: bp.name };
}

/** Narrow a users.mcp_app_scope value (JSON slug list, or null = no limit) to a blueprint's apps. */
export function narrowAppScope(raw, apps) {
  if (apps == null) return raw;
  let cur = null;
  if (raw != null && raw !== '') {
    try { cur = JSON.parse(raw); } catch (_) { cur = null; }
  }
  const out = Array.isArray(cur) ? apps.filter((s) => cur.map(String).includes(s)) : apps;
  return JSON.stringify(out);
}

/** Stamp a credential's effective scopes on BOTH views of the caller, as read_only is. */
export function applyCredentialScopes(user, key, eff) {
  if (!eff) return;
  const list = [...eff.scopes].sort();
  user.mcp_scopes = list;
  user.mcp_app_scope = narrowAppScope(user.mcp_app_scope, eff.apps);
  if (key) {
    key.scopes = list;
    key.blueprint = eff.blueprint;
  }
}
