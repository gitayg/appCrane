/**
 * Query layer for app-defined roles — the roles an app owner invents for their
 * own app (approver, auditor, reviewer...). AppCrane is the AUTHORITY that
 * stores and issues them; the hosted app is the ENFORCER that acts on them.
 *
 * THE RULE THIS FILE EXISTS TO KEEP: an app-defined role must never confer an
 * AppCrane privilege. Nothing here is consulted by requireAppUser,
 * requireAppAccess, permissions.js or resolveAppRole, and nothing here may
 * become an input to them. These rows exist only to be handed to the app.
 *
 * That is also why the vocabulary is kept disjoint from AppCrane's own (see
 * RESERVED_KEYS): even if some future code path did mix the two namespaces by
 * mistake, an app owner still cannot author the string that path is looking for.
 */
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';

/**
 * Keys travel in an HTTP header (X-AppCrane-App-Roles) and are matched by app
 * code, so the grammar is deliberately narrow: no commas (the separator), no
 * whitespace, no non-ASCII, no case ambiguity. 32 chars max.
 */
export const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

/**
 * Rejected because they collide with AppCrane's own vocabulary — the platform
 * tiers (users.role) and the per-app tier (app_user_roles.app_role). An app
 * owner naming their role 'admin' and granting it to themselves is exactly the
 * escalation this feature must not make expressible.
 */
export const RESERVED_KEYS = ['owner', 'admin', 'user', 'viewer', 'none', 'platform_admin']; // role:platform-admin-skipped

/**
 * Bounded so the header length is a design decision rather than a production
 * discovery: 16 roles x 32 chars + separators stays comfortably under any proxy
 * header limit even if one user holds every role an app defines.
 */
export const MAX_ROLES_PER_APP = 16;

const MAX_LABEL_LENGTH = 64;
const MAX_DESCRIPTION_LENGTH = 280;

export function validateRoleKey(key) {
  if (typeof key !== 'string' || !key) {
    throw new AppError('key is required', 400, 'VALIDATION');
  }
  if (!ROLE_KEY_PATTERN.test(key)) {
    throw new AppError(
      'key must start with a lowercase letter and contain only lowercase letters, digits, hyphens and underscores (max 32 characters)',
      400, 'INVALID_ROLE_KEY',
    );
  }
  if (RESERVED_KEYS.includes(key)) {
    throw new AppError(
      `'${key}' is reserved by AppCrane and cannot be used as an app-defined role key. Reserved: ${RESERVED_KEYS.join(', ')}`,
      400, 'RESERVED_ROLE_KEY',
    );
  }
  return key;
}

function validateLabel(label) {
  if (typeof label !== 'string' || !label.trim()) {
    throw new AppError('label is required', 400, 'VALIDATION');
  }
  const trimmed = label.trim();
  if (trimmed.length > MAX_LABEL_LENGTH) {
    throw new AppError(`label must be ${MAX_LABEL_LENGTH} characters or fewer`, 400, 'VALIDATION');
  }
  return trimmed;
}

function validateDescription(description) {
  if (description === undefined || description === null || description === '') return null;
  if (typeof description !== 'string') {
    throw new AppError('description must be a string', 400, 'VALIDATION');
  }
  const trimmed = description.trim();
  if (trimmed.length > MAX_DESCRIPTION_LENGTH) {
    throw new AppError(`description must be ${MAX_DESCRIPTION_LENGTH} characters or fewer`, 400, 'VALIDATION');
  }
  return trimmed || null;
}

/**
 * Roles defined by this app, each with the number of members holding it.
 *
 * Counts through app_users for the same reason roleKeysForUser reads through it:
 * a grant whose holder is no longer a member is not held by anyone. Counting the
 * grant rows directly would report "1 person holds approver" next to a roster
 * where nobody does, and the delete confirmation — whose whole job is to state
 * the blast radius — would state a number the operator cannot account for.
 */
export function listRoles(appId) {
  return getDb().prepare(`
    SELECT r.id, r.key, r.label, r.description, r.created_by, r.created_at,
           COUNT(au.user_id) AS member_count
    FROM app_defined_roles r
    LEFT JOIN app_role_grants g ON g.role_id = r.id
    LEFT JOIN app_users au ON au.app_id = g.app_id AND au.user_id = g.user_id
    WHERE r.app_id = ?
    GROUP BY r.id
    ORDER BY r.key
  `).all(appId);
}

/**
 * Fetch a role BY (app_id, id) — never by id alone. Every :id in the API is
 * client-supplied, so scoping the lookup to the app from the :slug is what stops
 * app A's role from being edited or deleted through app B's route.
 */
export function getRole(appId, roleId) {
  return getDb().prepare(
    'SELECT * FROM app_defined_roles WHERE app_id = ? AND id = ?'
  ).get(appId, roleId);
}

export function createRole(appId, { key, label, description }, createdBy) {
  const db = getDb();
  validateRoleKey(key);
  const cleanLabel = validateLabel(label);
  const cleanDescription = validateDescription(description);

  const { n } = db.prepare('SELECT COUNT(*) AS n FROM app_defined_roles WHERE app_id = ?').get(appId);
  if (n >= MAX_ROLES_PER_APP) {
    throw new AppError(
      `This app already defines the maximum of ${MAX_ROLES_PER_APP} roles. Delete one before adding another.`,
      400, 'ROLE_LIMIT',
    );
  }

  const existing = db.prepare('SELECT 1 FROM app_defined_roles WHERE app_id = ? AND key = ?').get(appId, key);
  if (existing) {
    throw new AppError(`A role with key '${key}' already exists on this app`, 409, 'DUPLICATE_ROLE_KEY');
  }

  const info = db.prepare(`
    INSERT INTO app_defined_roles (app_id, key, label, description, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(appId, key, cleanLabel, cleanDescription, createdBy);

  return getDb().prepare('SELECT * FROM app_defined_roles WHERE id = ?').get(info.lastInsertRowid);
}

/**
 * Label and description only. The key is IMMUTABLE: it is what the app's own
 * code compares against, and rewriting it would silently re-point every grant
 * at a permission the app has never heard of. Delete and recreate instead —
 * which forces the grants to be re-issued deliberately.
 */
export function updateRole(appId, roleId, { label, description }) {
  const db = getDb();
  const role = getRole(appId, roleId);
  if (!role) throw new AppError('Role not found on this app', 404, 'NOT_FOUND');

  const updates = [];
  const values = [];
  if (label !== undefined) { updates.push('label = ?'); values.push(validateLabel(label)); }
  if (description !== undefined) { updates.push('description = ?'); values.push(validateDescription(description)); }
  if (updates.length === 0) return role;

  db.prepare(`UPDATE app_defined_roles SET ${updates.join(', ')} WHERE id = ?`).run(...values, role.id);
  return getRole(appId, roleId);
}

/** Deletes the role; SQLite cascades its grants. Returns how many were lost. */
export function deleteRole(appId, roleId) {
  const db = getDb();
  const role = getRole(appId, roleId);
  if (!role) throw new AppError('Role not found on this app', 404, 'NOT_FOUND');

  const { n } = db.prepare('SELECT COUNT(*) AS n FROM app_role_grants WHERE role_id = ?').get(role.id);
  db.prepare('DELETE FROM app_defined_roles WHERE id = ?').run(role.id);
  return { role, grants_removed: n };
}

/**
 * The keys a user holds on an app, sorted. This is the read the wire contract
 * is built on (/api/me's app_roles and the X-AppCrane-App-Roles header), so it
 * returns keys — never ids, never labels, and never AppCrane's own tier.
 *
 * Joined to app_users so a grant is live only while its holder is still a member
 * — the same condition setUserRoleKeys enforces to WRITE one. Revocation happens
 * in several places (the Users modal's replace-all, the per-user tier route, the
 * MCP revoke tool) and every one of them must take effect on the wire; without
 * this join, a single revoke path that forgot to clear the grant rows would keep
 * handing a removed person their in-app powers, and on a public app — where
 * resolveAppRole falls back to 'viewer' rather than denying — /verify would go on
 * issuing the header indefinitely. Those paths clear the rows too; this is the
 * choke point that makes the guarantee hold even if a future one does not.
 */
export function roleKeysForUser(appId, userId) {
  if (!appId || !userId) return [];
  return getDb().prepare(`
    SELECT r.key
    FROM app_role_grants g
    JOIN app_defined_roles r ON r.id = g.role_id
    JOIN app_users au ON au.app_id = g.app_id AND au.user_id = g.user_id
    WHERE g.app_id = ? AND g.user_id = ?
    ORDER BY r.key
  `).all(appId, userId).map(r => r.key);
}

/**
 * Clear every app-defined role a user holds on one app. Called from the revoke
 * paths, so that re-adding the person later does not silently restore roles
 * nobody re-granted — a grant should have to be issued deliberately each time.
 */
export function clearUserRoleGrants(appId, userId) {
  return getDb().prepare('DELETE FROM app_role_grants WHERE app_id = ? AND user_id = ?')
    .run(appId, userId).changes;
}

/**
 * Drop grants belonging to people who are no longer members of the app. For the
 * replace-the-whole-member-list route, where the users who lost access are not
 * enumerated — they are whoever is missing from the new list.
 */
export function pruneGrantsForNonMembers(appId) {
  return getDb().prepare(`
    DELETE FROM app_role_grants
    WHERE app_id = ?
      AND user_id NOT IN (SELECT user_id FROM app_users WHERE app_id = ?)
  `).run(appId, appId).changes;
}

/**
 * Members of the app (app_users), each with the app-defined keys they hold and
 * AppCrane's own tier for them.
 *
 * app_role rides along so a screen showing both systems needs one read, not two.
 * The other tier source, GET /api/apps/:slug/identity/users, admits only app
 * OWNERS and global admins — so an app ADMIN, who may freely grant and revoke
 * app-defined roles, could not read the very column those roles are meant to be
 * compared against, and every tier rendered blank for the persona the screen is
 * for. It is the same audience either way: anyone who can see this roster.
 */
export function listMembersWithRoles(appId) {
  const db = getDb();
  const members = db.prepare(`
    SELECT u.id, u.name, u.email, u.username, u.avatar_url,
           COALESCE(aur.app_role, 'none') AS app_role
    FROM app_users au
    JOIN users u ON u.id = au.user_id
    LEFT JOIN app_user_roles aur ON aur.app_id = au.app_id AND aur.user_id = au.user_id
    WHERE au.app_id = ?
    ORDER BY u.name
  `).all(appId);

  const grants = db.prepare(`
    SELECT g.user_id, r.key
    FROM app_role_grants g
    JOIN app_defined_roles r ON r.id = g.role_id
    WHERE g.app_id = ?
    ORDER BY r.key
  `).all(appId);

  const byUser = new Map();
  for (const g of grants) {
    if (!byUser.has(g.user_id)) byUser.set(g.user_id, []);
    byUser.get(g.user_id).push(g.key);
  }

  return members.map(m => ({ ...m, app_roles: byUser.get(m.id) || [] }));
}

/**
 * Replace a user's whole set of app-defined roles on one app.
 *
 * Takes KEYS, not role ids, and resolves them against (app_id, key). A caller
 * therefore cannot name app A's role from app B's route at all — the IDOR is
 * unreachable rather than guarded against. The user must already be a member of
 * the app: a grant on a non-member is unenforceable (the app never sees them)
 * and would let this route write rows keyed to arbitrary user ids.
 */
export function setUserRoleKeys(appId, userId, keys, grantedBy) {
  const db = getDb();

  if (!Array.isArray(keys)) throw new AppError('keys must be an array of role keys', 400, 'VALIDATION');

  const member = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(appId, userId);
  if (!member) {
    throw new AppError('That user is not a member of this app. Assign them to the app first.', 404, 'NOT_A_MEMBER');
  }

  const unique = [...new Set(keys)];
  const roleIds = [];
  for (const key of unique) {
    const role = db.prepare('SELECT id FROM app_defined_roles WHERE app_id = ? AND key = ?').get(appId, key);
    if (!role) throw new AppError(`This app defines no role with key '${key}'`, 400, 'UNKNOWN_ROLE_KEY');
    roleIds.push(role.id);
  }

  db.transaction(() => {
    db.prepare('DELETE FROM app_role_grants WHERE app_id = ? AND user_id = ?').run(appId, userId);
    const insert = db.prepare(`
      INSERT INTO app_role_grants (role_id, user_id, app_id, granted_by) VALUES (?, ?, ?, ?)
    `);
    for (const roleId of roleIds) insert.run(roleId, userId, appId, grantedBy);
  })();

  return roleKeysForUser(appId, userId);
}
