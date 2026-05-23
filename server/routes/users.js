import { Router } from 'express';
import { getDb } from '../db.js';
import { generateApiKey, hashApiKey, hashPassword, encrypt } from '../services/encryption.js';
import { requireAuth, requireAdmin, requirePlatformAdmin, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { isAdmin } from '../utils/roles.js';

const router = Router();

router.use(requireAuth);

/** True if `user` is the owner of at least one app — gates owner self-service. */
function ownsAnyApp(db, userId) {
  return !!db.prepare(
    "SELECT 1 FROM app_user_roles WHERE user_id = ? AND app_role = 'owner' LIMIT 1"
  ).get(userId);
}

/**
 * GET /api/users - List users.
 *
 * Admins get the full directory (with login/SSO metadata). v2.7.9: app owners
 * also get a list so they can manage members of their own apps from the
 * Launcher, but a LEAN projection only (id, name, email, username, role,
 * kind) — no password/SSO/last-login/assignment metadata. Non-owners are
 * still denied.
 */
router.get('/', (req, res) => {
  const db = getDb();
  if (isAdmin(req.user)) {
    const users = db.prepare(`
      SELECT u.id, u.name, u.email, u.username, u.role, u.kind, u.created_at, u.last_login_at,
        CASE WHEN u.password_hash IS NOT NULL THEN 1 ELSE 0 END as has_password,
        CASE WHEN u.saml_name_id IS NOT NULL THEN 'saml' WHEN u.sso_sub IS NOT NULL THEN 'oidc' ELSE NULL END as sso_provider,
        (SELECT GROUP_CONCAT(a.slug, ', ') FROM app_users au JOIN apps a ON a.id = au.app_id WHERE au.user_id = u.id) as assigned_apps
      FROM users u ORDER BY u.created_at DESC
    `).all();
    return res.json({ users });
  }
  if (!ownsAnyApp(db, req.user.id)) {
    throw new AppError('Admin access required', 403, 'FORBIDDEN');
  }
  const users = db.prepare(
    'SELECT id, name, email, username, role, kind FROM users ORDER BY name'
  ).all();
  res.json({ users });
});

/**
 * POST /api/users - Create user (admin only)
 */
router.post('/', requireAdmin, auditMiddleware('user-create'), (req, res) => {
  const { name, email, role, kind, username, password, avatar_url, phone, year_of_birth } = req.body;
  if (!name) throw new AppError('Name is required', 400, 'VALIDATION');

  // Role assignment rules:
  //   - 'platform_admin' can only be assigned by an existing platform_admin (no privilege escalation)
  //   - 'admin' can be assigned by admin or platform_admin
  //   - anything else falls back to 'user'
  let userRole = 'user';
  if (role === 'platform_admin') {
    if (req.user.role !== 'platform_admin') {
      throw new AppError('Only platform admins can create platform admins', 403, 'FORBIDDEN_PLATFORM_ADMIN');
    }
    userRole = 'platform_admin';
  } else if (role === 'admin') { // role:platform-admin-skipped — assigning role STRING from req.body, not a caller-role check
    userRole = 'admin';
  }
  const userKind = kind === 'agent' ? 'agent' : 'human';
  const prefix = (userRole === 'admin' || userRole === 'platform_admin') ? 'dhk_admin' : 'dhk_user';
  const apiKey = generateApiKey(prefix);
  const keyHash = hashApiKey(apiKey);
  const pwHash = password ? hashPassword(password) : null;

  const db = getDb();

  // Check email uniqueness
  if (email) {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) throw new AppError('Email already registered', 409, 'DUPLICATE');
  }

  // Check username uniqueness
  if (username) {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) throw new AppError('Username already taken', 409, 'DUPLICATE');
  }

  const result = db.prepare(
    'INSERT INTO users (name, email, role, kind, api_key_hash, username, password_hash, avatar_url, phone, year_of_birth) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(name, email || null, userRole, userKind, keyHash, username || null, pwHash, avatar_url || null, phone || null, year_of_birth || null);

  res.json({
    user: { id: result.lastInsertRowid, name, email, role: userRole, kind: userKind },
    api_key: apiKey,
    warning: 'Save this API key! It will not be shown again.',
  });
});

/**
 * DELETE /api/users/:id - Delete user (admin only)
 */
router.delete('/:id', requireAdmin, auditMiddleware('user-delete'), (req, res) => {
  const db = getDb();
  const userId = parseInt(req.params.id);

  if (userId === 1) {
    throw new AppError('Cannot delete the owner account', 400, 'OWNER_PROTECTED');
  }

  if (userId === req.user.id) {
    throw new AppError('Cannot delete yourself', 400, 'SELF_DELETE');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

  // Delete related records first to avoid FK constraint failures
  db.transaction(() => {
    // NULL out non-cascading FK references to this user
    db.prepare('UPDATE apps SET created_by = NULL WHERE created_by = ?').run(userId);
    db.prepare('UPDATE deployments SET deployed_by = NULL WHERE deployed_by = ?').run(userId);
    db.prepare('UPDATE env_vars SET updated_by = NULL WHERE updated_by = ?').run(userId);
    db.prepare('UPDATE backups SET created_by = NULL WHERE created_by = ?').run(userId);
    db.prepare('UPDATE audit_log SET user_id = NULL WHERE user_id = ?').run(userId);
    // Delete cascading FK records
    db.prepare('DELETE FROM app_users WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM app_user_roles WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM notification_configs WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  })();
  res.json({ message: `User '${user.name}' deleted` });
});

/**
 * PUT /api/users/:id/role - Change a user's role (platform_admin only).
 *
 * Body: { role: 'platform_admin' | 'admin' | 'user' }
 *
 * Only platform_admin can call this. Guarded against demoting the last
 * platform_admin (would lock the org out of role-assignment forever) and
 * against self-demotion (use a different platform_admin to do that).
 */
router.put('/:id/role', requirePlatformAdmin, auditMiddleware('user-set-role'), (req, res) => {
  const db = getDb();
  const userId = parseInt(req.params.id);
  const { role } = req.body || {};

  if (!['platform_admin', 'admin', 'user'].includes(role)) {
    throw new AppError("role must be 'platform_admin', 'admin', or 'user'", 400, 'VALIDATION');
  }

  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(userId);
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

  if (user.role === 'platform_admin' && role !== 'platform_admin') {
    if (userId === req.user.id) {
      throw new AppError('Cannot demote yourself. Have another platform admin do it.', 400, 'SELF_DEMOTE');
    }
    const others = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'platform_admin' AND id != ?").get(userId);
    if (others.n === 0) {
      throw new AppError('Cannot demote the only platform admin', 400, 'LAST_PLATFORM_ADMIN');
    }
  }

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);
  res.json({ user: { id: userId, role } });
});

/**
 * POST /api/users/:id/regenerate-key - Generate new API key (admin only)
 */
router.post('/:id/regenerate-key', requireAdmin, auditMiddleware('user-regen-key'), (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.searchParams.get('confirm') !== 'true') {
    throw new AppError('This will invalidate the current key. Add ?confirm=true to proceed.', 400, 'CONFIRMATION_REQUIRED');
  }

  const db = getDb();
  const userId = parseInt(req.params.id);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

  // Block admin/platform_admin key regeneration via API -- use crane regenerate-key on server
  if (user.role === 'admin' || user.role === 'platform_admin') {
    throw new AppError('Admin keys cannot be regenerated via API. Run: crane regenerate-key --on the server.', 403, 'ADMIN_KEY_PROTECTED');
  }

  const prefix = (user.role === 'admin' || user.role === 'platform_admin') ? 'dhk_admin' : 'dhk_user';
  const apiKey = generateApiKey(prefix);
  const keyHash = hashApiKey(apiKey);

  db.prepare('UPDATE users SET api_key_hash = ? WHERE id = ?').run(keyHash, userId);
  db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(userId);

  res.json({
    user: { id: user.id, name: user.name, role: user.role },
    api_key: apiKey,
    warning: 'Save this API key! It will not be shown again.',
  });
});

/**
 * PUT /api/users/:id/password - Set/change password (admin only)
 */
router.put('/:id/password', requireAdmin, auditMiddleware('user-set-password'), (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 12) throw new AppError('Password must be at least 12 characters', 400, 'VALIDATION');

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id));
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

  const pwHash = hashPassword(password);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(pwHash, user.id);
  db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(user.id);

  res.json({ message: `Password set for ${user.name}` });
});

/**
 * PUT /api/users/:id/profile - Update user profile (admin only)
 */
router.put('/:id/profile', requireAdmin, auditMiddleware('user-update-profile'), (req, res) => {
  const { name, email, username, avatar_url, phone, year_of_birth, preferences } = req.body;
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id));
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

  const updates = [];
  const values = [];
  if (name !== undefined) { updates.push('name = ?'); values.push(name); }
  if (email !== undefined) { updates.push('email = ?'); values.push(email); }
  if (username !== undefined) { updates.push('username = ?'); values.push(username); }
  if (avatar_url !== undefined) { updates.push('avatar_url = ?'); values.push(avatar_url); }
  if (phone !== undefined) { updates.push('phone = ?'); values.push(phone); }
  if (year_of_birth !== undefined) { updates.push('year_of_birth = ?'); values.push(year_of_birth); }
  if (preferences !== undefined) { updates.push('preferences = ?'); values.push(typeof preferences === 'string' ? preferences : JSON.stringify(preferences)); }

  if (updates.length === 0) return res.json({ message: 'No changes' });

  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values, user.id);
  const updated = db.prepare('SELECT id, name, email, username, avatar_url, phone, year_of_birth, preferences FROM users WHERE id = ?').get(user.id);
  res.json({ user: updated });
});

/**
 * PUT /api/apps/:slug/roles - Set per-app role for a user.
 * Body: { user_id: 2, app_role: "owner" | "admin" | "user" | "none" }
 *
 * v2.7.9: global admins OR an owner of THIS app. Owners can grant up to
 * 'owner' (co-owners), but a last-owner guard prevents removing the final
 * owner so an app can't be left ownerless.
 */
router.put('/:slug/roles', requireAppAccess, auditMiddleware('app-set-role'), (req, res) => {
  const app = req.app; // set by requireAppAccess
  if (!isAdmin(req.user) && roleForUserOnApp(req.user, app) !== 'owner') {
    throw new AppError('Only the app owner can manage users on this app.', 403, 'FORBIDDEN');
  }

  const { user_id, app_role } = req.body;
  if (!user_id || !app_role) throw new AppError('user_id and app_role required', 400, 'VALIDATION');
  if (!['owner', 'admin', 'user', 'none'].includes(app_role)) throw new AppError('app_role must be owner, admin, user, or none', 400, 'VALIDATION');

  const db = getDb();

  // Last-owner guard: don't let the final owner be demoted/removed.
  if (app_role !== 'owner') {
    const target = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user_id);
    if (target?.app_role === 'owner') {
      const owners = db.prepare("SELECT COUNT(*) AS n FROM app_user_roles WHERE app_id = ? AND app_role = 'owner'").get(app.id);
      if (owners.n <= 1) throw new AppError('Cannot remove the last owner of the app. Assign another owner first.', 400, 'LAST_OWNER');
    }
  }

  db.prepare(`
    INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
    ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role
  `).run(app.id, user_id, app_role);

  // Keep app_users in sync so API-key based flows also see this user's apps
  db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(app.id, user_id);

  res.json({ message: `Role '${app_role}' set for user ${user_id} on app ${app.slug}` });
});

/**
 * GET /api/apps/:slug/identity/users - List all users + roles for an app.
 * v2.7.9: global admins OR an owner of this app.
 */
router.get('/:slug/identity/users', requireAppAccess, (req, res) => {
  const app = req.app; // set by requireAppAccess
  if (!isAdmin(req.user) && roleForUserOnApp(req.user, app) !== 'owner') {
    throw new AppError('Only the app owner can view users on this app.', 403, 'FORBIDDEN');
  }
  const db = getDb();

  const users = db.prepare(`
    SELECT u.id, u.name, u.email, u.username, u.avatar_url, u.phone, u.year_of_birth,
      COALESCE(aur.app_role, 'none') as app_role
    FROM users u
    LEFT JOIN app_user_roles aur ON u.id = aur.user_id AND aur.app_id = ?
    WHERE u.role NOT IN ('admin', 'platform_admin')
    ORDER BY u.name
  `).all(app.id);

  res.json({ app: app.slug, users });
});

export default router;
