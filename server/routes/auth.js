import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { userHasPlatformPermission } from '../services/permissions.js';

const router = Router();

/**
 * GET /api/auth/me
 * Return current user info based on API key.
 */
router.get('/me', requireAuth, (req, res) => {
  const { id, name, email, role, created_at } = req.user;
  const db = getDb();

  // Get assigned apps for non-admin users
  let apps = [];
  if (role === 'user') {
    apps = db.prepare(`
      SELECT a.slug, a.name, a.domain FROM apps a
      WHERE a.id IN (
        SELECT app_id FROM app_users WHERE user_id = ?
        UNION
        SELECT app_id FROM app_user_roles WHERE user_id = ?
      )
    `).all(id, id);
  } else {
    apps = db.prepare('SELECT slug, name, domain FROM apps').all();
  }

  const can_create_apps = userHasPlatformPermission(req.user, 'platform.create_app');
  // v2.18.0: surface the directory attributes inherited from the IdP (SCIM).
  const dir = db.prepare('SELECT department, region, location FROM users WHERE id = ?').get(id) || {};
  res.json({
    user: {
      id, name, email, role, created_at, can_create_apps,
      department: dir.department || null,
      region:     dir.region || null,
      location:   dir.location || null,
    },
    apps,
  });
});

export default router;
