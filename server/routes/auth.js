import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';

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
      JOIN app_users au ON a.id = au.app_id
      WHERE au.user_id = ?
    `).all(id);
  } else {
    apps = db.prepare('SELECT slug, name, domain FROM apps').all();
  }

  res.json({ user: { id, name, email, role, created_at }, apps });
});

export default router;
