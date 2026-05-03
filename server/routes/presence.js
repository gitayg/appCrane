import { Router } from 'express';
import { hashApiKey } from '../services/encryption.js';
import { getDb } from '../db.js';

const router = Router();

// In-memory: { [slug]: { [userId]: { name, lastSeen } } }
const viewers = {};
const TTL_MS = 30000;

function pruneSlug(slug) {
  const now = Date.now();
  const slot = viewers[slug];
  if (!slot) return;
  for (const uid of Object.keys(slot)) {
    if (now - slot[uid].lastSeen > TTL_MS) delete slot[uid];
  }
  if (Object.keys(slot).length === 0) delete viewers[slug];
}

function resolveUser(req) {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;
  try {
    const tokenHash = hashApiKey(token);
    const db = getDb();
    const row = db.prepare(`
      SELECT u.id, u.name FROM identity_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
    `).get(tokenHash);
    return row || null;
  } catch (_) { return null; }
}

/**
 * POST /api/presence/ping
 * Body: { slug }
 * Returns: { viewers: [{ name }] } — others on the same slug
 */
router.post('/ping', (req, res) => {
  const user = resolveUser(req);
  if (!user) return res.json({ viewers: [] });

  const { slug } = req.body || {};
  if (!slug) return res.json({ viewers: [] });

  pruneSlug(slug);
  if (!viewers[slug]) viewers[slug] = {};
  viewers[slug][user.id] = { name: user.name, lastSeen: Date.now() };

  const others = Object.entries(viewers[slug])
    .filter(([uid]) => Number(uid) !== user.id)
    .map(([, v]) => ({ name: v.name }));

  res.json({ viewers: others });
});

export default router;
