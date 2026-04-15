import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';

const router = Router();

/**
 * Keys that must never be returned to any caller, authenticated or not.
 * Includes all hashed credentials, encrypted secrets, and token material.
 */
const SENSITIVE_KEYS = new Set([
  'oidc_client_secret_enc',
  'saml_idp_cert_enc',
  'scim_token_hash',
  'scim_token_created_at',
]);

/**
 * GET /api/settings - All non-sensitive settings (public — agents need branding)
 */
router.get('/', (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const settings = {};
  for (const row of rows) {
    if (SENSITIVE_KEYS.has(row.key)) continue;
    settings[row.key] = row.value;
  }
  res.json({ settings });
});

/**
 * GET /api/settings/:key - Single setting (public, sensitive keys blocked)
 */
router.get('/:key', (req, res) => {
  if (SENSITIVE_KEYS.has(req.params.key)) {
    return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Access to this setting is restricted' } });
  }
  const db = getDb();
  const row = db.prepare('SELECT value, updated_at FROM settings WHERE key = ?').get(req.params.key);
  res.json({ key: req.params.key, value: row ? row.value : null, updated_at: row?.updated_at || null });
});

/**
 * PUT /api/settings/:key - Upsert a setting (admin only)
 */
router.put('/:key', requireAuth, requireAdmin, (req, res) => {
  const { value } = req.body;
  if (value === undefined) return res.status(400).json({ error: { code: 'VALIDATION', message: 'value required' } });
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(req.params.key, String(value), req.user.id);
  res.json({ key: req.params.key, value, message: 'Setting saved' });
});

export default router;
