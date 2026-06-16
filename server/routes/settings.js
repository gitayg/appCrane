import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { PERMISSIONS, getMatrix, setMatrix, resetToDefaults } from '../services/permissions.js';
import { ssoProviderConfigured } from '../services/authPolicy.js';
import { encrypt } from '../services/encryption.js';

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
  'github_service_token_enc',
  'graph_client_secret_encrypted',
]);

/**
 * v2.7.8: keys kept OUT of the bulk public dump but still readable via the
 * targeted GET /:key. `auth_sso_only` must stay readable by the
 * unauthenticated login page (it decides whether to hide the password form),
 * so it can't be gated — but it's auth policy, not general branding/config,
 * so we don't enumerate it in the catch-all settings list.
 */
const BULK_EXCLUDED_KEYS = new Set(['auth_sso_only']);

/**
 * GET /api/settings - All non-sensitive settings (public — agents need branding)
 */
router.get('/', (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const settings = {};
  for (const row of rows) {
    if (SENSITIVE_KEYS.has(row.key) || BULK_EXCLUDED_KEYS.has(row.key)) continue;
    settings[row.key] = row.value;
  }
  res.json({ settings });
});

// ── Configurable RBAC matrix ───────────────────────────────────────────
//
// /api/settings/role-permissions GET (any authed) returns the catalog +
// current matrix. PUT (admin) bulk-updates. POST /reset (admin) restores
// the seeded defaults.
//
// IMPORTANT: these routes MUST be registered before the generic /:key
// handlers below — otherwise PUT /:key captures /role-permissions first
// and rejects the body with "value required" (the matrix payload has no
// `value` field).

router.get('/role-permissions/catalog', requireAuth, (req, res) => {
  res.json({
    permissions: PERMISSIONS,
    matrix: getMatrix(),
    roles: ['user', 'admin', 'owner', 'platform_admin'],
  });
});

router.put('/role-permissions', requireAuth, requirePlatformAdmin, (req, res) => {
  const { matrix } = req.body || {};
  if (!matrix || typeof matrix !== 'object') {
    return res.status(400).json({ error: { code: 'VALIDATION', message: 'matrix required' } });
  }
  setMatrix(matrix);
  res.json({ matrix: getMatrix() });
});

router.post('/role-permissions/reset', requireAuth, requirePlatformAdmin, (req, res) => {
  const { permissions } = req.body || {};
  resetToDefaults(Array.isArray(permissions) ? permissions : null);
  res.json({ matrix: getMatrix() });
});

// ── Mail configuration (v2.8.0) ────────────────────────────────────────
//
// Microsoft Graph send-as-mailbox config for the app email service. The
// client secret is stored encrypted (graph_client_secret_encrypted, in
// SENSITIVE_KEYS) and never returned — the GET reports only whether it's set.
// Must be registered before the generic /:key handlers.

const MAIL_KEYS = {
  graph_tenant_id:   'tenant_id',
  graph_client_id:   'client_id',
  email_from_address:'from_address',
  email_from_name:   'from_name',
};

router.get('/mail/config', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const get = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? '';
  const out = {};
  for (const [key, field] of Object.entries(MAIL_KEYS)) out[field] = get(key);
  out.client_secret_set = !!get('graph_client_secret_encrypted');
  out.configured = !!(out.tenant_id && out.client_id && out.client_secret_set && out.from_address);
  res.json({ mail: out });
});

router.put('/mail/config', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const body = req.body || {};
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `);
  for (const [key, field] of Object.entries(MAIL_KEYS)) {
    if (body[field] !== undefined) upsert.run(key, String(body[field] ?? '').trim(), req.user.id);
  }
  // client_secret: only write when a non-empty value is supplied (so a save
  // that leaves the field blank doesn't wipe the stored secret). Encrypted.
  if (typeof body.client_secret === 'string' && body.client_secret.trim()) {
    upsert.run('graph_client_secret_encrypted', encrypt(body.client_secret.trim()), req.user.id);
  }
  res.json({ message: 'Mail settings saved' });
});

// Send a test email to the calling admin via the live transport + queue path.
router.post('/mail/test', requireAuth, requirePlatformAdmin, async (req, res) => {
  if (!req.user.email) throw new Error('Your account has no email address to send a test to');
  const { enqueueEmail } = await import('../services/emailQueue.js');
  const { id } = enqueueEmail({
    to: req.user.email,
    subject: '[AppCrane] Mail configuration test',
    text: 'This is a test email from AppCrane. If you received it, the mail service is configured correctly.',
    source: 'test',
  });
  res.json({ message: `Test email queued to ${req.user.email} (queue #${id}). Check your inbox shortly.`, queue_id: id });
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
router.put('/:key', requireAuth, requirePlatformAdmin, (req, res) => {
  const { value } = req.body;
  if (value === undefined) return res.status(400).json({ error: { code: 'VALIDATION', message: 'value required' } });
  const db = getDb();

  // v2.7.0: guard SSO-only so it can't lock the org out. Refuse to turn it
  // on unless an SSO provider (OIDC or SAML) is already enabled.
  if (req.params.key === 'auth_sso_only' && String(value) === 'true' && !ssoProviderConfigured(db)) {
    return res.status(400).json({
      error: { code: 'NO_SSO_PROVIDER', message: 'Enable and configure an SSO provider (OIDC or SAML) before requiring SSO-only login.' },
    });
  }

  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(req.params.key, String(value), req.user.id);
  res.json({ key: req.params.key, value, message: 'Setting saved' });
});

export default router;
