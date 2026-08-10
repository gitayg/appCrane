import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { PERMISSIONS, getMatrix, setMatrix, resetToDefaults } from '../services/permissions.js';
import { ssoProviderConfigured } from '../services/authPolicy.js';
import { encrypt } from '../services/encryption.js';
import { reloadCaddy } from '../services/caddy.js';
import { platformEmbedAncestors, platformRegistrableDomain } from '../utils/embed.js';
import { settingVisibility, PUBLIC, AUTHED } from '../utils/settingsVisibility.js';

const router = Router();

/**
 * Keys that must never be returned to any caller, authenticated or not.
 * Includes all hashed credentials, encrypted secrets, and token material.
 *
 * This is belt-and-braces on top of settingsVisibility.js: those keys are
 * already ADMIN-by-default there, and this set means even a platform admin
 * can't pull the ciphertext back out through the generic settings reader.
 */
const SENSITIVE_KEYS = new Set([
  'oidc_client_secret_enc',
  'saml_idp_cert_enc',
  'scim_token_hash',
  'scim_token_created_at',
  'github_service_token_enc',
  'graph_client_secret_encrypted',
  'backup_s3_secret_enc',
]);

/**
 * v2.7.8: keys kept out of the bulk dump but still readable via the targeted
 * GET /:key. `auth_sso_only` is auth policy read by the unauthenticated login
 * page, not general config, so it doesn't belong in the catch-all list.
 */
const BULK_EXCLUDED_KEYS = new Set(['auth_sso_only']);

/**
 * Enforce the per-key read visibility from settingsVisibility.js.
 *
 * Applied to GET /:key, which previously had NO middleware of its own. The 401
 * an anonymous caller saw came from logs.js doing `router.use(requireAuth)` on
 * the broader '/api' mount registered ahead of '/api/settings' — accidental
 * gating that would evaporate if those two mounts were ever reordered. This
 * makes the gate explicit and per-key.
 */
function requireSettingVisibility(req, res, next) {
  const level = settingVisibility(req.params.key);
  if (level === PUBLIC) return next();
  requireAuth(req, res, (err) => {
    if (err) return next(err);
    if (level === AUTHED) return next();
    requirePlatformAdmin(req, res, next);
  });
}

/**
 * GET /api/settings - All non-sensitive settings (platform admin only).
 *
 * v2.38.0: was ungated. It dumps every non-denylisted row, so a drifted
 * denylist turns into a full config disclosure — which is exactly how the S3
 * backup credentials leaked. Nothing in the SPA, the server, or the agent
 * pipeline reads the bulk endpoint, so it's admin-only now.
 */
router.get('/', requireAuth, requirePlatformAdmin, (req, res) => {
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
// /api/settings/role-permissions GET returns the catalog + current matrix.
// PUT (admin) bulk-updates. POST /reset (admin) restores the seeded defaults.
//
// v2.38.0: the GET was requireAuth-only, so any authenticated user could read
// the whole RBAC matrix — a map of which role can do what, i.e. free privilege-
// escalation reconnaissance. Its only caller is the platform-admin-gated
// Settings page (studio-web/src/pages/Settings.tsx), so it's admin-only now.
//
// IMPORTANT: these routes MUST be registered before the generic /:key
// handlers below — otherwise PUT /:key captures /role-permissions first
// and rejects the body with "value required" (the matrix payload has no
// `value` field).

router.get('/role-permissions/catalog', requireAuth, requirePlatformAdmin, (req, res) => {
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

// ── Config backup / restore (v2.9.0) — platform_admin only ──────────────
//
// Export the whole-system config (DB + .env + icons) as one zip, and import
// it back onto a fresh host. The bundle contains the ENCRYPTION_KEY and every
// encrypted secret, so both routes are platform-admin-gated. Registered before
// the generic /:key handlers.

router.get('/config/export', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { exportConfig } = await import('../services/configBackup.js');
  const { buffer, manifest } = exportConfig();
  const host = (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '');
  const date = manifest.exported_at.slice(0, 10);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="appcrane-backup-${host}-${date}.zip"`);
  res.setHeader('Content-Length', buffer.length);
  res.end(buffer);
});

// ── Scheduled off-site (S3) backup config — platform_admin only (v2.21.9) ──
router.get('/backup/s3', requireAuth, requirePlatformAdmin, async (_req, res) => {
  const { getBackupConfig } = await import('../services/backupScheduler.js');
  res.json(getBackupConfig());
});

router.put('/backup/s3', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { setBackupConfig } = await import('../services/backupScheduler.js');
  res.json(setBackupConfig(req.body || {}, req.user.id));
});

router.post('/backup/s3/run', requireAuth, requirePlatformAdmin, async (_req, res) => {
  const { runS3Backup } = await import('../services/backupScheduler.js');
  try {
    const r = await runS3Backup();
    res.json({ ok: true, ...r });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/config/import', requireAuth, requirePlatformAdmin, async (req, res) => {
  const multer = (await import('multer')).default;
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } }).single('file');
  upload(req, res, async (err) => {
    if (err) return res.status(400).json({ error: { code: 'UPLOAD_ERROR', message: err.message } });
    if (!req.file) return res.status(400).json({ error: { code: 'NO_FILE', message: 'No backup file uploaded (field name: file)' } });
    try {
      const { importConfig } = await import('../services/configBackup.js');
      const restoreEnv = req.query.restore_env !== '0';
      const result = importConfig(req.file.buffer, { restoreEnv });
      res.json({
        message: 'Backup imported. The server will restart now to load the restored database.',
        ...result,
      });
      // better-sqlite3 holds the old DB open; restart so the imported one
      // takes effect. systemd brings the process back up. Delay so the
      // response flushes first.
      setTimeout(() => process.exit(0), 1200);
    } catch (e) {
      res.status(400).json({ error: { code: 'IMPORT_FAILED', message: e.message } });
    }
  });
});

/**
 * GET /api/settings/embed/config — same-site iframe embedding policy (v2.25.0).
 * Apps are embeddable by any host under the platform's own registrable domain
 * unless this is turned off. Platform-admin only.
 */
router.get('/embed/config', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const get = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value;
  res.json({
    enabled: (get('platform_embed_same_site') ?? 'on') !== 'off',
    domain_override: get('platform_embed_domain') || '',
    derived_domain: platformRegistrableDomain() || '',
    effective: platformEmbedAncestors(db) || '',
  });
});

/**
 * PUT /api/settings/embed/config  { enabled, domain_override } — platform-admin.
 * Reloads Caddy so the change lands on the live per-app frame-ancestors blocks.
 */
router.put('/embed/config', requireAuth, requirePlatformAdmin, async (req, res) => {
  const db = getDb();
  const { enabled, domain_override } = req.body || {};
  const upsert = db.prepare(
    `INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`
  );
  if (enabled !== undefined) upsert.run('platform_embed_same_site', enabled ? 'on' : 'off', req.user.id);
  if (domain_override !== undefined) {
    const d = String(domain_override || '').trim().toLowerCase();
    if (d && !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(d)) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'domain_override must be a bare hostname like example.com' } });
    }
    upsert.run('platform_embed_domain', d, req.user.id);
  }
  await reloadCaddy().catch(() => {});
  res.json({ ok: true, effective: platformEmbedAncestors(db) || '' });
});

/**
 * GET /api/settings/:key - Single setting, gated by its classified visibility
 * (PUBLIC / AUTHED / ADMIN, defaulting to ADMIN). See settingsVisibility.js.
 *
 * The SENSITIVE_KEYS check runs AFTER the gate so an anonymous caller gets a
 * plain 401 rather than a 403 that confirms the key names a stored secret.
 */
router.get('/:key', requireSettingVisibility, (req, res) => {
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
