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

// ── Data backup / restore (v2.9.0, streamed since v2.74.0) — platform_admin only
//
// The data archive (DB + .env + icons + /data + declared volumes) contains the
// ENCRYPTION_KEY and every encrypted secret, so every route is
// platform-admin-gated. Registered before the generic /:key handlers.
//
// Nothing here holds an archive in memory: exports are written to disk by a
// spawned tar, downloads are piped from that file, uploads are streamed to disk
// by multer's diskStorage, and imports read the file. See services/configBackup.js.

// In-flight backup jobs (data and repo exports). Opaque ids; looked up only by
// a platform admin who was handed the id.
const backupJobs = new Map();

async function newBackupJob(kind, fields) {
  const { randomBytes } = await import('crypto');
  const id = randomBytes(16).toString('base64url');
  const job = { id, kind, state: 'running', started_at: new Date().toISOString(), result: null, error: null, ...fields };
  backupJobs.set(id, job);
  return job;
}

const finishJob = (job, p) => p
  .then((r) => { job.result = r; job.state = 'done'; job.finished_at = new Date().toISOString(); })
  .catch((e) => { job.error = e.message; job.state = 'failed'; job.finished_at = new Date().toISOString(); });

// Browser download (the Settings page). Written to a private temp file, piped
// to the response, deleted when the response ends — the backups directory is
// not left holding a key-bearing file nobody asked to keep.
router.get('/config/export', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { exportDataArchive } = await import('../services/configBackup.js');
  const { newWorkDir } = await import('../services/backupFiles.js');
  const { createReadStream } = await import('fs');
  const { rm } = await import('fs/promises');
  const { join } = await import('path');
  const work = await newWorkDir('download');
  const cleanup = () => rm(work, { recursive: true, force: true }).catch(() => {});
  let out;
  try {
    const at = new Date();
    const { dataArchiveFileName } = await import('../services/configBackup.js');
    out = await exportDataArchive({ at, dest: join(work, 'export.tar.gz') });
    const host = (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '');
    out.file = dataArchiveFileName(host, out.manifest.image_set?.fingerprint, at);
  } catch (e) {
    await cleanup();
    return res.status(e.status || 500).json({ error: { code: 'EXPORT_FAILED', message: e.message } });
  }
  res.setHeader('Content-Type', 'application/gzip');
  res.setHeader('Content-Disposition', `attachment; filename="${out.file}"`);
  res.setHeader('Content-Length', out.bytes);
  const stream = createReadStream(out.path);
  res.on('close', () => { stream.destroy(); cleanup(); });
  stream.pipe(res);
});

// On-host export, kept in DATA_DIR/backups. Returns a job; poll GET /config/export/:id.
router.post('/config/export', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { exportDataArchive } = await import('../services/configBackup.js');
  const job = await newBackupJob('data-export', {});
  finishJob(job, exportDataArchive({ force: !!(req.body || {}).force }));
  res.status(202).json({ job_id: job.id, state: job.state });
});

router.get('/config/export/:id', requireAuth, requirePlatformAdmin, (req, res) => {
  const job = backupJobs.get(req.params.id);
  if (!job || job.kind !== 'data-export') return res.status(404).json({ error: { code: 'NO_SUCH_JOB', message: 'Unknown export job' } });
  const r = job.result ? { path: job.result.path, file: job.result.file, bytes: job.result.bytes, warnings: job.result.warnings, manifest: job.result.manifest } : null;
  res.json({ job_id: job.id, state: job.state, started_at: job.started_at, finished_at: job.finished_at || null, result: r, error: job.error });
});

// ── Managed-app repository archives (v2.74.0) — platform_admin only ─────
//
// One archive per host-local repo, written to DATA_DIR/backups and restored
// from a path confined there, one repo at a time. See services/repoArchive.js.

router.get('/repos/plan', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { planRepoArchives } = await import('../services/repoArchive.js');
  try {
    res.json(await planRepoArchives());
  } catch (e) {
    res.status(400).json({ error: { code: 'PLAN_FAILED', message: e.message } });
  }
});

router.post('/repos/export', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { exportRepoArchives } = await import('../services/repoArchive.js');
  const { SLUG_RE } = await import('../services/backupFiles.js');
  const body = req.body || {};
  let slugs;
  if (body.slugs !== undefined) {
    if (!Array.isArray(body.slugs) || !body.slugs.every((s) => typeof s === 'string' && SLUG_RE.test(s))) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'slugs must be an array of app slugs' } });
    }
    slugs = body.slugs;
  }
  const job = await newBackupJob('repo-export', { progress: null });
  finishJob(job, exportRepoArchives({ slugs, onProgress: (p) => { job.progress = p; } }));
  res.status(202).json({ job_id: job.id, state: job.state });
});

router.get('/repos/export/:id', requireAuth, requirePlatformAdmin, (req, res) => {
  const job = backupJobs.get(req.params.id);
  if (!job || job.kind !== 'repo-export') return res.status(404).json({ error: { code: 'NO_SUCH_JOB', message: 'Unknown export job' } });
  res.json({ job_id: job.id, state: job.state, started_at: job.started_at, finished_at: job.finished_at || null, progress: job.progress, result: job.result, error: job.error });
});

// Restore ONE repo. `slug` is required and must match the archive, so an
// archive cannot be restored over a different app by mistake.
router.post('/repos/import', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { importRepoArchive } = await import('../services/repoArchive.js');
  const { SLUG_RE } = await import('../services/backupFiles.js');
  const { path, slug } = req.body || {};
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) {
    return res.status(400).json({ error: { code: 'VALIDATION', message: 'slug required (the app whose repository this archive restores)' } });
  }
  try {
    res.json(await importRepoArchive(path, { slug }));
  } catch (e) {
    res.status(e.status || 400).json({ error: { code: 'IMPORT_FAILED', message: e.message } });
  }
});

router.get('/repos/verify', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { verifyRepoSet } = await import('../services/repoArchive.js');
  try {
    res.json(await verifyRepoSet());
  } catch (e) {
    res.status(400).json({ error: { code: 'VERIFY_FAILED', message: e.message } });
  }
});

// ── Offline image archive (v2.72.0) — platform_admin only ──────────────
//
// The config zip above restores configuration and data. It does NOT contain the
// container images, and a restore that re-pulls them fails outright when the
// publisher has removed the image — bitnami/* 404 since their registry change,
// and medusajs/medusa, vendureio/vendure and crater/crater 404 today. These
// routes save the bytes the live deployments actually ran.
//
// The archive is 5-30 GB on a real box, so nothing here streams image bytes
// through Express: the export writes a file with `docker save -o` and answers
// with its path, and the import reads a path on the host. Copy the file with
// scp/rsync, which is the right tool for that size; a 30 GB browser download
// through Caddy is not.

// In-flight exports. Opaque ids (never Date.now() or a counter) and the job
// is looked up only by a platform admin who was handed the id.
const imageExportJobs = new Map();

router.get('/images/plan', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { planImageArchive } = await import('../services/imageArchive.js');
  try {
    res.json(await planImageArchive(req.query.scope || 'live'));
  } catch (e) {
    res.status(400).json({ error: { code: 'PLAN_FAILED', message: e.message } });
  }
});

// Starts the save and returns immediately. A 30 GB `docker save` outlives any
// sane HTTP timeout, so the response is a job id rather than a result; poll
// GET /images/export/:id, whose progress is the destination file's size on disk
// — a real measurement, not a guess from the writer.
router.post('/images/export', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { planImageArchive, exportImageArchive } = await import('../services/imageArchive.js');
  const scope = (req.body || {}).scope || 'live';
  let plan;
  try {
    plan = await planImageArchive(scope);
  } catch (e) {
    return res.status(400).json({ error: { code: 'PLAN_FAILED', message: e.message } });
  }

  const { randomBytes } = await import('crypto');
  const { archiveFileName, archiveDir } = await import('../services/imageArchive.js');
  const { join } = await import('path');
  const id = randomBytes(16).toString('base64url');
  // One timestamp for the whole job. The filename carries a date, so deriving
  // it twice would name two different files either side of a UTC midnight and
  // the progress poll would stat one that is never written.
  const at = new Date();
  const destPath = join(archiveDir(), archiveFileName(plan.fingerprint, at));
  const job = { id, scope, state: 'running', started_at: at.toISOString(), dest_path: destPath, plan, result: null, error: null };
  imageExportJobs.set(id, job);

  exportImageArchive({ scope, at, force: !!(req.body || {}).force })
    .then((r) => { job.result = r; job.state = 'done'; job.finished_at = new Date().toISOString(); })
    .catch((e) => { job.error = e.message; job.state = 'failed'; job.finished_at = new Date().toISOString(); });

  res.status(202).json({
    job_id: id, state: 'running', scope,
    estimated_bytes: plan.estimated_bytes, required_bytes: plan.required_bytes, free_bytes: plan.free_bytes,
    images: plan.included, missing: plan.missing.length, fingerprint: plan.fingerprint,
    expected_path: destPath,
  });
});

router.get('/images/export/:id', requireAuth, requirePlatformAdmin, async (req, res) => {
  const job = imageExportJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: { code: 'NO_SUCH_JOB', message: 'Unknown export job' } });
  // Progress is the destination file's real size, not a number the writer
  // reports about itself — `docker save -o` writes the file directly and this
  // process never sees a byte of it.
  let bytesWritten = null;
  if (job.state === 'running') {
    const { statSync } = await import('fs');
    try { bytesWritten = statSync(job.dest_path).size; } catch (_) { bytesWritten = 0; }
  }
  res.json({
    job_id: job.id, state: job.state, scope: job.scope, path: job.dest_path,
    started_at: job.started_at, finished_at: job.finished_at || null,
    estimated_bytes: job.plan.estimated_bytes,
    bytes_written: bytesWritten,
    result: job.result, error: job.error,
  });
});

// Load an archive that is already on this host. Takes a PATH, not an upload:
// multer's memoryStorage would put the whole archive in this process's heap,
// which is the exact failure the separate artifact exists to avoid. The path is
// confined to the backups directory so an admin cannot make the daemon read an
// arbitrary file through this route.
router.post('/images/import', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { importImageArchive, archiveDir, verifyImageSet } = await import('../services/imageArchive.js');
  const { resolve, join, basename } = await import('path');
  const raw = String((req.body || {}).path || '').trim();
  if (!raw) return res.status(400).json({ error: { code: 'VALIDATION', message: 'path required (the .tar on this host)' } });

  const dir = resolve(archiveDir());
  const abs = resolve(raw.includes('/') ? raw : join(dir, raw));
  if (abs !== dir && !abs.startsWith(dir + '/')) {
    return res.status(400).json({
      error: { code: 'VALIDATION', message: `archive must be inside ${dir} (got ${basename(abs)} elsewhere)` },
    });
  }
  try {
    const loadResult = await importImageArchive(abs);
    const verification = await verifyImageSet('live');
    res.json({
      ...loadResult,
      verification: {
        checked: verification.checked,
        restorable: verification.restorable,
        unrestorable: verification.unrestorable,
        expected_fingerprint: verification.expected_fingerprint,
        present_fingerprint: verification.present_fingerprint,
        matched: verification.expected_fingerprint === verification.present_fingerprint,
      },
    });
  } catch (e) {
    res.status(400).json({ error: { code: 'IMPORT_FAILED', message: e.message } });
  }
});

// Does this host hold what the restored DB says is running? The pair check.
router.get('/images/verify', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { verifyImageSet } = await import('../services/imageArchive.js');
  try {
    const v = await verifyImageSet(req.query.scope || 'live');
    res.json({ ...v, matched: v.expected_fingerprint === v.present_fingerprint });
  } catch (e) {
    res.status(400).json({ error: { code: 'VERIFY_FAILED', message: e.message } });
  }
});

// ── Scheduled off-site (S3) backup config — platform_admin only (v2.21.9) ──
//
// v2.79.0: the payload carries `off_site` beside the raw config. The fields
// were always enough to WORK OUT that nothing is being uploaded — bucket empty,
// last_run null — and the dashboard rendered neither, so the honest state was
// derivable and invisible. It is now a sentence the API states, so the SPA
// renders the same words the MCP status tool returns instead of composing its
// own. The existing flat fields are untouched: they are what the Settings form
// binds to.
router.get('/backup/s3', requireAuth, requirePlatformAdmin, async (_req, res) => {
  const { getBackupConfig, offSiteState } = await import('../services/backupScheduler.js');
  res.json({ ...getBackupConfig(), off_site: offSiteState() });
});

router.put('/backup/s3', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { setBackupConfig, offSiteState } = await import('../services/backupScheduler.js');
  const cfg = setBackupConfig(req.body || {}, req.user.id);
  res.json({ ...cfg, off_site: offSiteState() });
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

// ── Scheduled LOCAL backup — platform_admin only (v2.79.0) ─────────────────
//
// On by default, unlike the off-site schedule, which is a no-op until someone
// enters credentials. Same gate as the off-site config: a local archive holds
// the ENCRYPTION_KEY and every encrypted secret, so listing and triggering it
// is not an app-owner operation.
router.get('/backup/local', requireAuth, requirePlatformAdmin, async (_req, res) => {
  const { getLocalBackupConfig, listLocalBackups } = await import('../services/localBackup.js');
  const { offSiteState } = await import('../services/backupScheduler.js');
  res.json({ ...getLocalBackupConfig(), archives: await listLocalBackups(), off_site: offSiteState() });
});

router.put('/backup/local', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { setLocalBackupConfig, listLocalBackups } = await import('../services/localBackup.js');
  const { offSiteState } = await import('../services/backupScheduler.js');
  const cfg = setLocalBackupConfig(req.body || {}, req.user.id);
  res.json({ ...cfg, archives: await listLocalBackups(), off_site: offSiteState() });
});

router.post('/backup/local/run', requireAuth, requirePlatformAdmin, async (_req, res) => {
  const { runLocalBackup, listLocalBackups } = await import('../services/localBackup.js');
  try {
    const r = await runLocalBackup();
    res.json({ ok: true, ...r, archives: await listLocalBackups() });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// Restore a data archive. Two ways in:
//   - multipart upload (field `file`, the Settings page): streamed to a private
//     file under DATA_DIR/backups by multer's diskStorage, imported, deleted.
//   - JSON { path }: an archive already in DATA_DIR/backups (scp'd there),
//     confined to that directory.
//
// v2.74.0: the 200 MB cap is gone. It existed because the upload was held in
// memory; it now goes to disk, so the limit that matters is disk. The upload
// is refused up front when Content-Length exceeds free space minus a reserve,
// and multer's fileSize is set to that same figure so a request that lies
// about its length (or is chunked) is cut off before it fills the disk.
export const UPLOAD_DISK_RESERVE = 1024 * 1024 * 1024;

router.post('/config/import', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { importDataArchive } = await import('../services/configBackup.js');
  const { ensureBackupsDir, freeBytes, confineToBackups } = await import('../services/backupFiles.js');
  const { rm } = await import('fs/promises');
  const restoreEnv = req.query.restore_env !== '0' && (req.body || {}).restore_env !== false;

  // The uploaded copy is removed BEFORE answering, so a client that sees the
  // response never sees a key-bearing temp file still on disk.
  const runImport = async (path, cleanup) => {
    let result;
    let error;
    try {
      result = await importDataArchive(path, { restoreEnv });
    } catch (e) {
      error = e;
    }
    if (cleanup) await rm(path, { force: true }).catch(() => {});
    if (error) return res.status(error.status || 400).json({ error: { code: 'IMPORT_FAILED', message: error.message } });
    res.json({ message: 'Backup imported. The server will restart now to load the restored database.', ...result });
    // better-sqlite3 holds the old DB open; restart so the imported one
    // takes effect. systemd brings the process back up. Delay so the
    // response flushes first.
    if (!process.env.APPCRANE_NO_RESTART_AFTER_IMPORT) setTimeout(() => process.exit(0), 1200);
  };

  if (!req.is('multipart/form-data')) {
    let abs;
    try { abs = await confineToBackups((req.body || {}).path); } catch (e) {
      return res.status(e.status || 400).json({ error: { code: 'VALIDATION', message: e.message } });
    }
    return runImport(abs, false);
  }

  const dir = await ensureBackupsDir();
  const free = freeBytes(dir);
  const allowed = free === null ? Infinity : Math.max(0, free - UPLOAD_DISK_RESERVE);
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > allowed) {
    return res.status(507).json({ error: { code: 'INSUFFICIENT_STORAGE', message: `Upload of ${declared} bytes does not fit: ${free} bytes free in ${dir}, ${UPLOAD_DISK_RESERVE} kept in reserve.` } });
  }
  const multer = (await import('multer')).default;
  const { randomBytes } = await import('crypto');
  const storage = multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, dir),
    filename: (_r, _f, cb) => cb(null, `.upload-${randomBytes(12).toString('hex')}.part`),
  });
  const upload = multer({ storage, limits: { fileSize: Number.isFinite(allowed) ? allowed : undefined, files: 1 } }).single('file');
  upload(req, res, async (err) => {
    if (err) {
      if (req.file?.path) await rm(req.file.path, { force: true }).catch(() => {});
      return res.status(err.code === 'LIMIT_FILE_SIZE' ? 507 : 400).json({ error: { code: 'UPLOAD_ERROR', message: err.message } });
    }
    if (!req.file) return res.status(400).json({ error: { code: 'NO_FILE', message: 'No backup file uploaded (field name: file)' } });
    return runImport(req.file.path, true);
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
