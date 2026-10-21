/**
 * v2.21.9: scheduled off-site backups to S3 (or S3-compatible, e.g. R2).
 *
 * It's a no-op until an operator enters bucket + credentials in Settings →
 * Backup, so it's safe to ship before S3 is set up.
 *
 * Each run uploads one backup SET (see backupS3Sets.js): the full data archive
 * (SQLite DB + .env + icons + per-app /data + declared volumes + managed
 * database dumps), one archive per managed-app git repository, and a manifest
 * with the SHA-256 of every object, written last. Uploads stream from disk as
 * multipart uploads (s3.js). Optional client-side encryption uses a key
 * derived from ENCRYPTION_KEY; optional SSE-S3 / SSE-KMS headers ask the
 * bucket to encrypt at rest. After a successful upload, retention keeps N
 * daily / M weekly / K monthly sets of THIS host and deletes the rest.
 */
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import { createReadStream } from 'fs';
import { rm } from 'fs/promises';
import { join, basename } from 'path';
import { randomBytes, createHash } from 'crypto';
import { PassThrough, Transform } from 'stream';
import { pipeline } from 'stream/promises';
import { exportDataArchive } from './configBackup.js';
import { s3PutObject, s3GetObject, s3DeleteObject, s3UploadStream, s3DeleteObjects, DEFAULT_PART_SIZE } from './s3.js';
import { encryptStream, archiveKey, ENC_SUFFIX, signManifest } from './backupCrypto.js';
import { RETENTION_DEFAULTS } from './backupRetention.js';
import {
  MANIFEST_NAME, MANIFEST_KIND, hostLabel, normalizePrefix, setIdFor, listSets, applyRetention,
  readManifest, fetchSet, fetchLegacy, SET_ID_RE, verifySets,
} from './backupS3Sets.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';

const K = {
  enabled: 'backup_s3_enabled', bucket: 'backup_s3_bucket', region: 'backup_s3_region',
  prefix: 'backup_s3_prefix', endpoint: 'backup_s3_endpoint', accessKey: 'backup_s3_access_key_id',
  secretEnc: 'backup_s3_secret_enc', lastRun: 'backup_s3_last_run', lastError: 'backup_s3_last_error',
  hour: 'backup_s3_hour',
  keepDaily: 'backup_s3_keep_daily', keepWeekly: 'backup_s3_keep_weekly', keepMonthly: 'backup_s3_keep_monthly',
  encrypt: 'backup_s3_encrypt', sse: 'backup_s3_sse', sseKmsKeyId: 'backup_s3_sse_kms_key_id',
  includeRepos: 'backup_s3_include_repos',
  lastBytes: 'backup_s3_last_bytes', lastDurationMs: 'backup_s3_last_duration_ms', lastSet: 'backup_s3_last_set',
  lastWarnings: 'backup_s3_last_warnings', lastRetention: 'backup_s3_last_retention',
};

const SSE_MODES = ['', 'AES256', 'aws:kms'];
const clampInt = (v, lo, hi, dflt) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
};

export const OFFSITE_COVERS = [
  'deployhub.db', '.env (ENCRYPTION_KEY)', 'app icons', 'per-app /data', 'declared volumes',
  'managed database dumps', 'managed-app git repositories',
];
export const OFFSITE_EXCLUDES = ['container images (POST /api/settings/images/export)', 'build artifacts (releases/)', 'the Caddyfile (regenerated on boot)'];
export const ENCRYPTION_WARNING = 'Encrypted backups can only be decrypted with this host\'s ENCRYPTION_KEY. If that key is lost, every encrypted backup is unrecoverable — keep a copy of the key somewhere other than this host and this bucket.';

function get(db, k) { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r?.value ?? ''; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v ?? ''), userId ?? null);
}

/**
 * The one sentence every surface says when this host holds the only copy.
 *
 * It is a constant, exported and reused by the settings API, the MCP status
 * tool and (through the API payload) the dashboard, because the failure being
 * described is a single fact and three hand-written variants of it drift: one
 * gets softened, one gets dropped in a refactor, and the surface that still
 * says it is the one nobody reads. Tests assert this exact string on every
 * surface, so removing it from any of them fails the suite.
 */
export const NO_OFFSITE_NOTICE = 'No off-site copy — everything AppCrane knows lives on this host.';

/**
 * Measured off-site state, from the config and the recorded last run.
 *
 * `has_off_site_copy` is deliberately not `enabled`: a schedule that is on and
 * has never completed has produced no copy, and a stored bucket with the
 * schedule switched off has produced none either. Only a recorded successful
 * upload means bytes left this host.
 */
export function offSiteState() {
  const cfg = getBackupConfig();
  const missing = [];
  if (!cfg.bucket) missing.push('bucket');
  if (!cfg.access_key_id) missing.push('access_key_id');
  if (!cfg.has_secret) missing.push('secret_access_key');
  const configured = missing.length === 0;
  const hasCopy = configured && !!cfg.last_run;
  let reason = null;
  if (!configured) reason = `No off-site destination is configured (missing: ${missing.join(', ')}).`;
  else if (!cfg.last_run && !cfg.enabled) reason = 'A destination is stored, but the nightly upload is switched off and has never run.';
  else if (!cfg.last_run) reason = 'The nightly upload is switched on but has never completed.';
  return {
    configured,
    enabled: cfg.enabled,
    missing,
    last_run: cfg.last_run,
    last_error: cfg.last_error,
    has_off_site_copy: hasCopy,
    notice: hasCopy ? null : `${NO_OFFSITE_NOTICE} ${reason}`,
  };
}

// Client-side encryption is on by default for a NEW off-site config. A config
// saved before the default existed (a bucket set, no encrypt row) keeps what it
// had, which was off; the first save of a new config writes the default down.
function encryptSetting(db) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(K.encrypt)?.value;
  if (v === '1' || v === '0') return v;
  return get(db, K.bucket) ? '0' : '1';
}

export function getBackupConfig() {
  const db = getDb();
  const lastBytes = parseInt(get(db, K.lastBytes), 10);
  const lastDuration = parseInt(get(db, K.lastDurationMs), 10);
  let lastRetention = null;
  try { lastRetention = get(db, K.lastRetention) ? JSON.parse(get(db, K.lastRetention)) : null; } catch (_) { lastRetention = null; }
  return {
    enabled: get(db, K.enabled) === '1',
    bucket: get(db, K.bucket),
    region: get(db, K.region) || 'us-east-1',
    prefix: get(db, K.prefix),
    endpoint: get(db, K.endpoint) || '',
    access_key_id: get(db, K.accessKey),
    has_secret: !!get(db, K.secretEnc),
    hour: parseInt(get(db, K.hour) || '3', 10),
    last_run: get(db, K.lastRun) || null,
    last_error: get(db, K.lastError) || null,
    keep_daily: clampInt(get(db, K.keepDaily), 1, 366, RETENTION_DEFAULTS.daily),
    keep_weekly: clampInt(get(db, K.keepWeekly), 0, 520, RETENTION_DEFAULTS.weekly),
    keep_monthly: clampInt(get(db, K.keepMonthly), 0, 240, RETENTION_DEFAULTS.monthly),
    encrypt: encryptSetting(db) === '1',
    sse: SSE_MODES.includes(get(db, K.sse)) ? get(db, K.sse) : '',
    sse_kms_key_id: get(db, K.sseKmsKeyId),
    include_repos: get(db, K.includeRepos) !== '0',
    last_bytes: Number.isFinite(lastBytes) ? lastBytes : null,
    last_duration_ms: Number.isFinite(lastDuration) ? lastDuration : null,
    last_set: get(db, K.lastSet) || null,
    last_warnings: get(db, K.lastWarnings) ? get(db, K.lastWarnings).split('\n') : [],
    last_retention: lastRetention,
    covers: OFFSITE_COVERS,
    excludes: OFFSITE_EXCLUDES,
    encryption_warning: ENCRYPTION_WARNING,
  };
}

export function setBackupConfig(patch, userId) {
  const db = getDb();
  if (patch.encrypt === undefined && !get(db, K.bucket) && patch.bucket) set(db, K.encrypt, encryptSetting(db), userId);
  const map = { enabled: v => set(db, K.enabled, v ? '1' : '0', userId),
    bucket: v => set(db, K.bucket, v, userId), region: v => set(db, K.region, v, userId),
    prefix: v => set(db, K.prefix, v, userId), endpoint: v => set(db, K.endpoint, v, userId),
    access_key_id: v => set(db, K.accessKey, v, userId),
    hour: v => set(db, K.hour, String(parseInt(v, 10) || 3), userId),
    keep_daily: v => set(db, K.keepDaily, String(clampInt(v, 1, 366, RETENTION_DEFAULTS.daily)), userId),
    keep_weekly: v => set(db, K.keepWeekly, String(clampInt(v, 0, 520, RETENTION_DEFAULTS.weekly)), userId),
    keep_monthly: v => set(db, K.keepMonthly, String(clampInt(v, 0, 240, RETENTION_DEFAULTS.monthly)), userId),
    encrypt: v => set(db, K.encrypt, v ? '1' : '0', userId),
    sse: v => set(db, K.sse, SSE_MODES.includes(String(v)) ? String(v) : '', userId),
    sse_kms_key_id: v => set(db, K.sseKmsKeyId, v, userId),
    include_repos: v => set(db, K.includeRepos, v ? '1' : '0', userId) };
  for (const [k, fn] of Object.entries(map)) if (patch[k] !== undefined) fn(patch[k]);
  // Secret only when a non-empty value is provided (never returned to clients).
  if (patch.secret_access_key) set(db, K.secretEnc, encrypt(patch.secret_access_key), userId);
  return getBackupConfig();
}

/** Connection + per-run options from the saved config, optionally overridden (Test connection). */
function resolveConn(overrides = {}) {
  const db = getDb();
  const cfg = getBackupConfig();
  const pick = (k) => (overrides[k] !== undefined && overrides[k] !== '' ? String(overrides[k]) : cfg[k]);
  const bucket = pick('bucket');
  const accessKeyId = pick('access_key_id');
  const secretAccessKey = overrides.secret_access_key ? String(overrides.secret_access_key) : (cfg.has_secret ? decrypt(get(db, K.secretEnc)) : '');
  if (!bucket || !accessKeyId || !secretAccessKey) {
    throw new Error('S3 backup is not fully configured (needs bucket, access key, and secret).');
  }
  const endpoint = pick('endpoint') || undefined;
  if (endpoint && !/^https?:\/\/[^/\s]+\/?$/i.test(endpoint)) throw new Error('Endpoint must be a bare URL like https://<account>.r2.cloudflarestorage.com');
  const sseMode = overrides.sse !== undefined ? String(overrides.sse) : cfg.sse;
  return {
    cfg,
    conn: { bucket, region: pick('region') || 'us-east-1', endpoint, accessKeyId, secretAccessKey },
    prefix: normalizePrefix(overrides.prefix !== undefined ? overrides.prefix : cfg.prefix),
    sse: SSE_MODES.includes(sseMode) && sseMode ? { mode: sseMode, kmsKeyId: (overrides.sse_kms_key_id ?? cfg.sse_kms_key_id) || null } : null,
  };
}

async function uploadFile(conn, objectKey, path, { key, sse, partSize }) {
  const plain = createHash('sha256');
  let plainBytes = 0;
  const tap = new Transform({ transform(c, _e, cb) { plain.update(c); plainBytes += c.length; cb(null, c); } });
  const out = new PassThrough();
  const stages = [createReadStream(path), tap, ...(key ? [encryptStream(key)] : []), out];
  pipeline(...stages).catch(() => { /* surfaced through `out` to the uploader */ });
  const r = await s3UploadStream(conn, objectKey, out, { partSize, sse, contentType: key ? 'application/octet-stream' : 'application/gzip' });
  return { bytes: r.bytes, sha256: r.sha256, plain_bytes: plainBytes, plain_sha256: plain.digest('hex'), multipart: r.multipart, parts: r.parts };
}

/**
 * One off-site backup run, recorded in Job Health as 'offsite-backup' whether
 * it was started by the schedule, the dashboard or the MCP tool.
 *
 * opts (tests): { at, partSize, managedDbOps }
 */
export function runS3Backup(opts = {}) {
  return trackJob('offsite-backup', () => doS3Backup(opts));
}

async function doS3Backup(opts) {
  const db = getDb();
  const startedAt = Date.now();
  let ctx;
  try {
    ctx = resolveConn();
  } catch (e) {
    set(db, K.lastError, String(e.message).slice(0, 300));
    throw e;
  }
  const { cfg, conn, prefix, sse } = ctx;
  const at = opts.at || new Date();
  const host = hostLabel();
  const setId = setIdFor(at, host);
  const base = `${prefix}${setId}/`;
  const key = cfg.encrypt ? archiveKey() : null;
  const partSize = opts.partSize || DEFAULT_PART_SIZE;
  const { newWorkDir } = await import('./backupFiles.js');
  const work = await newWorkDir('s3');
  const uploaded = [];
  const artifacts = [];
  const warnings = [];
  try {
    const put = async (kind, name, path, extra = {}) => {
      const objName = key ? name + ENC_SUFFIX : name;
      const objectKey = base + objName;
      uploaded.push(objectKey);
      const r = await uploadFile(conn, objectKey, path, { key, sse, partSize });
      artifacts.push({
        kind, name: objName, ...extra, bytes: r.bytes, sha256: r.sha256, encrypted: !!key,
        ...(key ? { plain_bytes: r.plain_bytes, plain_sha256: r.plain_sha256 } : {}),
        multipart: r.multipart, parts: r.parts,
      });
      await rm(path, { force: true });
    };

    const data = await exportDataArchive({ dest: join(work, 'data.tar.gz'), at, managedDbOps: opts.managedDbOps });
    warnings.push(...(data.warnings || []));
    await put('data', 'data.tar.gz', data.path);

    let repos = { included: false, exported: 0, failed: [] };
    if (cfg.include_repos) {
      const { exportRepoArchives } = await import('./repoArchive.js');
      const r = await exportRepoArchives({ at, dir: join(work, 'repos') });
      for (const f of r.failed) warnings.push(`repository ${f.slug} was not archived: ${f.error}`);
      for (const ex of r.exported) {
        await put('repo', `repos/${basename(ex.path)}`, ex.path, { slug: ex.slug, fingerprint: ex.fingerprint, head_sha: ex.head_sha });
      }
      repos = { included: true, exported: r.exported.length, failed: r.failed.map((f) => f.slug) };
    }

    const dm = data.manifest;
    const manifest = {
      kind: MANIFEST_KIND, format: 1, set: setId, host, created_at: at.toISOString(),
      appcrane_version: dm.version,
      encryption: key ? { algorithm: 'aes-256-gcm', key_source: 'derived from ENCRYPTION_KEY', warning: ENCRYPTION_WARNING } : null,
      server_side_encryption: sse ? sse.mode : null,
      covers: cfg.include_repos ? OFFSITE_COVERS : OFFSITE_COVERS.filter((c) => c !== 'managed-app git repositories'),
      excludes: cfg.include_repos ? OFFSITE_EXCLUDES : [...OFFSITE_EXCLUDES, 'managed-app git repositories (switched off)'],
      artifacts,
      data: {
        includes: dm.includes, counts: dm.counts, bytes: dm.bytes,
        managed_db: { databases: dm.managed_db?.databases?.length || 0, failed: (dm.managed_db?.failed || []).map((f) => `${f.engine}/${f.db_name}`) },
        repo_set: dm.repo_set ? { count: dm.repo_set.count, fingerprint: dm.repo_set.fingerprint } : null,
      },
      repos,
      warnings,
    };
    const manifestKey = base + MANIFEST_NAME;
    uploaded.push(manifestKey);
    await s3PutObject({ ...conn, key: manifestKey, body: JSON.stringify(signManifest(manifest), null, 2), contentType: 'application/json', sse });

    const size = artifacts.reduce((n, a) => n + a.bytes, 0);
    let retention;
    try {
      retention = await applyRetention(conn, prefix, { daily: cfg.keep_daily, weekly: cfg.keep_weekly, monthly: cfg.keep_monthly }, { host, justUploaded: setId });
    } catch (e) {
      retention = { applied: false, refused: `retention failed: ${e.message}`, kept: [], removed_sets: [], deleted_objects: 0, errors: [] };
    }
    if (retention.refused) warnings.push(`retention not applied: ${retention.refused}`);
    const durationMs = Date.now() - startedAt;
    set(db, K.lastRun, new Date().toISOString());
    set(db, K.lastError, '');
    set(db, K.lastBytes, String(size));
    set(db, K.lastDurationMs, String(durationMs));
    set(db, K.lastSet, setId);
    set(db, K.lastWarnings, warnings.join('\n').slice(0, 2000));
    set(db, K.lastRetention, JSON.stringify({ applied: retention.applied, refused: retention.refused, kept: retention.kept.length, removed_sets: retention.removed_sets.length, deleted_objects: retention.deleted_objects }));
    setJobDetail('offsite-backup', { last_success_bytes: size, last_success_duration_ms: durationMs, artifacts: artifacts.length, set: setId });
    log.info(`[backup-s3] uploaded set ${setId} (${artifacts.length} artifacts, ${size} bytes, ${durationMs} ms, retention ${retention.applied ? `kept ${retention.kept.length} removed ${retention.removed_sets.length}` : 'not applied'})`);
    return { key: manifestKey, size, set: setId, artifacts, encrypted: !!key, retention, warnings, duration_ms: durationMs };
  } catch (e) {
    if (uploaded.length) await s3DeleteObjects(conn, uploaded).catch(() => {});
    set(db, K.lastError, String(e.message).slice(0, 300));
    log.error(`[backup-s3] backup failed: ${e.message}`);
    throw e;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** PUT, GET and DELETE a small probe object. Each step reported separately. */
export async function testS3Connection(overrides = {}) {
  const steps = [];
  let ctx;
  try {
    ctx = resolveConn(overrides);
  } catch (e) {
    return { ok: false, steps: [{ step: 'config', ok: false, error: e.message }] };
  }
  const { conn, prefix, sse } = ctx;
  const probeKey = `${prefix}appcrane-probe-${randomBytes(8).toString('hex')}.txt`;
  const body = `appcrane connection probe ${randomBytes(16).toString('hex')}`;
  const step = async (name, fn) => {
    try { await fn(); steps.push({ step: name, ok: true }); return true; } catch (e) { steps.push({ step: name, ok: false, error: e.message }); return false; }
  };
  if (await step('put', () => s3PutObject({ ...conn, key: probeKey, body, contentType: 'text/plain', sse }))) {
    await step('get', async () => {
      const got = (await s3GetObject(conn, probeKey)).toString('utf8');
      if (got !== body) throw new Error('the object read back differs from the one written');
    });
    await step('delete', () => s3DeleteObject(conn, probeKey));
  }
  return { ok: steps.every((s) => s.ok), steps, bucket: conn.bucket, prefix };
}

/**
 * Backups under the prefix, every host's (own_host marks which are ours).
 * Verified sets come first, newest by their SIGNED time; unverified ones
 * (legacy, incomplete, unsigned or forged) after them, by the time in their
 * name, flagged and never restorable. latest_verified is what to restore.
 */
export async function listS3Backups() {
  const { conn, prefix } = resolveConn();
  const { sets, others, truncated } = await listSets(conn, prefix);
  await verifySets(conn, prefix, sets);
  const host = hostLabel();
  const rows = sets.map((s) => ({
    id: s.id, host: s.verified ? s.signed_host : s.host, own: (s.verified ? s.signed_host : s.host) === host,
    created_at: s.verified ? s.signed_at : s.at, legacy: s.legacy, complete: s.complete,
    verified: !!s.verified, verify_error: s.verified ? null : s.verify_error, restorable: !!s.verified, downloadable: !!s.verified || s.legacy,
    objects: s.objects.length, bytes: s.bytes,
  }));
  const order = (a, b) => (a.verified !== b.verified ? (a.verified ? -1 : 1) : (a.created_at < b.created_at ? 1 : -1));
  rows.sort(order);
  return {
    own_host: host, prefix, truncated, other_objects: others,
    latest_verified: rows.find((r) => r.verified && r.own)?.id || null,
    unverified: rows.filter((r) => !r.verified).length,
    backups: rows,
  };
}

export async function getS3BackupManifest(setId) {
  const { conn, prefix } = resolveConn();
  return { ...(await readManifest(conn, prefix, setId)), verified: true };
}

/**
 * Download (and verify) a backup's artifacts into `dir`. A legacy set (no
 * manifest) is fetched unverified and says so.
 */
export async function fetchS3Backup(setId, dir, { only = null } = {}) {
  if (!SET_ID_RE.test(String(setId))) throw Object.assign(new Error('invalid backup id'), { status: 400 });
  const { conn, prefix } = resolveConn();
  const { sets } = await listSets(conn, prefix);
  const found = sets.find((s) => s.id === setId);
  if (!found) throw Object.assign(new Error('No such backup in the bucket'), { status: 404 });
  if (found.legacy) return fetchLegacy(conn, prefix, setId, dir);
  if (!found.complete) throw Object.assign(new Error('This backup is incomplete (no manifest) and cannot be verified'), { status: 409 });
  // fetchSet authenticates the manifest before it downloads anything.
  return fetchSet(conn, prefix, setId, dir, { only, key: archiveKey() });
}

/**
 * Restore a whole backup set through the existing importers: the data archive
 * via importDataArchive (as POST /config/import does), then every repository
 * via importRepoArchive (as POST /repos/import does). The caller restarts.
 */
export async function restoreS3Backup(setId) {
  const { backupsDir } = await import('./backupFiles.js');
  const fetched = await fetchS3Backup(setId, backupsDir());
  if (!fetched.manifest) throw Object.assign(new Error('A pre-manifest backup cannot be restored in one step: it is not verifiable. It was downloaded; import it with POST /api/settings/config/import if you trust it.'), { status: 409 });
  const data = fetched.files.find((f) => f.kind === 'data');
  if (!data) throw new Error('This backup has no data archive');
  const { importDataArchive } = await import('./configBackup.js');
  const { importRepoArchive, verifyRepoSet } = await import('./repoArchive.js');
  const result = await importDataArchive(data.path, { restoreEnv: true });
  const repos = { restored: [], failed: [] };
  for (const f of fetched.files.filter((x) => x.kind === 'repo')) {
    try { await importRepoArchive(f.local_file, { slug: f.slug }); repos.restored.push(f.slug); } catch (e) { repos.failed.push({ slug: f.slug, error: e.message }); }
  }
  let verification = null;
  try { verification = await verifyRepoSet(); } catch (_) { verification = null; }
  return { set: setId, files: fetched.files.map(({ path: _p, ...f }) => f), data: result, repos, repo_verification: verification };
}

let _timer = null;
export function startBackupScheduler() {
  if (_timer) return;
  const tick = async () => {
    try {
      const db = getDb();
      const cfg = getBackupConfig();
      if (!cfg.enabled) return;
      const today = new Date().toISOString().slice(0, 10);
      if ((get(db, K.lastRun) || '').slice(0, 10) !== today && new Date().getHours() >= cfg.hour) {
        await runS3Backup().catch(() => { /* last_error already recorded */ });
      }
    } catch (e) {
      log.warn(`[backup-s3] scheduler tick failed: ${e.message}`);
    }
  };
  jobStarted('offsite-backup', { enabled: () => getBackupConfig().enabled });
  tick();
  _timer = setInterval(() => { tick().catch(() => {}); }, 60 * 60 * 1000);
  log.info('[backup-s3] scheduler started (hourly check)');
}
