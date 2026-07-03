/**
 * v2.21.9: scheduled off-site backups to S3 (or S3-compatible, e.g. R2).
 *
 * Local tar.gz backups and the config-export zip already exist; this uploads
 * the config-export zip (SQLite DB + .env + icons + appdata) to an object
 * store on a nightly schedule. It's a no-op until an operator enters bucket +
 * credentials in Settings → Backup, so it's safe to ship before S3 is set up.
 */
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import { exportConfig } from './configBackup.js';
import { s3PutObject } from './s3.js';
import log from '../utils/logger.js';

const K = {
  enabled: 'backup_s3_enabled', bucket: 'backup_s3_bucket', region: 'backup_s3_region',
  prefix: 'backup_s3_prefix', endpoint: 'backup_s3_endpoint', accessKey: 'backup_s3_access_key_id',
  secretEnc: 'backup_s3_secret_enc', lastRun: 'backup_s3_last_run', lastError: 'backup_s3_last_error',
  hour: 'backup_s3_hour',
};

function get(db, k) { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r?.value ?? ''; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v ?? ''), userId ?? null);
}

export function getBackupConfig() {
  const db = getDb();
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
  };
}

export function setBackupConfig(patch, userId) {
  const db = getDb();
  const map = { enabled: v => set(db, K.enabled, v ? '1' : '0', userId),
    bucket: v => set(db, K.bucket, v, userId), region: v => set(db, K.region, v, userId),
    prefix: v => set(db, K.prefix, v, userId), endpoint: v => set(db, K.endpoint, v, userId),
    access_key_id: v => set(db, K.accessKey, v, userId),
    hour: v => set(db, K.hour, String(parseInt(v, 10) || 3), userId) };
  for (const [k, fn] of Object.entries(map)) if (patch[k] !== undefined) fn(patch[k]);
  // Secret only when a non-empty value is provided (never returned to clients).
  if (patch.secret_access_key) set(db, K.secretEnc, encrypt(patch.secret_access_key), userId);
  return getBackupConfig();
}

export async function runS3Backup() {
  const db = getDb();
  const cfg = getBackupConfig();
  if (!cfg.bucket || !cfg.access_key_id || !cfg.has_secret) {
    throw new Error('S3 backup is not fully configured (needs bucket, access key, and secret).');
  }
  const secret = decrypt(get(db, K.secretEnc));
  const { buffer, manifest } = exportConfig();
  const host = (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '');
  const stamp = manifest.exported_at.replace(/[:.]/g, '-');
  const prefix = cfg.prefix ? cfg.prefix.replace(/^\/+|\/+$/g, '') + '/' : '';
  const key = `${prefix}appcrane-backup-${host}-${stamp}.zip`;
  try {
    const r = await s3PutObject({
      bucket: cfg.bucket, region: cfg.region, endpoint: cfg.endpoint || undefined,
      accessKeyId: cfg.access_key_id, secretAccessKey: secret,
      key, body: buffer, contentType: 'application/zip',
    });
    set(db, K.lastRun, new Date().toISOString());
    set(db, K.lastError, '');
    log.info(`[backup-s3] uploaded ${key} (${r.size} bytes)`);
    return { key, size: r.size };
  } catch (e) {
    set(db, K.lastError, String(e.message).slice(0, 300));
    log.error(`[backup-s3] upload failed: ${e.message}`);
    throw e;
  }
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
  tick();
  _timer = setInterval(() => { tick().catch(() => {}); }, 60 * 60 * 1000);
  log.info('[backup-s3] scheduler started (hourly check)');
}
