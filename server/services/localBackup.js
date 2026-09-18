/**
 * Scheduled LOCAL backup — on by default (v2.79.0).
 *
 * WHY THIS EXISTS AND WHY IT DEFAULTS TO ON.
 * AppCrane has had scheduled off-site (S3/R2) backup since v2.21.9 and it is a
 * no-op until an operator enters a bucket and credentials. Measured on a
 * production instance running 62 apps: `configured: false`, `last_run: null` —
 * no copy of the database existed anywhere, on or off the host, and every
 * status surface reported that fact only to whoever went looking for it. The
 * platform's own words are "everything AppCrane knows lives in one SQLite file
 * on this host", so the failure that needs no network, no credentials and no
 * decision from anyone is the one this covers: that single file being
 * corrupted, truncated, replaced by a bad import, or deleted.
 *
 * A local copy is NOT a substitute for an off-site one and this module never
 * says it is — lose the host and you lose both. It is the floor, not the
 * ceiling, which is why every surface that reports it also carries
 * NO_OFFSITE_NOTICE until a destination exists.
 *
 * WHAT IT WRITES, WHERE, AND WHAT IT COSTS
 *   - Archives land in DATA_DIR/backups/local/, 0600 inside a 0700 directory.
 *   - `appcrane-platform-<host>-<stamp>.tar.gz`, one per night at 04:00 local.
 *   - CONTENTS: deployhub.db + .env ONLY (contents: 'platform'). Not app
 *     icons, not per-app /data, not declared volumes. Those are in the full
 *     export and the off-site upload. An unattended nightly job that copies
 *     every hosted app's data onto the same disk it is protecting is unbounded
 *     in size and is how a backup takes a host down; the database and the
 *     ENCRYPTION_KEY are the part nothing else can rebuild.
 *   - DISK COST: KEEP_DEFAULT (7) copies of a gzipped SQLite database plus a
 *     .env. For a 62-app instance that is single-digit MB per copy — the whole
 *     schedule costs less than one container image. exportDataArchive's own
 *     free-space check (needs 1.1x uncompressed + 64 MB headroom) refuses the
 *     run rather than filling the disk, and the refusal is recorded in
 *     last_error where every status surface already reads it.
 *
 * Retention is applied AFTER a successful write and only to files this job
 * names, so an operator's own manual exports in DATA_DIR/backups are never
 * deleted by it.
 *
 * SECURITY: these archives contain the ENCRYPTION_KEY and every encrypted
 * secret, exactly like the ones Settings → Backup produces. Nothing here logs
 * a credential; the only values written to the settings table are a flag, two
 * integers, timestamps and an error string.
 */

import { join } from 'path';
import { mkdir, readdir, stat, unlink } from 'fs/promises';
import { getDb } from '../db.js';
import { exportDataArchive } from './configBackup.js';
import { dataDir } from './backupFiles.js';
import log from '../utils/logger.js';

const K = {
  enabled: 'backup_local_enabled',
  keep: 'backup_local_keep',
  hour: 'backup_local_hour',
  lastRun: 'backup_local_last_run',
  lastError: 'backup_local_last_error',
  lastFile: 'backup_local_last_file',
  lastBytes: 'backup_local_last_bytes',
};

export const KEEP_DEFAULT = 7;
export const HOUR_DEFAULT = 4;

/** Files this job writes. Anchored so an operator's own archives are never pruned. */
const LOCAL_FILE_RE = /^appcrane-platform-[a-z0-9.-]*-.+\.tar\.gz$/i;

export const localBackupsDir = () => join(dataDir(), 'backups', 'local');

function get(db, k) { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r?.value ?? null; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v ?? ''), userId ?? null);
}

const clampInt = (v, lo, hi, dflt) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
};

/**
 * ABSENT MEANS ON. A fresh instance, and an instance upgrading from a version
 * that had no local schedule, both get the backup; only an explicit '0' turns
 * it off. Defaulting off would reproduce the measured state this exists to fix:
 * a capability that ships switched off and is discovered during the incident.
 */
export function getLocalBackupConfig() {
  const db = getDb();
  const raw = get(db, K.enabled);
  const lastBytes = parseInt(get(db, K.lastBytes) || '', 10);
  return {
    enabled: raw === null || raw === '' ? true : raw === '1',
    keep: clampInt(get(db, K.keep), 1, 60, KEEP_DEFAULT),
    hour: clampInt(get(db, K.hour), 0, 23, HOUR_DEFAULT),
    last_run: get(db, K.lastRun) || null,
    last_error: get(db, K.lastError) || null,
    last_file: get(db, K.lastFile) || null,
    last_bytes: Number.isFinite(lastBytes) ? lastBytes : null,
    directory: localBackupsDir(),
    contents: ['deployhub.db', '.env'],
    excludes: ['app icons', 'per-app /data', 'declared volumes', 'managed-app repositories', 'container images'],
  };
}

export function setLocalBackupConfig(patch, userId) {
  const db = getDb();
  if (patch.enabled !== undefined) set(db, K.enabled, patch.enabled ? '1' : '0', userId);
  if (patch.keep !== undefined) set(db, K.keep, String(clampInt(patch.keep, 1, 60, KEEP_DEFAULT)), userId);
  if (patch.hour !== undefined) set(db, K.hour, String(clampInt(patch.hour, 0, 23, HOUR_DEFAULT)), userId);
  return getLocalBackupConfig();
}

/** Archives this job has written, newest first. */
export async function listLocalBackups() {
  const dir = localBackupsDir();
  let names;
  try { names = await readdir(dir); } catch (_) { return []; }
  const out = [];
  for (const name of names) {
    if (!LOCAL_FILE_RE.test(name)) continue;
    try {
      const st = await stat(join(dir, name));
      if (st.isFile()) out.push({ file: name, bytes: st.size, modified_at: st.mtime.toISOString() });
    } catch (_) { /* vanished between readdir and stat */ }
  }
  // Newest first, with the file name (which carries the same stamp) breaking a
  // tie: an unstable order here would let retention delete the newest archive.
  return out.sort((a, b) => (a.modified_at === b.modified_at
    ? b.file.localeCompare(a.file)
    : (a.modified_at < b.modified_at ? 1 : -1)));
}

/** Delete all but the newest `keep` archives. Returns the names removed. */
export async function pruneLocalBackups(keep = KEEP_DEFAULT) {
  const files = await listLocalBackups();
  const doomed = files.slice(Math.max(1, keep));
  const removed = [];
  for (const f of doomed) {
    try { await unlink(join(localBackupsDir(), f.file)); removed.push(f.file); }
    catch (e) { log.warn(`[backup-local] could not remove ${f.file}: ${e.message}`); }
  }
  return removed;
}

/**
 * Millisecond-resolution stamp, unlike the on-demand export's second-resolution
 * one: two "Back up locally now" clicks inside the same second would otherwise
 * produce the same name, and the second would silently overwrite the first.
 */
function localFileName(at) {
  const host = (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '') || 'appcrane';
  const stamp = at.toISOString().replace(/[:.]/g, '-');
  return `appcrane-platform-${host}-${stamp}.tar.gz`;
}

/**
 * Take one local backup now. Throws on failure (the caller records it); the
 * scheduler records last_error itself so a failing night is visible on every
 * status surface rather than only in the log.
 */
export async function runLocalBackup() {
  const db = getDb();
  const cfg = getLocalBackupConfig();
  const at = new Date();
  const dir = localBackupsDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = localFileName(at);
  try {
    const out = await exportDataArchive({ dest: join(dir, file), at, contents: 'platform' });
    const removed = await pruneLocalBackups(cfg.keep);
    set(db, K.lastRun, at.toISOString());
    set(db, K.lastError, '');
    set(db, K.lastFile, file);
    set(db, K.lastBytes, String(out.bytes));
    log.info(`[backup-local] wrote ${file} (${out.bytes} bytes, kept ${cfg.keep}, pruned ${removed.length})`);
    return { file, path: out.path, bytes: out.bytes, pruned: removed, keep: cfg.keep, directory: dir };
  } catch (e) {
    set(db, K.lastError, String(e.message).slice(0, 300));
    log.error(`[backup-local] failed: ${e.message}`);
    throw e;
  }
}

let _timer = null;
export function startLocalBackupScheduler() {
  if (_timer) return;
  const tick = async () => {
    try {
      const db = getDb();
      const cfg = getLocalBackupConfig();
      if (!cfg.enabled) return;
      const today = new Date().toISOString().slice(0, 10);
      if ((get(db, K.lastRun) || '').slice(0, 10) === today) return;
      if (new Date().getHours() < cfg.hour) return;
      await runLocalBackup().catch(() => { /* last_error already recorded */ });
    } catch (e) {
      log.warn(`[backup-local] scheduler tick failed: ${e.message}`);
    }
  };
  tick();
  _timer = setInterval(() => { tick().catch(() => {}); }, 60 * 60 * 1000);
  log.info('[backup-local] scheduler started (hourly check)');
}

export function stopLocalBackupScheduler() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}
