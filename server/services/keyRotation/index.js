import { randomBytes } from 'crypto';
import { existsSync, statSync } from 'fs';
import { join } from 'path';
import { getState, modeFor } from '../managedDbEncryption.js';
import { openExclusive, serverAnswers, pendingMigrations, diskRefusal, backupBeforeRotation } from './preflight.js';
import { readEnv, readEnvKey, replaceEnvKey, stageEnv } from './envFile.js';
import { rotateDatabase, selfCheck, RotationError } from './rotate.js';

export { RotationError };

const KEY_RE = /^[0-9a-f]{64}$/;

export class RefusedError extends Error {}

/** Why rotating would break something outside deployhub.db, one line each. Empty when safe. */
export function blockers(db) {
  const out = [];
  const hasSettings = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settings'").get();
  if (hasSettings && modeFor(getState(db)) !== 'none') {
    out.push('MariaDB encryption at rest is in use. Its key file is wrapped with a secret derived from ENCRYPTION_KEY and the running MariaDB '
      + 'container holds the current one, so after a rotation it would fail at its next restart. Turn MariaDB encryption off '
      + 'and unload its key (Settings > Managed databases) first, then rotate and turn it back on.');
  }
  return out;
}

/** Facts about things signed under the old key that stay that way (reported, not changed). */
function signedElsewhere(db) {
  const has = (t) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t);
  const setting = (k) => (has('settings') ? db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value : null);
  return {
    evidence_packs: has('evidence_packs') ? db.prepare("SELECT COUNT(*) AS n FROM evidence_packs WHERE status = 'ready'").get().n : 0,
    offsite_backups_encrypted: setting('backup_s3_enabled') === '1' && setting('backup_s3_encrypt') === '1',
    offsite_backups_configured: !!setting('backup_s3_bucket'),
  };
}

/**
 * crane rotate-key. Options: dataDir, envPath, newKey (hex, optional), dryRun,
 * port (the AppCrane HTTP port probed to tell whether it runs).
 * Returns { report, backupDir, notes }. Throws RefusedError before any change,
 * or RotationError (with .report and .backupDir) after a rolled-back attempt.
 */
export async function rotateKey({ dataDir, envPath, newKey = null, dryRun = false, port = 5001, now = new Date() }) {
  if (!existsSync(envPath)) throw new RefusedError(`no .env at ${envPath}`);
  const envText = readEnv(envPath);
  const oldKey = readEnvKey(envText);
  if (!oldKey) throw new RefusedError(`${envPath} has no ENCRYPTION_KEY of 64 hex characters`);
  const live = process.env.ENCRYPTION_KEY;
  if (live && live.slice(0, 64).toLowerCase() !== oldKey) {
    throw new RefusedError('ENCRYPTION_KEY is set in this shell and differs from the one in .env. The server prefers the environment over .env, '
      + 'so rotating .env would not change the key it uses. Unset it (and remove it from the service definition) first');
  }
  if (newKey != null) {
    newKey = String(newKey).trim().toLowerCase();
    if (!KEY_RE.test(newKey)) throw new RefusedError('the new key must be exactly 64 hex characters');
    if (newKey === oldKey) throw new RefusedError('the new key is the same as the current one');
  } else {
    newKey = randomBytes(32).toString('hex');
  }

  const dbPath = join(dataDir, 'deployhub.db');
  if (!existsSync(dbPath) || !statSync(dbPath).isFile()) throw new RefusedError(`no database at ${dbPath}`);
  if (await serverAnswers(port)) throw new RefusedError(`something answers on port ${port}: AppCrane appears to be running. Stop it first`);
  let db;
  try {
    db = openExclusive(dbPath);
  } catch (e) {
    throw e.code === 'IN_USE' ? new RefusedError(e.message) : e;
  }
  try {
    const pending = pendingMigrations(db);
    if (pending.length) throw new RefusedError(`the database is ${pending.length} migration(s) behind this code (first: ${pending[0]}). Start AppCrane once so it migrates, stop it, then rotate`);
    const blocked = blockers(db);
    const notes = signedElsewhere(db);

    if (dryRun) {
      const report = rotateDatabase(db, { oldKey, newKey, dryRun: true });
      return { report: { ...report, blockers: blocked }, backupDir: null, notes };
    }
    if (blocked.length) throw new RefusedError(blocked.join('\n'));
    const disk = diskRefusal(dataDir, dbPath);
    if (disk) throw new RefusedError(disk);

    const backupDir = backupBeforeRotation(db, { dataDir, envPath, now });
    let staged = null;
    let report;
    try {
      report = rotateDatabase(db, {
        oldKey,
        newKey,
        beforeCommit: () => { staged = stageEnv(envPath, replaceEnvKey(envText, newKey)); },
      });
    } catch (e) {
      if (staged) staged.discard();
      e.backupDir = backupDir;
      throw e;
    }
    try {
      staged.commit();
    } catch (e) {
      e.backupDir = backupDir;
      e.dbCommitted = true;
      e.message = `the database now uses the new key but .env could not be replaced (${e.message}). The new .env is at ${staged.path}: `
        + `move it over ${envPath}, or restore ${backupDir}/deployhub.db and ${backupDir}/env.backup`;
      throw e;
    }
    const written = readEnvKey(readEnv(envPath));
    const after = written === newKey ? selfCheck(db, written) : ['.env does not hold the new key'];
    report.post_check = after.length ? { ok: false, failures: after } : { ok: true };
    return { report, backupDir, notes };
  } finally {
    db.close();
  }
}
