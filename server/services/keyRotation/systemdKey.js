import { existsSync, copyFileSync, chmodSync, renameSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { credentialName, systemdPaths, expectedKeys, encryptCredential, decryptCredential } from '../secretsProvider/systemdCreds.js';
import { rotateDatabase, selfCheck } from './rotate.js';

const KEY_RE = /^[0-9a-f]{64}$/i;
const NAME = credentialName('ENCRYPTION_KEY');

/**
 * The systemd credential when it holds ENCRYPTION_KEY, or null when rotation
 * is the plain .env case. Decrypting needs root; a credential that is expected
 * and cannot be read throws rather than fall back to .env.
 */
export async function systemdKeyHeld(env = process.env) {
  const paths = systemdPaths(env);
  const file = join(paths.credstore, NAME);
  if (!expectedKeys(env).includes('ENCRYPTION_KEY') && !existsSync(file)) return null;
  let oldKey;
  try {
    oldKey = await decryptCredential(NAME, file);
  } catch (e) {
    if (process.geteuid?.() !== 0) throw new Error(`ENCRYPTION_KEY is the systemd credential ${file}, which only root can decrypt and replace: run sudo crane rotate-key (${e.message})`);
    throw e;
  }
  if (!KEY_RE.test(oldKey)) throw new Error(`systemd credential ${NAME}: ENCRYPTION_KEY must be 64 hex characters`);
  return { kind: 'systemd-creds', oldKey: oldKey.toLowerCase(), file, credential: NAME, unit: paths.unit };
}

/**
 * The provider half of crane rotate-key for systemd-creds: seal the new key
 * next to the old credential (.pending) and decrypt it back -> commit the
 * database -> rename .pending over the credential -> decrypt and self-check.
 * Before the commit the old credential is untouched. The old credential's
 * ciphertext is copied into the backup folder; it opens only on this host.
 */
export async function rotateWithSystemdCreds(db, { held, newKey, backupDir }) {
  const { oldKey, file, credential } = held;
  rotateDatabase(db, { oldKey, newKey, dryRun: true });
  const pending = `${file}.pending`;
  const previous = join(backupDir, `${credential}.previous`);
  copyFileSync(file, previous);
  chmodSync(previous, 0o600);
  const restore = `sudo install -m 0600 -o root -g root ${previous} ${file}`;

  let report;
  try {
    rmSync(pending, { force: true });
    await encryptCredential(credential, newKey, pending);
    chmodSync(pending, 0o600);
    // Names, paths and commands only. Should this process die after the commit, this is the way forward.
    writeFileSync(join(backupDir, 'credential-rotation.json'), JSON.stringify({
      credential, file, pending, previous_copy: previous,
      if_interrupted_after_commit: `sudo mv ${pending} ${file}`,
      undo: `${restore} (and restore ${join(backupDir, 'deployhub.db')})`,
    }, null, 2), { mode: 0o600 });
    if (await decryptCredential(credential, pending) !== newKey) throw new Error('the new credential did not decrypt back to the new key; the database was not changed');
    report = rotateDatabase(db, { oldKey, newKey });
  } catch (e) {
    rmSync(pending, { force: true });
    throw e;
  }

  try {
    renameSync(pending, file);
  } catch (e) {
    e.dbCommitted = true;
    e.message = `the database now uses the new key but the credential could not be replaced (${e.message}). AppCrane will not read its data until this is done. Run: `
      + `sudo mv ${pending} ${file} (or restore ${join(backupDir, 'deployhub.db')})`;
    throw e;
  }

  let failures;
  try {
    failures = await decryptCredential(credential, file) === newKey ? selfCheck(db, newKey) : [`${file} does not hold the new key`];
  } catch (e) {
    failures = [e.message];
  }
  report.post_check = failures.length ? { ok: false, failures } : { ok: true };
  return { report, provider: { kind: 'systemd-creds', credential, file, previous_copy: previous, undo: restore } };
}
