/**
 * Key separation for platform backups (v2.145.0).
 *
 * The nightly local archive and the off-site set used to carry .env, and with
 * it ENCRYPTION_KEY, next to deployhub.db: whoever held one file held every
 * secret in it. They now carry .env without the key lines and a manifest entry
 * naming the key they need by fingerprint (backupCrypto.keyFingerprint). The
 * key itself is kept apart: on the running host, in a secrets provider, or in
 * the recovery key file a platform admin downloads from Settings > Backup.
 *
 * Every key that decrypts deployhub.db contents is ENCRYPTION_KEY: encrypt(),
 * deriveSecret() (the MariaDB key file wrap, the off-site archive key and
 * manifest MAC) and the SSO HMACs all read it. OLD_/NEW_ENCRYPTION_KEY are
 * only CLI inputs, but a .env that holds one holds a key that decrypts an
 * older copy of the database, so they go too, as does any line whose value
 * contains the live key.
 */
import Database from 'better-sqlite3';
import { decrypt } from './encryption.js';
import { keyFingerprint, liveKeyHex, normalizeKeyHex, shortFingerprint, KEY_FINGERPRINT_ALG } from './backupCrypto.js';
import { platformKeyLoaded } from './secretsProvider/index.js';
import { parseEnvText } from './secretsProvider/envText.js';
import { describeKnownKey } from './recoveryKey.js';

export const KEY_ENV_NAMES = Object.freeze(['ENCRYPTION_KEY', 'OLD_ENCRYPTION_KEY', 'NEW_ENCRYPTION_KEY']);
const KEY_LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

const refuse = (msg) => Object.assign(new Error(msg), { status: 400, code: 'BACKUP_KEY_REFUSED' });

/** The .env text with every key line gone. Returns { text, removed } (names only). */
export function scrubEnvText(text, liveKey = liveKeyHex()) {
  const removed = [];
  const lower = liveKey ? liveKey.toLowerCase() : null;
  const kept = String(text).split('\n').filter((line) => {
    const m = KEY_LINE_RE.exec(line);
    const name = m ? m[1] : null;
    const holdsKey = lower && line.toLowerCase().includes(lower);
    if ((name && KEY_ENV_NAMES.includes(name)) || holdsKey) {
      removed.push(name || '(unnamed line)');
      return false;
    }
    return true;
  });
  return { text: kept.join('\n'), removed: [...new Set(removed)] };
}

/** The manifest's `encryption_key` entry for an archive written without its key. */
export function keyManifestEntry(removed, liveKey = liveKeyHex()) {
  return {
    in_archive: false,
    fingerprint: keyFingerprint(liveKey),
    fingerprint_alg: KEY_FINGERPRINT_ALG,
    removed_from_env: removed,
    note: 'This archive does not contain ENCRYPTION_KEY. It restores only with the key whose fingerprint is above: '
      + 'the key of the host that wrote it, or the recovery key downloaded from Settings > Backup. Without that key the encrypted values in it cannot be read.',
  };
}

/** True when an archive's manifest says it was written without its key. */
export const keySeparated = (manifest) => manifest?.encryption_key?.in_archive === false;

function sampleDecrypts(stagedDbPath, keyHex) {
  let d;
  try {
    d = new Database(stagedDbPath, { readonly: true, fileMustExist: true });
    const has = d.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'env_vars'").get();
    if (!has) return { tried: 0, failed: 0 };
    const rows = d.prepare("SELECT value_encrypted FROM env_vars WHERE value_encrypted IS NOT NULL AND value_encrypted != '' ORDER BY id LIMIT 3").all();
    let failed = 0;
    for (const r of rows) {
      try { decrypt(r.value_encrypted, keyHex); } catch (_) { failed++; }
    }
    return { tried: rows.length, failed };
  } finally {
    try { d?.close(); } catch (_) {}
  }
}

/**
 * Which key a key-separated archive restores with, decided before anything
 * live changes. null for an archive that carries its own key (the format
 * before v2.145.0), which restores exactly as it always did.
 *
 * Returns { key, source: 'host'|'supplied', fingerprint, writeKey, changesKey }:
 * writeKey is the value the restored .env must hold so the restarted server
 * loads the right key (null when the key lives outside .env and stays there).
 * Throws a 400 naming fingerprints, never key values.
 */
export function planBackupKey(manifest, {
  suppliedKey = null, stagedDbPath, restoreEnv = true, liveEnvText = '',
  env = process.env, keyLoaded = platformKeyLoaded,
} = {}) {
  if (!keySeparated(manifest)) return null;
  const want = manifest.encryption_key.fingerprint;
  if (typeof want !== 'string' || !/^[0-9a-f]{64}$/.test(want)) {
    throw refuse('This backup was written without its ENCRYPTION_KEY and its manifest names no key fingerprint, so the key cannot be checked. Nothing was changed.');
  }
  const given = suppliedKey != null && String(suppliedKey).trim() !== '';
  const supplied = given ? normalizeKeyHex(String(suppliedKey).replace(/^\s*ENCRYPTION_KEY\s*=\s*/, '')) : null;
  if (given && !supplied) {
    throw refuse('The recovery key must be 64 hex characters (the ENCRYPTION_KEY= value in the recovery key file). Nothing was changed.');
  }
  const liveKey = liveKeyHex(env);
  const key = supplied || liveKey;
  const source = supplied ? 'supplied' : 'host';
  if (!key) {
    throw refuse(`This backup needs the ENCRYPTION_KEY with fingerprint ${shortFingerprint(want)}, and this host has no key loaded. Supply the recovery key. Nothing was changed.`);
  }
  const have = keyFingerprint(key);
  if (have !== want) {
    let known = '';
    try { known = describeKnownKey(want); } catch (_) { /* advisory only; the refusal stands */ }
    throw refuse(`This backup needs the ENCRYPTION_KEY with fingerprint ${shortFingerprint(want)}; ${source === 'supplied' ? 'the recovery key supplied' : "this host's key"} has fingerprint ${shortFingerprint(have)}. Nothing was changed. `
      + (known ? `${known} ` : '')
      + (source === 'supplied'
        ? 'Check that it is the recovery key of the host that wrote this backup.'
        : 'Supply the recovery key of the host that wrote this backup (Settings > Backup > Download recovery key on that host).'));
  }
  const sample = sampleDecrypts(stagedDbPath, key);
  if (sample.failed) {
    throw refuse(`The key matches the fingerprint this backup names, but ${sample.failed} of ${sample.tried} sampled encrypted values in its database do not decrypt with it. Nothing was changed.`);
  }

  const changesKey = key !== liveKey;
  const liveEnvKey = normalizeKeyHex(parseEnvText(liveEnvText).ENCRYPTION_KEY);
  let writeKey = null;
  if (changesKey) {
    if (keyLoaded('ENCRYPTION_KEY')) {
      throw refuse('This backup needs a different ENCRYPTION_KEY from the one this host loads from its secrets provider, and AppCrane refuses to boot with two keys. '
        + 'Nothing was changed. Put the recovery key in the provider (a new version), restart, and restore again.');
    }
    if (!restoreEnv) {
      throw refuse('This backup needs a different ENCRYPTION_KEY from this host\'s, and .env restore is off, so the restarted server would not be able to read the restored secrets. '
        + 'Nothing was changed. Restore .env as well, or put the recovery key in this host\'s .env, restart, and restore again.');
    }
    if (liveKey && liveEnvKey !== liveKey) {
      throw refuse('This host sets ENCRYPTION_KEY outside .env (in the service environment), which would override the key a restore writes to .env. '
        + 'Nothing was changed. Set the recovery key there instead, restart, and restore again.');
    }
    writeKey = key;
  } else if (restoreEnv && liveEnvKey === key) {
    writeKey = key;
  }
  return { key, source, fingerprint: want, writeKey, changesKey, sampled: sample.tried };
}
