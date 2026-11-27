import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import { AppError } from '../utils/errors.js';
import { guardedSettingKey } from './settingsOwnedKeys.js';

// v2.21.43: first-class config export/import between AppCrane instances, with
// re-encrypt-on-migrate so encrypted secrets move without sharing keys.
//
// The `settings` table mixes plaintext values, AES-GCM-encrypted secrets (stored
// as `iv:tag:data` hex — see encryption.js), and one-way hashes (e.g.
// scim_token_hash). We classify encrypted values by their STRUCTURE, not by a
// hand-maintained key list, so a new encrypted setting is handled automatically.

// iv (16 bytes = 32 hex) : authTag (16 bytes = 32 hex) : ciphertext (hex)
const ENCRYPTED_RE = /^[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]+$/;
const isEncryptedBlob = (v) => typeof v === 'string' && ENCRYPTED_RE.test(v);
// One-way hashes can't be migrated — the plaintext was never stored. The target
// must generate a fresh value (e.g. a new SCIM token) and re-point the IdP.
const isOneWay = (key) => /_hash$/.test(key);

/**
 * Snapshot the settings table for transfer to another instance. Encrypted
 * values are exported AS-IS (still ciphertext under the SOURCE key — never
 * decrypted to plaintext), so the export file carries no readable secrets.
 */
export function exportConfig(db = getDb()) {
  const rows = db.prepare('SELECT key, value FROM settings ORDER BY key').all();
  const settings = [];
  const regenerate = [];
  for (const { key, value } of rows) {
    if (isOneWay(key)) { regenerate.push(key); continue; }
    settings.push({ key, value, encrypted: isEncryptedBlob(value) });
  }
  return {
    kind: 'appcrane-config',
    version: 1,
    exported_at: new Date().toISOString(),
    settings,
    // Keys the target must set fresh — one-way hashes we can't carry over.
    regenerate,
  };
}

/**
 * Apply an exported config onto THIS instance, re-encrypting any secret with
 * this instance's ENCRYPTION_KEY. `oldKeyHex` is the SOURCE instance's key,
 * needed only to decrypt the encrypted values first (decrypt-old → encrypt-new).
 * Plaintext settings copy straight over. Nothing is decrypted to disk.
 */
export function importConfig(config, oldKeyHex, db = getDb(), { includeProtected = false } = {}) {
  if (!config || config.kind !== 'appcrane-config' || !Array.isArray(config.settings)) {
    throw new Error('Not an AppCrane config export (missing kind/settings).');
  }
  // v2.147.0: protective, owned and AppCrane-recorded keys have their own
  // validated, audited routes. A snapshot naming any of them is refused whole
  // unless the caller asked for include_protected; then each one is reported
  // (old and new value, ciphertext redacted) for the route to audit.
  const guarded = config.settings.filter((s) => s && guardedSettingKey(s.key)).map((s) => String(s.key));
  if (guarded.length && !includeProtected) {
    const err = new AppError(`This snapshot sets ${guarded.length} protected setting(s) that have their own routes: ${guarded.join(', ')}. Nothing was imported. Remove them, or pass include_protected=true from a signed-in session.`, 409, 'PROTECTED_SETTINGS');
    err.publicDetails = { keys: guarded };
    throw err;
  }
  const current = db.prepare('SELECT value FROM settings WHERE key = ?');
  const shown = (v) => (isEncryptedBlob(v) ? '(encrypted)' : v ?? null);
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `);
  const result = { imported: 0, reencrypted: 0, plaintext: 0, errors: [], regenerate: config.regenerate || [], keys: [], protected: [] };

  const run = db.transaction(() => {
    for (const s of config.settings) {
      const before = current.get(s.key)?.value;
      if (s.value == null) {
        upsert.run(s.key, null); result.imported++;
      } else if (s.encrypted) {
        if (!oldKeyHex) { result.errors.push(`${s.key}: encrypted; import again with the source instance's ENCRYPTION_KEY`); continue; }
        let plain;
        try { plain = decrypt(s.value, oldKeyHex); }
        catch (e) { result.errors.push(`${s.key}: could not decrypt with the provided old key (${e.message})`); continue; }
        upsert.run(s.key, encrypt(plain)); // re-encrypt with THIS instance's key
        result.reencrypted++; result.imported++;
      } else {
        upsert.run(s.key, s.value);
        result.plaintext++; result.imported++;
      }
      result.keys.push(s.key);
      if (guarded.includes(String(s.key))) result.protected.push({ key: s.key, from: shown(before), to: s.encrypted ? '(encrypted)' : shown(s.value) });
    }
  });
  run();
  return result;
}
