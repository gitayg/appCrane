import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';

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
export function importConfig(config, oldKeyHex, db = getDb()) {
  if (!config || config.kind !== 'appcrane-config' || !Array.isArray(config.settings)) {
    throw new Error('Not an AppCrane config export (missing kind/settings).');
  }
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `);
  const result = { imported: 0, reencrypted: 0, plaintext: 0, errors: [], regenerate: config.regenerate || [] };

  const run = db.transaction(() => {
    for (const s of config.settings) {
      if (s.value == null) { upsert.run(s.key, null); result.imported++; continue; }
      if (s.encrypted) {
        if (!oldKeyHex) { result.errors.push(`${s.key}: encrypted — re-run with the source ENCRYPTION_KEY (--old-key)`); continue; }
        let plain;
        try { plain = decrypt(s.value, oldKeyHex); }
        catch (e) { result.errors.push(`${s.key}: could not decrypt with the provided old key (${e.message})`); continue; }
        upsert.run(s.key, encrypt(plain)); // re-encrypt with THIS instance's key
        result.reencrypted++; result.imported++;
      } else {
        upsert.run(s.key, s.value);
        result.plaintext++; result.imported++;
      }
    }
  });
  run();
  return result;
}
