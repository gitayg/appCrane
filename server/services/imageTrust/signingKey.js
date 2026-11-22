// This instance's image-signing key: ECDSA P-256, generated on first use.
//
// The private key is PKCS#8 PEM encrypted with services/encryption.js (the
// instance ENCRYPTION_KEY), the way dbPki.js keeps its CA key, in the settings
// table. It never leaves this module: callers get a KeyObject to sign with, and
// only the public half (SPKI PEM) is ever exported. P-256 with SHA-256 is what
// `cosign generate-key-pair` produces and what `cosign verify --key` accepts.

import crypto from 'node:crypto';
import { encrypt, decrypt } from '../encryption.js';

export const PRIVATE_KEY_SETTING = 'image_signing_key_enc';
export const PUBLIC_KEY_SETTING = 'image_signing_public_key';

let cached = null;

/** Drop the in-memory copy (tests, key rotation). */
export function _resetSigningKeyCache() { cached = null; }

function read(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value || null;
}

/** sha256 of the DER SubjectPublicKeyInfo, hex. Stable across PEM formatting. */
export function keyIdFor(publicKey) {
  const pub = publicKey instanceof crypto.KeyObject && publicKey.type === 'public' ? publicKey : crypto.createPublicKey(publicKey);
  const der = pub.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function generate(db) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const encPriv = encrypt(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  // Two inserts that only ever create: a concurrent first use loses the race
  // and reads the winner's pair below, so one instance never holds two keys.
  const tx = db.transaction(() => {
    const exists = read(db, PRIVATE_KEY_SETTING);
    if (exists) return;
    const ins = db.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))");
    ins.run(PRIVATE_KEY_SETTING, encPriv);
    ins.run(PUBLIC_KEY_SETTING, pubPem);
  });
  tx();
}

/**
 * The signing key, created if this instance has none yet.
 * @returns {{ privateKey: crypto.KeyObject, publicKey: crypto.KeyObject, publicKeyPem: string, keyId: string }}
 */
export function getSigningKey(db) {
  if (!read(db, PRIVATE_KEY_SETTING)) generate(db);
  const enc = read(db, PRIVATE_KEY_SETTING);
  if (cached && cached.enc === enc) return cached.key;
  const pubPem = read(db, PUBLIC_KEY_SETTING);
  if (!enc || !pubPem) throw new Error('image signing key is incomplete in settings (one half is missing)');
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(decrypt(enc));
  } catch (e) {
    throw new Error(`image signing key could not be decrypted with this instance's ENCRYPTION_KEY (${e.code || 'decrypt failed'})`);
  }
  const publicKey = crypto.createPublicKey(pubPem);
  const derived = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  if (derived !== publicKey.export({ type: 'spki', format: 'pem' })) {
    throw new Error('image signing key pair does not match: the stored public key is not the private key\'s');
  }
  cached = { enc, key: { privateKey, publicKey, publicKeyPem: pubPem, keyId: keyIdFor(publicKey) } };
  return cached.key;
}

/** The verifying half only, or null when no key was ever created. Never creates one. */
export function getPublicKey(db) {
  const pem = read(db, PUBLIC_KEY_SETTING);
  if (!pem) return null;
  const publicKey = crypto.createPublicKey(pem);
  return { publicKey, publicKeyPem: pem, keyId: keyIdFor(publicKey) };
}
