/**
 * Client-side encryption for off-site backup artifacts.
 *
 * Format: MAGIC (8 bytes) | IV (12) | AES-256-GCM ciphertext | tag (16).
 * The key is derived from ENCRYPTION_KEY (deriveSecret), never stored. LOSING
 * ENCRYPTION_KEY MAKES EVERY ENCRYPTED BACKUP UNRECOVERABLE — there is no
 * other copy of the key and no rotation mechanism.
 *
 * Decryption writes plaintext to a file and only keeps it once the GCM tag has
 * verified; a tampered or truncated object leaves nothing behind.
 */
import crypto from 'crypto';
import { createReadStream, createWriteStream } from 'fs';
import { open, rm, stat, writeFile } from 'fs/promises';
import { Transform } from 'stream';
import { pipeline } from 'stream/promises';
import { deriveSecret } from './encryption.js';

export const ENC_MAGIC = Buffer.from([0x41, 0x43, 0x45, 0x4e, 0x43, 0x00, 0x01, 0x00]);
export const ENC_SUFFIX = '.enc';
export const KEY_LABEL = 'appcrane-s3-backup-archive-v1';
const IV_LEN = 12;
const TAG_LEN = 16;

export function archiveKey() {
  return Buffer.from(deriveSecret(KEY_LABEL), 'hex');
}

// Manifest authentication. Anyone who can write to the bucket can write a
// manifest.json, so a set is genuine only when its manifest carries an HMAC
// under a key derived from ENCRYPTION_KEY (a label of its own, never the
// archive key). The MAC covers the whole manifest, set id and created_at
// included, in a canonical JSON form (keys sorted), so it does not depend on
// how the object was serialised.
export const MANIFEST_MAC_LABEL = 'appcrane-s3-backup-manifest-mac-v1';
export const MANIFEST_MAC_ALG = 'hmac-sha256';

export function manifestMacKey() {
  return Buffer.from(deriveSecret(MANIFEST_MAC_LABEL), 'hex');
}

export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

function macOf(manifest, key) {
  const { signature: _s, ...body } = manifest;
  return crypto.createHmac('sha256', key).update(canonicalJson(body)).digest('hex');
}

/** The manifest with its signature added. */
export function signManifest(manifest, key = manifestMacKey()) {
  return { ...manifest, signature: { alg: MANIFEST_MAC_ALG, mac: macOf(manifest, key) } };
}

/** True only for a manifest signed under `key` and not changed since. */
export function manifestSignatureValid(manifest, key = manifestMacKey()) {
  const sig = manifest?.signature;
  if (!sig || sig.alg !== MANIFEST_MAC_ALG || typeof sig.mac !== 'string' || !/^[0-9a-f]{64}$/.test(sig.mac)) return false;
  return crypto.timingSafeEqual(Buffer.from(sig.mac, 'hex'), Buffer.from(macOf(manifest, key), 'hex'));
}

export function encryptStream(key) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let headerSent = false;
  return new Transform({
    transform(chunk, _e, cb) {
      if (!headerSent) { this.push(Buffer.concat([ENC_MAGIC, iv])); headerSent = true; }
      cb(null, cipher.update(chunk));
    },
    flush(cb) {
      if (!headerSent) this.push(Buffer.concat([ENC_MAGIC, iv]));
      this.push(cipher.final());
      cb(null, cipher.getAuthTag());
    },
  });
}

/** Decrypt `src` into `dest`. Returns { bytes, sha256 } of the plaintext. */
export async function decryptFile(src, dest, key) {
  const size = (await stat(src)).size;
  if (size < ENC_MAGIC.length + IV_LEN + TAG_LEN) throw new Error('encrypted backup is truncated');
  const fh = await open(src, 'r');
  const head = Buffer.alloc(ENC_MAGIC.length + IV_LEN);
  const authTag = Buffer.alloc(TAG_LEN);
  try {
    await fh.read(head, 0, head.length, 0);
    await fh.read(authTag, 0, TAG_LEN, size - TAG_LEN);
  } finally {
    await fh.close();
  }
  if (!head.subarray(0, ENC_MAGIC.length).equals(ENC_MAGIC)) throw new Error('not an AppCrane encrypted backup');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, head.subarray(ENC_MAGIC.length));
  decipher.setAuthTag(authTag);
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  const tap = new Transform({ transform(c, _e, cb) { hash.update(c); bytes += c.length; cb(null, c); } });
  const end = size - TAG_LEN - 1;
  try {
    if (end >= head.length) {
      await pipeline(createReadStream(src, { start: head.length, end }), decipher, tap, createWriteStream(dest, { mode: 0o600 }));
    } else {
      decipher.final();
      await writeFile(dest, '', { mode: 0o600 });
    }
  } catch (e) {
    await rm(dest, { force: true });
    throw new Error(`encrypted backup failed authentication (wrong ENCRYPTION_KEY or damaged object): ${e.message}`);
  }
  return { bytes, sha256: hash.digest('hex') };
}
