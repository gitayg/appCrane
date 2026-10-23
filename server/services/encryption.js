import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16; // GCM's full tag. Anything shorter is a weakened tag, not a valid one.
const TAG_LENGTH = 16;

let _cachedKey = null;

function getKey() {
  if (_cachedKey) return _cachedKey;

  const key = process.env.ENCRYPTION_KEY;
  if (!key || key.length < 32) {
    // Production: refuse to start rather than silently generate an ephemeral
    // key (any data encrypted against it would be unreadable after restart).
    if (process.env.NODE_ENV === 'production') {
      throw new Error('ENCRYPTION_KEY missing or too short (need 32+ hex chars). Set it in .env before starting the server.');
    }
    // Dev/test: generate a stable key for this process, but never print the
    // key itself — stdout can be captured by PM2/journalctl/log aggregators.
    const generated = crypto.randomBytes(32).toString('hex');
    process.env.ENCRYPTION_KEY = generated;
    console.warn('[WARN] No ENCRYPTION_KEY in .env. Using an ephemeral key for this process only.');
    console.warn('[WARN] Any data encrypted now will be UNREADABLE after restart.');
    console.warn('[WARN] Fix: generate one with `openssl rand -hex 32` and add ENCRYPTION_KEY=... to .env');
    _cachedKey = Buffer.from(generated, 'hex');
    return _cachedKey;
  }
  _cachedKey = Buffer.from(key.slice(0, 64), 'hex');
  return _cachedKey;
}

// keyOverrideHex (optional): use a specific 32-byte hex key instead of the
// instance's ENCRYPTION_KEY. Used by config migration to re-encrypt a value
// from a source instance's key into this instance's key. Omit for normal use.
export function encrypt(plaintext, keyOverrideHex) {
  const key = keyOverrideHex ? Buffer.from(keyOverrideHex.slice(0, 64), 'hex') : getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decrypt(encoded, keyOverrideHex) {
  const key = keyOverrideHex ? Buffer.from(keyOverrideHex.slice(0, 64), 'hex') : getKey();
  const [ivHex, authTagHex, encryptedHex] = encoded.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  // authTagLength pinned to 16, and the parsed tag length checked before it is
  // handed over. Without both, GCM accepts a 4, 8, 12, 13, 14 or 15-byte tag —
  // measured on this Node, a 4-byte tag decrypts successfully — which drops the
  // cost of forging a ciphertext from 2^-128 to 2^-32. The round-trip works
  // identically either way, so no existing test could see the difference; see
  // test/encryption-authtag.test.js.
  //
  // The explicit length check is not redundant with authTagLength. createDecipheriv
  // enforces it at setAuthTag time, but the error it raises names an "unsupported
  // state" rather than the actual problem, and a stored blob truncated by anything
  // other than an attacker (a botched migration, a CHAR column) should say so.
  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error(
      `decrypt: authentication tag is ${authTag.length} bytes, expected ${AUTH_TAG_LENGTH}`,
    );
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// A secret derived from ENCRYPTION_KEY for one named purpose (HMAC-SHA256 of
// the label, hex). Used where a secret must be reproducible from the instance
// key without being stored anywhere, and must not BE the instance key: the
// MariaDB key file's wrapping secret (managedDbEncryption.js) is handed to a
// container, and a container must never hold the key that decrypts every
// other secret in SQLite. Changing the label changes the secret.
// keyOverrideHex (optional): derive under that key instead of the instance key
// (crane rotate-key derives under the old and the new key side by side).
export function deriveSecret(label, keyOverrideHex) {
  const key = keyOverrideHex ? Buffer.from(keyOverrideHex.slice(0, 64), 'hex') : getKey();
  return crypto.createHmac('sha256', key).update(String(label)).digest('hex');
}

export function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

export function generateApiKey(prefix = 'dhk') {
  const random = crypto.randomBytes(24).toString('base64url');
  return `${prefix}_${random}`;
}

// Password hashing. New hashes are PBKDF2-HMAC-SHA256 (FIPS 140-3 approved),
// stored self-describing as pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>.
// 600,000 iterations is OWASP's Password Storage Cheat Sheet figure for
// PBKDF2-HMAC-SHA256 (2023+). Hashes written before this are scrypt,
// "<32 hex salt>:<128 hex hash>" (the salt used as the hex string itself), and
// still verify; a successful verify of one hands a PBKDF2 replacement to
// onRehash so the caller can store it. Under a FIPS provider scrypt is not
// available: such a verify returns false and calls onLegacyUnavailable, and
// that user has to have the password reset.
export const PBKDF2_SCHEME = 'pbkdf2-sha256';
export const PBKDF2_ITERATIONS = 600000;
const PBKDF2_MIN_ITERATIONS = 100000;
const PBKDF2_MAX_ITERATIONS = 10000000;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function hashPassword(password, { iterations = PBKDF2_ITERATIONS } = {}) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(String(password), salt, iterations, 32, 'sha256');
  return `${PBKDF2_SCHEME}$${iterations}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/** { scheme: 'pbkdf2-sha256'|'scrypt', ... } or null when `stored` is not a hash this module wrote. */
export function parsePasswordHash(stored) {
  if (typeof stored !== 'string') return null;
  const legacy = /^([0-9a-f]{32}):([0-9a-f]{128})$/.exec(stored);
  if (legacy) return { scheme: 'scrypt', salt: legacy[1], hash: Buffer.from(legacy[2], 'hex') };
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== PBKDF2_SCHEME || !/^[1-9][0-9]{0,7}$/.test(parts[1])) return null;
  const iterations = Number(parts[1]);
  if (iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS) return null;
  if (!B64.test(parts[2]) || !B64.test(parts[3])) return null;
  const salt = Buffer.from(parts[2], 'base64');
  const hash = Buffer.from(parts[3], 'base64');
  if (salt.length < 16 || hash.length !== 32) return null;
  return { scheme: PBKDF2_SCHEME, iterations, salt, hash };
}

/** True when `stored` should be replaced by a fresh hashPassword() after a successful verify. */
export function needsRehash(stored) {
  const p = parsePasswordHash(stored);
  return !p || p.scheme !== PBKDF2_SCHEME || p.iterations < PBKDF2_ITERATIONS;
}

/** True when this process can compute scrypt (false under an OpenSSL FIPS provider). */
export function scryptAvailable() {
  try {
    crypto.scryptSync('probe', 'probe', 16);
    return true;
  } catch {
    return false;
  }
}

export function verifyPassword(password, stored, { onRehash, onLegacyUnavailable } = {}) {
  const p = parsePasswordHash(stored);
  if (!p) return false;
  let check;
  if (p.scheme === PBKDF2_SCHEME) {
    check = crypto.pbkdf2Sync(String(password), p.salt, p.iterations, p.hash.length, 'sha256');
  } else {
    try {
      check = crypto.scryptSync(String(password), p.salt, 64);
    } catch {
      if (onLegacyUnavailable) onLegacyUnavailable();
      return false;
    }
  }
  const ok = crypto.timingSafeEqual(p.hash, check);
  if (ok && onRehash && needsRehash(stored)) onRehash(hashPassword(password));
  return ok;
}

export function generateSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}
