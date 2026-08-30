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

export function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

export function generateApiKey(prefix = 'dhk') {
  const random = crypto.randomBytes(24).toString('base64url');
  return `${prefix}_${random}`;
}

// Password hashing using Node.js built-in scrypt (no external deps)
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

export function generateSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}
