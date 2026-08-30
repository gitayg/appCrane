import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

// AES-GCM must not accept a truncated authentication tag (v2.53.1).
//
// decrypt() built its decipher with `createDecipheriv(ALGORITHM, key, iv)` and
// no authTagLength, then fed it a tag parsed straight out of the stored blob.
// Node reads authTagLength as "whatever setAuthTag is given" in that case, and
// GCM accepts 4, 8, 12, 13, 14, 15 or 16 bytes. A 4-byte tag means a forged
// ciphertext authenticates with probability 2^-32 instead of 2^-128 — online
// brute force rather than never.
//
// Reaching it needs write access to a stored ciphertext (every caller reads
// from the database), so this is hardening, not an open door. It is also one
// line, and the property is invisible to every other test: the round-trip
// succeeds either way, which is exactly why nothing caught it.

process.env.ENCRYPTION_KEY = 'f'.repeat(64);
const { encrypt, decrypt } = await import('../server/services/encryption.js');

/** Re-encode a blob with its auth tag cut to `n` bytes. */
function truncateTag(blob, n) {
  const [iv, tag, ct] = blob.split(':');
  return [iv, Buffer.from(tag, 'hex').subarray(0, n).toString('hex'), ct].join(':');
}

test('a full 16-byte tag still round-trips', () => {
  assert.equal(decrypt(encrypt('hunter2')), 'hunter2');
});

test('Node itself accepts short GCM tags — this is the behaviour being guarded', () => {
  // Stated as a test rather than a comment: if a future Node makes short tags
  // an error on its own, the guard below stops being load-bearing and someone
  // should know that rather than inferring it.
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = c.update('x', 'utf8', 'hex') + c.final('hex');
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(c.getAuthTag().subarray(0, 4));
  assert.equal(d.update(ct, 'hex', 'utf8') + d.final('utf8'), 'x',
    'raw Node accepts a 4-byte tag; if this ever fails, the platform fixed it upstream');
});

for (const n of [4, 8, 12, 15]) {
  test(`decrypt() REFUSES a ${n}-byte tag`, () => {
    const short = truncateTag(encrypt('secret-value'), n);
    assert.throws(() => decrypt(short), /auth tag|authentication|Unsupported state/i,
      `a ${n}-byte tag reduces forgery cost from 2^-128 to 2^-${n * 8}`);
  });
}

test('a tag of the right length but wrong bytes is still refused', () => {
  const [iv, tag, ct] = encrypt('secret-value').split(':');
  const flipped = Buffer.from(tag, 'hex');
  flipped[0] ^= 0xff;
  assert.throws(() => decrypt([iv, flipped.toString('hex'), ct].join(':')),
    /Unsupported state|unable to authenticate/i,
    'the ordinary GCM guarantee must survive the length check being added');
});
