import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

process.env.ENCRYPTION_KEY = 'f'.repeat(64);
const enc = await import('../server/services/encryption.js');

// What hashPassword wrote before PBKDF2: scrypt, the 32-hex salt used as a string.
function legacyScryptHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

test('new hashes are PBKDF2-HMAC-SHA256, 600k iterations, self-describing, and verify', () => {
  const h = enc.hashPassword('correct horse battery staple');
  const [scheme, iter, salt, hash] = h.split('$');
  assert.equal(scheme, 'pbkdf2-sha256');
  assert.equal(Number(iter), 600000);
  assert.equal(Buffer.from(salt, 'base64').length, 16);
  const expect = crypto.pbkdf2Sync('correct horse battery staple', Buffer.from(salt, 'base64'), 600000, 32, 'sha256');
  assert.equal(hash, expect.toString('base64'), 'the stored value is exactly PBKDF2-HMAC-SHA256');
  assert.equal(enc.verifyPassword('correct horse battery staple', h), true);
  assert.equal(enc.verifyPassword('wrong', h), false);
  assert.equal(enc.needsRehash(h), false);
  assert.notEqual(enc.hashPassword('x'), enc.hashPassword('x'), 'salted');
});

test('a legacy scrypt hash still verifies, and a successful verify hands back a PBKDF2 re-hash', () => {
  const legacy = legacyScryptHash('hunter22');
  assert.equal(enc.parsePasswordHash(legacy).scheme, 'scrypt');
  assert.equal(enc.needsRehash(legacy), true);
  const stored = { value: legacy };
  const onRehash = (h) => { stored.value = h; };
  assert.equal(enc.verifyPassword('nope', legacy, { onRehash }), false);
  assert.equal(stored.value, legacy, 'a failed sign-in never re-hashes');
  assert.equal(enc.verifyPassword('hunter22', legacy, { onRehash }), true);
  assert.match(stored.value, /^pbkdf2-sha256\$600000\$/);
  assert.equal(enc.verifyPassword('hunter22', stored.value), true, 'the replacement verifies the same password');
  let again = 0;
  enc.verifyPassword('hunter22', stored.value, { onRehash: () => again++ });
  assert.equal(again, 0, 'a current PBKDF2 hash is not re-hashed');
});

test('a PBKDF2 hash below the current iteration count is re-hashed on sign-in', () => {
  const weak = enc.hashPassword('pw', { iterations: 200000 });
  let out = null;
  assert.equal(enc.verifyPassword('pw', weak, { onRehash: (h) => { out = h; } }), true);
  assert.match(out, /^pbkdf2-sha256\$600000\$/);
});

test('when scrypt is unavailable (as under a FIPS provider) a legacy hash fails closed and says so', (t) => {
  const legacy = legacyScryptHash('pw');
  t.mock.method(crypto, 'scryptSync', () => { throw Object.assign(new Error('unsupported'), { code: 'ERR_OSSL_EVP_UNSUPPORTED' }); });
  let flagged = 0;
  assert.equal(enc.verifyPassword('pw', legacy, { onLegacyUnavailable: () => flagged++ }), false);
  assert.equal(flagged, 1);
  assert.equal(enc.scryptAvailable(), false);
});

test('format parsing rejects garbage instead of throwing', () => {
  const good = enc.hashPassword('pw');
  const [, , salt, hash] = good.split('$');
  const bad = [
    null, undefined, 42, '', 'garbage', ':', 'abc:def',
    'a'.repeat(32) + ':' + 'b'.repeat(127),
    'A'.repeat(32) + ':' + 'b'.repeat(128),
    `pbkdf2-sha256$600000$${salt}`,
    `pbkdf2-sha1$600000$${salt}$${hash}`,
    `pbkdf2-sha256$0$${salt}$${hash}`,
    `pbkdf2-sha256$1000$${salt}$${hash}`,
    `pbkdf2-sha256$99999999$${salt}$${hash}`,
    `pbkdf2-sha256$6e5$${salt}$${hash}`,
    `pbkdf2-sha256$600000$${salt}$${hash}$extra`,
    `pbkdf2-sha256$600000$!!!!$${hash}`,
    `pbkdf2-sha256$600000$${Buffer.alloc(8).toString('base64')}$${hash}`,
    `pbkdf2-sha256$600000$${salt}$${Buffer.alloc(16).toString('base64')}`,
  ];
  for (const b of bad) {
    assert.equal(enc.parsePasswordHash(b), null, `parsed ${JSON.stringify(b)}`);
    assert.equal(enc.verifyPassword('pw', b), false);
    assert.equal(enc.needsRehash(b), true);
  }
});
