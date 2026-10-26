import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import Database from 'better-sqlite3';

process.env.ENCRYPTION_KEY = 'b'.repeat(64);
const fips = await import('../server/services/fipsMode.js');
const enc = await import('../server/services/encryption.js');

const quiet = { warn: () => {} };
const passing = () => ({ ok: true, md5Available: false, checks: [] });

test('APPCRANE_FIPS parsing: default off, rejects unknown values', () => {
  assert.equal(fips.fipsSetting({}), 'off');
  assert.equal(fips.fipsSetting({ APPCRANE_FIPS: ' Require ' }), 'require');
  assert.throws(() => fips.fipsSetting({ APPCRANE_FIPS: 'yes' }), /must be one of/);
});

test('require refuses to start when getFips() is 0', () => {
  assert.throws(
    () => fips.enforceFipsAtStartup({ env: { APPCRANE_FIPS: 'require' }, getFips: () => 0, check: passing, log: quiet }),
    (e) => e.code === 'FIPS_REQUIRED' && /getFips\(\) is 0/.test(e.message),
  );
});

test('require starts when getFips() is 1 and the self-check passes; refuses when MD5 is still available', () => {
  const r = fips.enforceFipsAtStartup({ env: { APPCRANE_FIPS: 'require' }, getFips: () => 1, check: passing, log: quiet });
  assert.equal(r.fipsActive, true);
  assert.deepEqual(r.problems, []);
  assert.throws(
    () => fips.enforceFipsAtStartup({ env: { APPCRANE_FIPS: 'require' }, getFips: () => 1, check: () => ({ ok: true, md5Available: true, checks: [] }), log: quiet }),
    /MD5 is available/,
  );
});

test('prefer and off never refuse', () => {
  const warned = [];
  const r = fips.enforceFipsAtStartup({ env: { APPCRANE_FIPS: 'prefer' }, getFips: () => 0, check: passing, log: { warn: (m) => warned.push(m) } });
  assert.equal(r.fipsActive, false);
  assert.equal(warned.length, 1);
  assert.equal(fips.enforceFipsAtStartup({ env: {}, getFips: () => 0 }).checked, false);
});

test('the real self-check passes its known-answer vectors here and detects MD5 as available (non-FIPS Node)', () => {
  const sc = fips.selfCheck();
  assert.equal(sc.ok, true, JSON.stringify(sc.checks));
  assert.deepEqual(sc.checks.map((c) => c.name), ['sha256', 'hmac-sha256', 'pbkdf2-hmac-sha256', 'aes-256-gcm', 'csprng']);
  assert.equal(sc.md5Available, crypto.getFips() !== 1);
});

test('the self-check reports MD5 unavailable when createHash(md5) throws, and a broken algorithm fails', () => {
  const real = crypto.createHash;
  const fake = Object.create(crypto);
  fake.createHash = (alg, ...r) => { if (alg === 'md5') throw new Error('unsupported'); return real.call(crypto, alg, ...r); };
  assert.equal(fips.selfCheck(fake).md5Available, false);
  const broken = Object.create(crypto);
  broken.pbkdf2Sync = () => Buffer.alloc(64);
  const sc = fips.selfCheck(broken);
  assert.equal(sc.ok, false);
  assert.equal(sc.checks.find((c) => c.name === 'pbkdf2-hmac-sha256').ok, false);
  assert.throws(() => fips.enforceFipsAtStartup({ env: { APPCRANE_FIPS: 'require' }, getFips: () => 1, check: () => sc, log: quiet }), /pbkdf2-hmac-sha256 failed/);
});

test('cryptoStatus counts legacy password hashes and never returns one', () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, password_hash TEXT); CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_by INTEGER, updated_at TEXT)');
  const salt = 'a'.repeat(32);
  const legacy = `${salt}:${crypto.scryptSync('x', salt, 64).toString('hex')}`;
  const pb = enc.hashPassword('x');
  for (const h of [legacy, legacy, pb, null, 'junk']) db.prepare('INSERT INTO users (password_hash) VALUES (?)').run(h);
  const s = fips.cryptoStatus(db, { env: { APPCRANE_FIPS: 'prefer' }, getFips: () => 0 });
  assert.equal(s.mode, 'prefer');
  assert.equal(s.fipsActive, false);
  assert.equal(s.openssl, process.versions.openssl);
  assert.deepEqual(s.legacy.map((l) => [l.id, l.count]), [['password-scrypt', 2], ['password-unreadable', 1]]);
  assert.equal(s.claimable, false);
  const text = JSON.stringify(s);
  assert.ok(!text.includes(legacy.slice(33, 60)) && !text.includes(pb.split('$')[3]), 'no hash material in the status');
});
