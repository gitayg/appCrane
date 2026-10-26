import { test, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';

// The MariaDB key file's wrapping KDF: legacy EVP_BytesToKey/SHA-1 stays the
// default (existing servers are untouched), APPCRANE_TDE_KDF=pbkdf2-sha256
// wraps it as `openssl enc -aes-256-cbc -md sha256 -pbkdf2 -iter 600000`.
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tdekdf-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
delete process.env.APPCRANE_TDE_KDF;
delete process.env.MANAGED_DB_MARIADB_IMAGE;
const tde = await import('../server/services/managedDbEncryption.js');
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));
afterEach(() => { delete process.env.APPCRANE_TDE_KDF; delete process.env.MANAGED_DB_MARIADB_IMAGE; });

const PBKDF2 = { name: 'pbkdf2-sha256', iterations: 600000 };

function db() {
  const d = new Database(':memory:');
  d.exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_by INTEGER, updated_at TEXT)');
  return d;
}

// Reference implementation of openssl enc's PBKDF2 path, independent of the module.
function opensslPbkdf2Decrypt(buf, pass, iter) {
  const out = crypto.pbkdf2Sync(pass, buf.subarray(8, 16), iter, 48, 'sha256');
  const d = crypto.createDecipheriv('aes-256-cbc', out.subarray(0, 32), out.subarray(32));
  return Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString('utf8');
}

test('default stays legacy: same flags, same fingerprint input, SHA-1 wrap still reads', () => {
  assert.deepEqual(tde.keyFileKdf(), { name: 'legacy' });
  assert.deepEqual(tde.kdfServerArgs(tde.keyFileKdf()), []);
  assert.ok(!tde.serverArgs('encrypt').some((a) => a.includes('digest') || a.includes('pbkdf2')));
  const fpLegacy = crypto.createHash('sha256').update(`fp:${tde.fileKey()}`).digest('hex').slice(0, 12);
  assert.equal(tde.fileKeyFingerprint(), fpLegacy, 'a legacy server is not recreated by this release');
  const buf = tde.wrapKeyFile('1;abc\n', 'secret');
  assert.equal(tde.unwrapKeyFile(buf, 'secret'), '1;abc\n');
  assert.equal(tde.unwrapKeyFile(buf, 'secret', { name: 'legacy' }), '1;abc\n');
});

test('pbkdf2-sha256 wrap is openssl-enc compatible and deterministic for a given salt', (t) => {
  const buf = tde.wrapKeyFile('1;abc\n', 'secret', PBKDF2);
  assert.equal(buf.subarray(0, 8).toString('latin1'), 'Salted__');
  assert.equal(opensslPbkdf2Decrypt(buf, 'secret', 600000), '1;abc\n');
  assert.equal(tde.unwrapKeyFile(buf, 'secret', PBKDF2), '1;abc\n');
  assert.throws(() => tde.unwrapKeyFile(buf, 'secret'), 'a PBKDF2 file does not read as legacy');
  const fixed = Buffer.alloc(8, 7);
  t.mock.method(crypto, 'randomBytes', () => fixed);
  assert.deepEqual(tde.wrapKeyFile('1;abc\n', 'secret', PBKDF2), tde.wrapKeyFile('1;abc\n', 'secret', PBKDF2));
});

test('APPCRANE_TDE_KDF=pbkdf2-sha256 adds the matching plugin flags and changes the fingerprint', () => {
  const legacyFp = tde.fileKeyFingerprint();
  process.env.APPCRANE_TDE_KDF = 'pbkdf2-sha256';
  const args = tde.serverArgs('encrypt');
  assert.ok(args.includes('--file-key-management-digest=sha256'));
  assert.ok(args.includes('--file-key-management-use-pbkdf2=600000'));
  assert.ok(tde.serverArgs('decrypt').includes('--file-key-management-use-pbkdf2=600000'));
  assert.notEqual(tde.fileKeyFingerprint(), legacyFp, 'switching recreates the container once');
  process.env.APPCRANE_TDE_KDF = 'md5';
  assert.throws(() => tde.keyFileKdf(), /legacy or pbkdf2-sha256/);
});

test('writeKeyFile wraps with the chosen KDF, and refuses a MariaDB image older than 12', () => {
  const d = db();
  tde.enable(d);
  process.env.APPCRANE_TDE_KDF = 'pbkdf2-sha256';
  assert.throws(() => tde.writeKeyFile(d), /needs MariaDB 12\.0 or later.*mariadb:11\.4/);
  process.env.MANAGED_DB_MARIADB_IMAGE = 'mariadb:12.0';
  const dir = tde.writeKeyFile(d);
  const buf = readFileSync(join(dir, tde.KEY_FILE));
  assert.match(opensslPbkdf2Decrypt(buf, tde.fileKey(), 600000), /^1;[0-9a-f]{64}\n$/);
  assert.equal(tde.keyFileUsesLegacyKdf(d), false);
  delete process.env.APPCRANE_TDE_KDF;
  const legacyDir = tde.writeKeyFile(d);
  assert.match(tde.unwrapKeyFile(readFileSync(join(legacyDir, tde.KEY_FILE)), tde.fileKey()), /^1;[0-9a-f]{64}\n$/, 'switching back re-wraps the SAME key legacy');
  assert.equal(tde.keyFileUsesLegacyKdf(d), true);
});

test('image version parsing', () => {
  assert.equal(tde.kdfImageRefusal({ name: 'legacy' }, 'mariadb:10.6'), null);
  assert.equal(tde.kdfImageRefusal(PBKDF2, 'mariadb:12.0.2'), null);
  assert.equal(tde.kdfImageRefusal(PBKDF2, 'mariadb:12'), null);
  assert.match(tde.kdfImageRefusal(PBKDF2, 'reg.example:5000/mariadb:11.8-ubi'), /needs MariaDB 12/);
  assert.equal(tde.kdfImageRefusal(PBKDF2, 'mariadb:latest'), null, 'an unparseable tag is not refused here');
});
