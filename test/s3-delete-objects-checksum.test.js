import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { startFakeS3 } from './fake-s3.mjs';
import { s3DeleteObjects, s3PutObject, deleteObjectsChecksumHeaders } from '../server/services/s3.js';

// DeleteObjects carries x-amz-checksum-sha256 (signed) instead of the MD5
// Content-MD5 a FIPS provider refuses. The fake verifies the SigV4 signature
// itself, rejects any unsigned x-amz-* header, and checks the checksum.
const fake = await startFakeS3();
after(() => fake.close());

const seed = async (keys) => { for (const k of keys) await s3PutObject({ ...fake.conn, key: k, body: k }); };

test('DeleteObjects sends a correct, signed x-amz-checksum-sha256 and no Content-MD5', async (t) => {
  const seen = [];
  const realFetch = globalThis.fetch;
  t.mock.method(globalThis, 'fetch', (url, init) => { seen.push(init); return realFetch(url, init); });
  await seed(['a/1', 'a/2', 'a/<&3>']);
  const r = await s3DeleteObjects(fake.conn, ['a/1', 'a/2', 'a/<&3>']);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.deleted.sort(), ['a/1', 'a/2', 'a/<&3>']);
  assert.equal(fake.objects.size, 0);
  const del = seen.find((i) => i.method === 'POST');
  const h = del.headers;
  assert.equal(h['content-md5'], undefined, 'no Content-MD5');
  assert.equal(h['x-amz-checksum-sha256'], crypto.createHash('sha256').update(del.body).digest('base64'));
  assert.equal(h['x-amz-sdk-checksum-algorithm'], 'SHA256');
  const signed = /SignedHeaders=([^,]+)/.exec(h.authorization)[1].split(';');
  assert.ok(signed.includes('x-amz-checksum-sha256'), 'checksum header is signed');
  assert.ok(signed.includes('x-amz-sdk-checksum-algorithm'));
  const entry = fake.log.find((l) => l.op === 'DELETE-OBJECTS');
  assert.equal(entry.checksum, 'sha256');
  assert.equal(entry.rejected, undefined, 'the fake accepted the signature');
});

test('the checksum header is the base64 SHA-256 of the exact body', () => {
  const body = Buffer.from('<Delete><Object><Key>k</Key></Object></Delete>');
  assert.equal(deleteObjectsChecksumHeaders(body)['x-amz-checksum-sha256'], crypto.createHash('sha256').update(body).digest('base64'));
});

test('a server that insists on Content-MD5 gets it on a retry while MD5 is available', async () => {
  fake.state.requireMd5 = true;
  try {
    await seed(['b/1', 'b/2']);
    const r = await s3DeleteObjects(fake.conn, ['b/1', 'b/2']);
    assert.deepEqual(r.deleted.sort(), ['b/1', 'b/2']);
    const tries = fake.log.filter((l) => l.op === 'DELETE-OBJECTS').slice(-2).map((l) => l.checksum);
    assert.deepEqual(tries, ['sha256', 'md5']);
  } finally { fake.state.requireMd5 = false; }
});

test('without MD5 (FIPS), that server is served one DeleteObject per key instead', async (t) => {
  fake.state.requireMd5 = true;
  await seed(['c/1', 'c/2']);
  const real = crypto.createHash;
  t.mock.method(crypto, 'createHash', (alg, ...rest) => {
    if (String(alg).toLowerCase() === 'md5') throw Object.assign(new Error('disabled for FIPS'), { code: 'ERR_OSSL_EVP_UNSUPPORTED' });
    return real.call(crypto, alg, ...rest);
  });
  try {
    const before = fake.log.length;
    const r = await s3DeleteObjects(fake.conn, ['c/1', 'c/2']);
    assert.deepEqual(r.deleted.sort(), ['c/1', 'c/2']);
    assert.deepEqual(r.errors, []);
    assert.equal(fake.objects.size, 0);
    assert.deepEqual(fake.log.slice(before).map((l) => l.op), ['DELETE-OBJECTS', 'DELETE', 'DELETE']);
  } finally { fake.state.requireMd5 = false; }
});
