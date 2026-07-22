import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'os';
import { join, sep, resolve } from 'path';
import { rmSync, existsSync, writeFileSync } from 'fs';
import {
  orgFromEmail, tenantKey, tenantDir, tenantDbPath,
  tenantStorageDir, tenantFile, tenantUsage, tenantQuotaBytes, assertTenantQuota,
} from './index.js';

// Minimal fake requests in both supported shapes.
const expressReq = (headers) => ({ get: (n) => headers[n] });
const nodeReq = (headers) => ({ headers });

test('orgFromEmail: domain, lowercased, sanitised, unknown fallback', () => {
  assert.equal(orgFromEmail('alice@acme.com'), 'acme.com');
  assert.equal(orgFromEmail('Alice@ACME.com'), 'acme.com');
  assert.equal(orgFromEmail('a+tag@sub.acme.co.uk'), 'sub.acme.co.uk');
  assert.equal(orgFromEmail('a@b@corp.com'), 'corp.com'); // domain = after LAST '@'
  assert.equal(orgFromEmail('no-at-sign'), 'unknown');
  assert.equal(orgFromEmail(''), 'unknown');
  assert.equal(orgFromEmail(null), 'unknown');
});

test('tenantKey: reads both req shapes, sanitises id, requires identity', () => {
  const h = { 'X-AppCrane-User-Email': 'bob@acme.com', 'X-AppCrane-User-Id': '42' };
  assert.deepEqual(tenantKey(expressReq(h)), { org: 'acme.com', userId: '42' });
  assert.deepEqual(tenantKey(nodeReq(h)), { org: 'acme.com', userId: '42' });
  // non-digit chars stripped from id
  assert.equal(tenantKey(expressReq({ 'X-AppCrane-User-Email': 'x@y.com', 'X-AppCrane-User-Id': ' 7 ' })).userId, '7');
  // no id → throw
  assert.throws(() => tenantKey(expressReq({ 'X-AppCrane-User-Email': 'x@y.com' })), /no tenant identity/);
});

test('tenantDir / tenantDbPath: correct shape under a custom root', () => {
  const root = join(tmpdir(), 'appcrane-tenant-test-' + process.pid);
  rmSync(root, { recursive: true, force: true });
  const req = expressReq({ 'X-AppCrane-User-Email': 'c@acme.com', 'X-AppCrane-User-Id': '9' });
  const dir = tenantDir(req, { root });
  assert.equal(dir, join(root, 'acme.com', 'u9'));
  assert.ok(existsSync(dir), 'dir is created by default');
  assert.equal(tenantDbPath(req, { root }), join(root, 'acme.com', 'u9', 'db.sqlite'));
  rmSync(root, { recursive: true, force: true });
});

test('tenantStorageDir / tenantFile: storage path + filename safety', () => {
  const root = join(tmpdir(), 'appcrane-tenant-store-' + process.pid);
  rmSync(root, { recursive: true, force: true });
  const req = expressReq({ 'X-AppCrane-User-Email': 'd@acme.com', 'X-AppCrane-User-Id': '3' });
  assert.equal(tenantStorageDir(req, { root }), join(root, 'acme.com', 'u3', 'storage'));
  assert.equal(tenantFile(req, 'photo.png', { root }), join(root, 'acme.com', 'u3', 'storage', 'photo.png'));
  // user-supplied filenames can't traverse
  assert.equal(tenantFile(req, '../../etc/passwd', { root }), join(root, 'acme.com', 'u3', 'storage', 'passwd'));
  for (const bad of ['', '.', '..', '/', 'a/../../b']) {
    // 'a/../../b' -> basename 'b' is fine; the traversal-only ones must throw
    if (['', '.', '..', '/'].includes(bad)) assert.throws(() => tenantFile(req, bad, { root }), /invalid filename/);
  }
  rmSync(root, { recursive: true, force: true });
});

test('tenantUsage / quota: measures bytes and enforces the limit', () => {
  const root = join(tmpdir(), 'appcrane-tenant-quota-' + process.pid);
  rmSync(root, { recursive: true, force: true });
  const req = expressReq({ 'X-AppCrane-User-Email': 'e@acme.com', 'X-AppCrane-User-Id': '4' });
  assert.equal(tenantUsage(req, { root }), 0, 'no dir yet -> 0 bytes');
  writeFileSync(tenantFile(req, 'a.txt', { root }), 'x'.repeat(100));
  writeFileSync(tenantFile(req, 'b.txt', { root }), 'y'.repeat(50));
  assert.equal(tenantUsage(req, { root }), 150, 'sums files recursively');

  const prev = process.env.APPCRANE_TENANT_QUOTA_BYTES;
  try {
    delete process.env.APPCRANE_TENANT_QUOTA_BYTES;
    assert.equal(tenantQuotaBytes(), 0);
    assert.doesNotThrow(() => assertTenantQuota(req, { root }), 'unlimited -> no-op');
    process.env.APPCRANE_TENANT_QUOTA_BYTES = '1000';
    assert.equal(tenantQuotaBytes(), 1000);
    assert.doesNotThrow(() => assertTenantQuota(req, { root }), 'under quota');
    process.env.APPCRANE_TENANT_QUOTA_BYTES = '100';
    assert.throws(() => assertTenantQuota(req, { root }), /quota exceeded/);
  } finally {
    if (prev === undefined) delete process.env.APPCRANE_TENANT_QUOTA_BYTES;
    else process.env.APPCRANE_TENANT_QUOTA_BYTES = prev;
  }
  rmSync(root, { recursive: true, force: true });
});

test('path-traversal safety: hostile emails cannot escape the root', () => {
  const root = resolve(join(tmpdir(), 'appcrane-tenant-trav-' + process.pid));
  // Pure-dot domains would otherwise become '.'/'..' path segments.
  assert.equal(orgFromEmail('a@..'), 'unknown');
  assert.equal(orgFromEmail('a@.'), 'unknown');
  const hostile = ['evil@../../etc/passwd', 'x@..', 'y@.', 'z@/etc'];
  for (const email of hostile) {
    const dir = resolve(tenantDir(expressReq({ 'X-AppCrane-User-Email': email, 'X-AppCrane-User-Id': '1' }), { root, create: false }));
    assert.ok(dir.startsWith(root + sep), `"${email}" stays under root (got ${dir})`);
  }
});
