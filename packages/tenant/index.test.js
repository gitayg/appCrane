import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'os';
import { join, sep, resolve } from 'path';
import { rmSync, existsSync } from 'fs';
import { orgFromEmail, tenantKey, tenantDir, tenantDbPath } from './index.js';

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
