import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactAuditArgs } from '../server/utils/auditRedact.js';

// The contract: no credential-bearing argument may ever reach audit_log in
// plaintext, and no single call may write an unbounded payload into it.

test('masks credential-bearing keys', () => {
  const out = redactAuditArgs({
    slug: 'my-app',
    value: 'super-secret-value',
    github_token: 'ghp_aaaaaaaaaaaaaaaaaaaa',
    client_secret: 'xyz',
    password: 'hunter2',
    api_key: 'dhk_admin_abc',
    old_key: 'deadbeef',
  });

  assert.equal(out.slug, 'my-app', 'non-secret args survive — the trail is still useful');
  for (const k of ['value', 'github_token', 'client_secret', 'password', 'api_key', 'old_key']) {
    assert.match(String(out[k]), /^\[redacted/, `${k} must be masked`);
    assert.ok(!String(out[k]).includes('secret'), `${k} must not leak its value`);
  }
  assert.ok(!JSON.stringify(out).includes('ghp_aaaaaaaaaaaaaaaaaaaa'), 'token absent from payload');
  assert.ok(!JSON.stringify(out).includes('hunter2'), 'password absent from payload');
});

test('distinguishes "cleared" from "rotated" without revealing bytes', () => {
  assert.equal(redactAuditArgs({ github_token: '' }).github_token, '[redacted:empty]');
  assert.match(redactAuditArgs({ github_token: 'abcd' }).github_token, /\[redacted:4 chars\]/);
});

test('masks nested and array-nested secrets', () => {
  const out = redactAuditArgs({
    config: { settings: [{ key: 'smtp', value: 'p@ssw0rd' }] },
  });
  assert.ok(!JSON.stringify(out).includes('p@ssw0rd'), 'nested secret must not survive');
});

test('truncates oversized strings so one call cannot bloat the DB', () => {
  const big = 'A'.repeat(50_000);
  const out = redactAuditArgs({ content: big });
  assert.ok(out.content.length < 300, `expected truncation, got ${out.content.length}`);
  assert.match(out.content, /truncated 49880 chars/);
});

test('caps long arrays', () => {
  const out = redactAuditArgs({ files: Array.from({ length: 100 }, (_, i) => ({ path: `f${i}` })) });
  assert.equal(out.files.length, 21, '20 entries + a "+N more" marker');
  assert.match(String(out.files[20]), /\+80 more/);
});

test('leaves primitives and unknown keys intact', () => {
  const out = redactAuditArgs({ env: 'sandbox', count: 3, ok: true, missing: null });
  assert.deepEqual(out, { env: 'sandbox', count: 3, ok: true, missing: null });
});

test('never throws on hostile input', () => {
  const circular = {};
  circular.self = circular;
  assert.doesNotThrow(() => redactAuditArgs(circular));
  assert.doesNotThrow(() => redactAuditArgs(undefined));
});
