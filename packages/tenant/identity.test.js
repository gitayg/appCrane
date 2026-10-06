import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { tenantKey, signIdentity } from './index.js';

// With APPCRANE_IDENTITY_SECRET set (AppCrane 2.97.0+), tenantKey() only trusts
// identity AppCrane signed, so a forged X-AppCrane-User-Id cannot pick another
// user's tenant folder.

const SECRET = 'test-secret-0123456789abcdef0123456789';
afterEach(() => { delete process.env.APPCRANE_IDENTITY_SECRET; });

function signed(fields) {
  const ts = Math.floor(Date.now() / 1000);
  const h = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k.toLowerCase(), v]));
  h['x-appcrane-identity-ts'] = String(ts);
  h['x-appcrane-identity-sig'] = signIdentity(SECRET, ts, (name) => h[name.toLowerCase()]);
  return h;
}

test('without the secret, tenantKey reads the headers as before', () => {
  assert.deepEqual(tenantKey({ 'x-appcrane-user-id': '7', 'x-appcrane-user-email': 'a@acme.test' }), { org: 'acme.test', userId: '7' });
});

test('with the secret, signed identity is accepted', () => {
  process.env.APPCRANE_IDENTITY_SECRET = SECRET;
  assert.deepEqual(tenantKey(signed({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-User-Email': 'a@acme.test' })), { org: 'acme.test', userId: '7' });
});

test('with the secret, forged identity cannot choose a tenant', () => {
  process.env.APPCRANE_IDENTITY_SECRET = SECRET;
  assert.throws(() => tenantKey({ 'x-appcrane-user-id': '1', 'x-appcrane-user-email': 'victim@acme.test' }), /signature/);
  const h = signed({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-User-Email': 'a@acme.test' });
  h['x-appcrane-user-id'] = '1';
  assert.throws(() => tenantKey(h), /signature/);
});
