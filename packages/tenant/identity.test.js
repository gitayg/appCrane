import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { tenantKey, signIdentity, signIdentityV2, signIdentityV3, verifyIdentity, authenticatedWithin, stepUpUrl } from './index.js';

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

// 1.3.0: v1 does not cover X-AppCrane-Auth-Via, so off the proxy a script call
// signed in with a personal app key could drop 'app-key' and pass as a browser.
function signedV2(fields) {
  const h = signed(fields);
  h['x-appcrane-identity-sig-v2'] = signIdentityV2(SECRET, h['x-appcrane-identity-ts'], (name) => h[name.toLowerCase()]);
  return h;
}

test('v2 vouches for Auth-Via: app-key, and a browser session reads as session', () => {
  const key = signedV2({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-Auth-Via': 'app-key' });
  assert.equal(verifyIdentity(key, { secret: SECRET }).authVia, 'app-key');
  assert.equal(verifyIdentity(signedV2({ 'X-AppCrane-User-Id': '7' }), { secret: SECRET }).authVia, 'session');
});

test('v2: removing Auth-Via after signing is rejected', () => {
  const h = signedV2({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-Auth-Via': 'app-key' });
  delete h['x-appcrane-auth-via'];
  assert.throws(() => verifyIdentity(h, { secret: SECRET }), /signature/);
});

test('v1 only: still verifies, but Auth-Via is unknown, and requireV2 refuses it', () => {
  const h = signedV2({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-Auth-Via': 'app-key' });
  delete h['x-appcrane-identity-sig-v2'];
  delete h['x-appcrane-auth-via'];
  assert.equal(verifyIdentity(h, { secret: SECRET }).authVia, null);
  assert.throws(() => verifyIdentity(h, { secret: SECRET, requireV2: true }), /v2 missing/);
});

// 1.4.0: v3 also covers when and how the person last authenticated.
function signedV3(fields) {
  const h = signedV2(fields);
  h['x-appcrane-identity-sig-v3'] = signIdentityV3(SECRET, h['x-appcrane-identity-ts'], (name) => h[name.toLowerCase()]);
  return h;
}

test('v3 carries authTime and mfa; v1 and v2 beside it still verify on their own', () => {
  const at = Math.floor(Date.now() / 1000) - 120;
  const h = signedV3({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-Auth-Time': String(at), 'X-AppCrane-Auth-Mfa': 'totp' });
  const id = verifyIdentity(h, { secret: SECRET, requireV3: true });
  assert.equal(id.authTime, at);
  assert.equal(id.mfa, 'totp');
  assert.equal(authenticatedWithin(id, 300), true);
  assert.equal(authenticatedWithin(id, 60), false);
  const v2 = { ...h };
  delete v2['x-appcrane-identity-sig-v3'];
  assert.equal(verifyIdentity(v2, { secret: SECRET }).authTime, null);
  assert.throws(() => verifyIdentity(v2, { secret: SECRET, requireV3: true }), /v3 missing/);
});

test('v3: a moved-forward auth time or a changed factor is rejected', () => {
  const h = signedV3({ 'X-AppCrane-User-Id': '7', 'X-AppCrane-Auth-Time': '1000', 'X-AppCrane-Auth-Mfa': 'none' });
  assert.throws(() => verifyIdentity({ ...h, 'x-appcrane-auth-time': String(Math.floor(Date.now() / 1000)) }, { secret: SECRET }), /signature/);
  assert.throws(() => verifyIdentity({ ...h, 'x-appcrane-auth-mfa': 'totp' }, { secret: SECRET }), /signature/);
});

test('stepUpUrl names the app and return URL, encoded', () => {
  const u = new URL(stepUpUrl({ craneUrl: 'https://crane.example.test/', app: 'shop', returnUrl: 'https://shop.apps.example.test/pay?x=1&y=2' }));
  assert.equal(u.origin + u.pathname, 'https://crane.example.test/api/identity/step-up/app');
  assert.equal(u.searchParams.get('app'), 'shop');
  assert.equal(u.searchParams.get('return'), 'https://shop.apps.example.test/pay?x=1&y=2');
});
