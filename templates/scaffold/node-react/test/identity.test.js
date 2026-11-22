import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { TEST_SECRET, signedHeaders } from './helpers.js';
import { verifyRequest, atLeast, signIdentityV2 } from '../server/identity.js';

const verify = (headers, opts) => verifyRequest({ headers }, opts);

// A known answer computed by AppCrane's own signer (appcrane-tenant
// signIdentityV2). If this fails, this copy signs different bytes than the
// platform and no real request would verify.
test('matches AppCrane\'s signer byte for byte', () => {
  const headers = {
    'x-appcrane-user': 'kat@example.test',
    'x-appcrane-user-id': '7',
    'x-appcrane-user-email': 'kat@example.test',
    'x-appcrane-user-name': 'K%C3%A4t%20Tester',
    'x-appcrane-user-role': 'user',
    'x-appcrane-app-role': 'admin',
    'x-appcrane-is-admin': '1',
    'x-appcrane-app-roles': 'approver,auditor',
    'x-appcrane-auth-via': 'app-key',
  };
  assert.equal(signIdentityV2('known-answer-only', 1700000000, headers), 'Bm6H2230lr8CqUJ9vcOPtxZj9z3umJzlGjTjY2FRZ-o');
  delete headers['x-appcrane-app-roles'];
  delete headers['x-appcrane-auth-via'];
  assert.equal(signIdentityV2('known-answer-only', 1700000000, headers), 'OyZ3qwyGsbpbIPfWQw-8s4LA3dxePNBv7t7v6hd29Mo');
  const r = verify({ ...headers, 'x-appcrane-identity-ts': '1700000000', 'x-appcrane-identity-sig-v2': 'OyZ3qwyGsbpbIPfWQw-8s4LA3dxePNBv7t7v6hd29Mo' },
    { secret: 'known-answer-only', now: 1700000010 * 1000 });
  assert.equal(r.ok, true, r.message);
  assert.equal(r.identity.name, 'Kät Tester');
});

test('a correctly signed identity verifies and is read', () => {
  const r = verify(signedHeaders({ appRole: 'admin', appRoles: 'approver,auditor' }));
  assert.equal(r.ok, true, r.message);
  assert.equal(r.identity.userId, '42');
  assert.equal(r.identity.email, 'person@example.test');
  assert.equal(r.identity.name, 'Test Person');
  assert.equal(r.identity.appRole, 'admin');
  assert.equal(r.identity.isAppAdmin, true);
  assert.deepEqual(r.identity.appRoles, ['approver', 'auditor']);
  assert.equal(r.identity.authVia, 'session');
});

test('headers with no signature are refused, however convincing', () => {
  const h = signedHeaders({ appRole: 'owner' });
  delete h['x-appcrane-identity-sig-v2'];
  assert.equal(verify(h).code, 'IDENTITY_UNSIGNED');
  assert.equal(verify({}).code, 'IDENTITY_UNSIGNED');
});

test('a signature made with another secret is refused', () => {
  const forged = signedHeaders({ appRole: 'owner', secret: randomBytes(32).toString('base64url') });
  assert.equal(verify(forged).code, 'IDENTITY_FORGED');
});

test('changing any signed header after signing is refused', () => {
  for (const [name, value] of [
    ['x-appcrane-app-role', 'owner'],
    ['x-appcrane-user-id', '1'],
    ['x-appcrane-is-admin', '1'],
    ['x-appcrane-app-roles', 'approver'],
    ['x-appcrane-auth-via', 'session'],
  ]) {
    const h = signedHeaders({ appRole: 'viewer' });
    h[name] = value;
    assert.equal(verify(h).code, 'IDENTITY_FORGED', `${name} was not covered by the signature`);
  }
});

test('removing x-appcrane-auth-via (an app-key call passed off as a browser) is refused', () => {
  const h = signedHeaders({ extra: { 'x-appcrane-auth-via': 'app-key' } });
  assert.equal(verify(h).identity.authVia, 'app-key');
  delete h['x-appcrane-auth-via'];
  assert.equal(verify(h).code, 'IDENTITY_FORGED');
});

test('an old signature is refused', () => {
  const ts = Math.floor(Date.now() / 1000) - 301;
  assert.equal(verify(signedHeaders({ ts })).code, 'IDENTITY_EXPIRED');
});

test('with no secret configured nothing verifies', () => {
  assert.equal(verify(signedHeaders(), { secret: '' }).code, 'IDENTITY_NOT_CONFIGURED');
  assert.ok(TEST_SECRET);
});

test('role ladder: an owner passes an admin check, a viewer does not pass user', () => {
  assert.equal(atLeast('owner', 'admin'), true);
  assert.equal(atLeast('admin', 'admin'), true);
  assert.equal(atLeast('viewer', 'user'), false);
  assert.equal(atLeast('bogus', 'viewer'), false);
});
