import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { redeemSsoCode } from '../studio-web/src/utils/ssoHandoff.ts';

// /login?oidc_token=<attacker's token> signed the victim in as the attacker: the
// page stored whatever the URL carried. No page may take a session from a URL any
// more. Chrome run of the same attack: scratchpad harness, scenario I. Source
// checks here because the two pages are not loadable under node:test.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const LOGIN = read('studio-web/src/components/Login.tsx');
const LEGACY = read('docs/login.html');
const ADMIN_APP = read('studio-web/src/AdminApp.tsx');

function fakeStore() {
  const m = new Map();
  return { m, setItem: (k, v) => m.set(k, v) };
}

test('redeemSsoCode posts the code in the body and stores only what the server returned', async () => {
  const calls = [];
  const store = fakeStore();
  const ok = await redeemSsoCode('the-code', {
    fetch: async (url, init) => { calls.push({ url, init }); return { ok: true, json: async () => ({ token: 'from-server' }) }; },
    store,
  });
  assert.equal(ok, true);
  assert.equal(store.m.get('cc_identity_token'), 'from-server');
  assert.equal(calls[0].url, '/api/auth/oidc/handoff', 'the code must not go in the URL');
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), { code: 'the-code' });
});

test('redeemSsoCode stores nothing on a refusal, a bad body or a network failure', async () => {
  for (const fetchImpl of [
    async () => ({ ok: false, json: async () => ({ token: 'should-not-be-used' }) }),
    async () => ({ ok: true, json: async () => ({}) }),
    async () => ({ ok: true, json: async () => ({ token: 7 }) }),
    async () => ({ ok: true, json: async () => { throw new Error('not json'); } }),
    async () => { throw new Error('offline'); },
  ]) {
    const store = fakeStore();
    assert.equal(await redeemSsoCode('c', { fetch: fetchImpl, store }), false);
    assert.equal(store.m.size, 0);
  }
});

test('Login.tsx never reads a session from the URL; it scrubs both params before anything navigates', () => {
  assert.doesNotMatch(LOGIN, /params\.get\('oidc_token'\)/);
  assert.doesNotMatch(LOGIN, /setItem\('cc_identity_token', (oidcToken|params)/);
  const oldScrub = LOGIN.indexOf("searchParams.delete('oidc_token')");
  const newScrub = LOGIN.indexOf("searchParams.delete('sso_code')");
  const redeemAt = LOGIN.indexOf('redeemSsoCode(');
  assert.ok(oldScrub > 0 && newScrub > 0 && redeemAt > 0, 'scrub or redeem missing');
  assert.ok(oldScrub < redeemAt && newScrub < redeemAt, 'the code must leave the address bar before the exchange');
});

test('docs/login.html does not store a token from the URL, and still removes a stale one', () => {
  assert.doesNotMatch(LEGACY, /params\.get\('oidc_token'\)\s*;[\s\S]{0,120}setItem/);
  assert.doesNotMatch(LEGACY, /const oidcToken/);
  assert.doesNotMatch(LEGACY, /setAuthCookie\(oidcToken\)/);
  assert.match(LEGACY, /searchParams\.delete\('oidc_token'\)/);
});

test('AdminApp scrubs the code as well as a stale token before its own deep-link replace', () => {
  const before = ADMIN_APP.slice(ADMIN_APP.indexOf('checkSession({'), ADMIN_APP.indexOf('window.location.replace(next.target'));
  assert.match(before, /searchParams\.delete\('sso_code'\)/);
  assert.match(before, /searchParams\.delete\('oidc_token'\)/);
});

test('AdminApp also cleans the address bar when it is already signed in and Login never mounts', () => {
  assert.match(ADMIN_APP, /if \(!auth\.isAuthed\) return\s+const url = new URL\(window\.location\.href\)[\s\S]{0,240}delete\('sso_code'\)[\s\S]{0,120}replaceState/);
});
