import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { isSafeRedirect } from '../server/utils/safeRedirect.js';
import {
  readLandingIntent, initialLanding, checkSession, allowRedirect, clearRedirectAttempts, afterCheck,
  REDIRECT_MAX, REDIRECT_WINDOW_MS, REDIRECT_STORE_PREFIX,
} from '../studio-web/src/utils/landingRedirect.ts';

// The sign-in landing page's ?redirect= decision.
//
// Measured in a real browser (v2.77.0): forward_auth refuses /<slug> and sends the
// browser to /login -> /launch?redirect=/<slug>; the landing page forwarded back
// to /<slug> whenever a token merely EXISTED in localStorage. A token whose
// session was gone looped 297 times in 5 s inside an embedded frame, until the
// per-IP API limiter started answering 429. A user with no role on the app looped
// the same way, because `denied=1` was ignored.

const ADMIN_APP = readFileSync(new URL('../studio-web/src/AdminApp.tsx', import.meta.url), 'utf8');

function memStore() {
  const m = new Map();
  return {
    m,
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

function fakeFetch(respond) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, ...init }); return respond(url, init); };
  return { fn, calls };
}

test('readLandingIntent: a safe deep link is a target; unsafe or landing routes are not', () => {
  assert.equal(readLandingIntent('?redirect=%2Fproduct-roadmap-v2', isSafeRedirect).target, '/product-roadmap-v2');
  for (const bad of ['//evil.example.com', '/\\evil.example.com', 'https://evil.example.com/', 'javascript:alert(1)', '']) {
    assert.equal(readLandingIntent('?redirect=' + encodeURIComponent(bad), isSafeRedirect).target, null, bad);
  }
  for (const landing of ['/launch', '/launch?x=1', '/login', '/applications/', '/launch/foo']) {
    assert.equal(readLandingIntent('?redirect=' + encodeURIComponent(landing), isSafeRedirect).target, null, landing);
  }
  assert.equal(readLandingIntent('', isSafeRedirect).target, null);
});

test('readLandingIntent: denied, and the app name kept as plain text and bounded', () => {
  const i = readLandingIntent('?redirect=%2Fproduct-roadmap-v2&denied=1&app=product-roadmap-v2&name=Roadmap+%3Cb%3Ev2%3C%2Fb%3E', isSafeRedirect);
  assert.deepEqual(i, { target: '/product-roadmap-v2', denied: true, appName: 'Roadmap <b>v2</b>' });
  assert.equal(readLandingIntent('?denied=1&app=only-slug', isSafeRedirect).appName, 'only-slug');
  assert.equal(readLandingIntent('?denied=true', isSafeRedirect).denied, false);
  assert.equal(readLandingIntent('?denied=1&name=' + 'x'.repeat(500), isSafeRedirect).appName.length, 120);
});

test('initialLanding: denied never forwards; a stored token only earns a server check, not a redirect', () => {
  const target = '/product-roadmap-v2';
  for (const isAuthed of [true, false]) {
    assert.deepEqual(initialLanding({ target, denied: true, appName: 'Roadmap' }, isAuthed), { kind: 'denied', appName: 'Roadmap', target });
  }
  assert.deepEqual(initialLanding({ target, denied: false, appName: '' }, true), { kind: 'checking', target });
  assert.deepEqual(initialLanding({ target, denied: false, appName: '' }, false), { kind: 'none' });
  assert.deepEqual(initialLanding({ target: null, denied: false, appName: '' }, true), { kind: 'none' });
});

test('checkSession: an identity token is confirmed by refresh-cookie, which also sets the cookie forward_auth reads', async () => {
  const ok = fakeFetch(() => ({ status: 200, ok: true }));
  assert.equal(await checkSession({ token: 'tok-abc', apiKey: 'key-ignored', fetch: ok.fn }), 'valid');
  assert.deepEqual(ok.calls, [{ url: '/api/identity/refresh-cookie', method: 'POST', headers: { Authorization: 'Bearer tok-abc' } }]);

  for (const status of [401, 403]) {
    const no = fakeFetch(() => ({ status, ok: false }));
    assert.equal(await checkSession({ token: 'tok-dead', apiKey: '', fetch: no.fn }), 'invalid', String(status));
  }
});

test('checkSession: an API key is checked against /api/me; nothing stored is invalid', async () => {
  const f = fakeFetch(() => ({ status: 200, ok: true }));
  assert.equal(await checkSession({ token: '', apiKey: 'dhk_user_x', fetch: f.fn }), 'valid');
  assert.deepEqual(f.calls, [{ url: '/api/me', method: 'GET', headers: { 'X-API-Key': 'dhk_user_x' } }]);
  const none = fakeFetch(() => { throw new Error('must not be called'); });
  assert.equal(await checkSession({ token: '', apiKey: '', fetch: none.fn }), 'invalid');
  assert.equal(none.calls.length, 0);
});

test('checkSession: a network failure or 5xx is not proof the credential died', async () => {
  assert.equal(await checkSession({ token: 't', apiKey: '', fetch: async () => { throw new TypeError('Failed to fetch'); } }), 'unreachable');
  assert.equal(await checkSession({ token: 't', apiKey: '', fetch: async () => ({ status: 502, ok: false }) }), 'unreachable');
  assert.equal(await checkSession({ token: 't', apiKey: '', fetch: async () => ({ status: 429, ok: false }) }), 'unreachable');
});

test('allowRedirect: REDIRECT_MAX forwards per target inside the window, then refuses', () => {
  const s = memStore();
  const now = 1_000_000;
  for (let i = 0; i < REDIRECT_MAX; i++) assert.equal(allowRedirect(s, '/a', now + i * 100), true, `attempt ${i + 1}`);
  assert.equal(allowRedirect(s, '/a', now + 1000), false, 'the next forward inside the window is a loop');
  assert.equal(allowRedirect(s, '/a', now + 1001), false, 'and stays refused');
  assert.equal(allowRedirect(s, '/b', now + 1000), true, 'counted per target');
  assert.equal(allowRedirect(s, '/a', now + REDIRECT_WINDOW_MS + 300), true, 'old attempts age out');
  assert.equal(REDIRECT_MAX, 3);
  assert.equal(REDIRECT_WINDOW_MS, 30_000);
});

test('allowRedirect: corrupt, throwing or missing storage allows the forward instead of breaking sign-in', () => {
  const s = memStore();
  s.setItem(REDIRECT_STORE_PREFIX + '/a', '{not json');
  assert.equal(allowRedirect(s, '/a', 5), true);
  const throwing = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('SecurityError'); }, removeItem() { throw new Error('SecurityError'); } };
  assert.equal(allowRedirect(throwing, '/a', 5), true);
  assert.equal(allowRedirect(null, '/a', 5), true);
  assert.doesNotThrow(() => clearRedirectAttempts(throwing, '/a'));
  assert.doesNotThrow(() => clearRedirectAttempts(null, '/a'));
});

test('clearRedirectAttempts resets the breaker for that target', () => {
  const s = memStore();
  for (let i = 0; i < REDIRECT_MAX; i++) allowRedirect(s, '/a', 10 + i);
  assert.equal(allowRedirect(s, '/a', 20), false);
  clearRedirectAttempts(s, '/a');
  assert.equal(allowRedirect(s, '/a', 21), true);
});

test('afterCheck: refused -> stale (and no forward recorded); valid or unreachable -> go, until the breaker trips', () => {
  const s = memStore();
  assert.deepEqual(afterCheck('/a', 'invalid', s, 1), { kind: 'stale' });
  assert.equal(s.m.size, 0, 'a refused credential does not count as a forward');
  assert.deepEqual(afterCheck('/a', 'valid', s, 2), { kind: 'go', target: '/a' });
  assert.deepEqual(afterCheck('/a', 'unreachable', s, 3), { kind: 'go', target: '/a' });
  assert.deepEqual(afterCheck('/a', 'valid', s, 4), { kind: 'go', target: '/a' });
  assert.deepEqual(afterCheck('/a', 'valid', s, 5), { kind: 'loop', target: '/a' });
});

// Wiring. The decision functions above are only worth anything if AdminApp
// routes through them; these fail when it goes back to forwarding on its own.
test('AdminApp forwards to ?redirect= only from the checked "go" branch', () => {
  const replaces = ADMIN_APP.match(/window\.location\.replace\(/g) || [];
  assert.equal(replaces.length, 1, 'exactly one navigation in AdminApp');
  assert.match(ADMIN_APP, /if \(next\.kind === 'go'\) \{[\s\S]*?window\.location\.replace\(next\.target\)/);
  assert.match(ADMIN_APP, /checkSession\(\{/);
  assert.match(ADMIN_APP, /afterCheck\(landing\.target, check, attemptStore\(\), Date\.now\(\)\)/);
  assert.match(ADMIN_APP, /initialLanding\(readLandingIntent\(window\.location\.search, isSafeRedirect\), auth\.isAuthed\)/);
  assert.doesNotMatch(ADMIN_APP, /auth\.isAuthed\s*&&[^\n]*\n[\s\S]{0,400}location\.replace/, 'no forward keyed on a token merely existing');
});

test('AdminApp drops a refused credential without navigating, and renders the denied and loop screens', () => {
  assert.match(ADMIN_APP, /if \(next\.kind === 'stale'\) forget\(false\)/);
  assert.match(ADMIN_APP, /landing\.kind === 'denied'\) \{\s*return <AccessDenied appName=\{landing\.appName\}/);
  assert.match(ADMIN_APP, /landing\.kind === 'loop'\) \{\s*return <SignInStuck/);
  assert.doesNotMatch(ADMIN_APP, /dangerouslySetInnerHTML/);
});
