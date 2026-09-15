import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'fs';
import { isSafeRedirect } from '../server/utils/safeRedirect.js';
import {
  isFramed, signInPlan, shouldUsePopupSignIn, popupStartUrl, reloadTargetAfterSignIn,
  isSignedInMessage, waitForPopupSignIn, POLL_INTERVAL_MS, POLL_MAX_MS, SSO_CHANNEL,
} from '../studio-web/src/utils/popupSignIn.ts';

// The framed sign-in decision and the listener that learns the popup finished.
// popupSignIn.ts is erasable TypeScript with no imports, so it is loaded here
// directly instead of mirrored.

const LOGIN = readFileSync(new URL('../studio-web/src/components/Login.tsx', import.meta.url), 'utf8');

test('isFramed: top !== self, and an unreadable top counts as framed', () => {
  const w = {};
  assert.equal(isFramed({ top: w, self: w }), false);
  assert.equal(isFramed({ top: {}, self: w }), true);
  assert.equal(isFramed({ get top() { throw new Error('SecurityError'); }, self: w }), true);
});

test('signInPlan: SSO opens in a popup only when framed; password stays wherever SSO is not required', () => {
  for (const framed of [true, false]) {
    for (const ssoEnabled of [true, false]) {
      for (const ssoOnly of [true, false]) {
        const plan = signInPlan({ framed, ssoEnabled, ssoOnly });
        assert.equal(plan.showPassword, !ssoOnly, `password visibility changed with framed=${framed}`);
        assert.equal(plan.sso, !ssoEnabled ? 'none' : framed ? 'popup' : 'navigate', JSON.stringify({ framed, ssoEnabled, ssoOnly }));
      }
    }
  }
  assert.equal(shouldUsePopupSignIn({ framed: true, ssoEnabled: true }), true);
  assert.equal(shouldUsePopupSignIn({ framed: false, ssoEnabled: true }), false);
});

test('popupStartUrl is a relative start URL in popup mode', () => {
  const u = popupStartUrl('oidc', '/product-roadmap-v2');
  assert.match(u, /^\/api\/auth\/oidc\/start\?/);
  const q = new URLSearchParams(u.split('?')[1]);
  assert.equal(q.get('mode'), 'popup');
  assert.equal(q.get('redirect'), '/product-roadmap-v2');
  assert.match(popupStartUrl('saml', '/a b'), /^\/api\/auth\/saml\/start\?redirect=%2Fa\+b&mode=popup$/);
});

test('reloadTargetAfterSignIn only returns a same-origin path', () => {
  assert.equal(reloadTargetAfterSignIn('?redirect=%2Fproduct-roadmap-v2', isSafeRedirect), '/product-roadmap-v2');
  for (const evil of ['//attacker.example/x', 'https://attacker.example/x', '/\\attacker.example', 'javascript:alert(1)']) {
    assert.equal(reloadTargetAfterSignIn('?redirect=' + encodeURIComponent(evil), isSafeRedirect), null, evil);
  }
  assert.equal(reloadTargetAfterSignIn('', isSafeRedirect), null);
});

test('isSignedInMessage accepts only the signed-in shape', () => {
  assert.equal(isSignedInMessage({ type: 'signed-in' }), true);
  for (const m of [null, 'signed-in', { type: 'other' }, {}, undefined]) assert.equal(isSignedInMessage(m), false);
});

// ---- listener with fakes --------------------------------------------------
const flush = () => new Promise((r) => setImmediate(r));

function fakes({ sessions = [] } = {}) {
  const intervals = new Map();
  const timeouts = new Map();
  let id = 0;
  const channels = [];
  let checks = 0;
  const deps = {
    openChannel: (name) => {
      const ch = { name, fn: null, closed: false, listen(fn) { this.fn = fn; }, close() { this.closed = true; } };
      channels.push(ch);
      return ch;
    },
    checkSession: () => { const v = sessions[Math.min(checks, sessions.length - 1)] ?? false; checks++; return Promise.resolve(v); },
    setInterval: (fn, ms) => { intervals.set(++id, { fn, ms }); return id; },
    clearInterval: (h) => intervals.delete(h),
    setTimeout: (fn, ms) => { timeouts.set(++id, { fn, ms }); return id; },
    clearTimeout: (h) => timeouts.delete(h),
  };
  return {
    deps, channels, intervals, timeouts,
    get checks() { return checks; },
    tickInterval: async (n = 1) => { for (let i = 0; i < n; i++) { for (const t of [...intervals.values()]) t.fn(); await flush(); } },
    fireTimeout: async () => { for (const t of [...timeouts.values()]) t.fn(); await flush(); },
  };
}

test('listener: a signed-in BroadcastChannel message finishes and tears everything down', async () => {
  const f = fakes({ sessions: [false] });
  const w = waitForPopupSignIn(f.deps);
  assert.equal(f.channels[0].name, SSO_CHANNEL);
  f.channels[0].fn({ type: 'something-else' });
  f.channels[0].fn({ type: 'signed-in' });
  assert.equal(await w.done, 'signed-in');
  assert.equal(f.channels[0].closed, true);
  assert.equal(f.intervals.size, 0, 'poll interval left running');
  assert.equal(f.timeouts.size, 0, 'timeout left running');
});

test('listener: the poll finishes once a signed-out baseline turns signed-in', async () => {
  const f = fakes({ sessions: [false, false, true] });
  const w = waitForPopupSignIn(f.deps);
  await flush();
  const [iv] = [...f.intervals.values()];
  assert.equal(iv.ms, POLL_INTERVAL_MS);
  let result = null;
  w.done.then((r) => { result = r; });
  await f.tickInterval();
  assert.equal(result, null);
  await f.tickInterval();
  assert.equal(result, 'signed-in');
});

test('listener: a session that already existed does not count as the popup finishing', async () => {
  const f = fakes({ sessions: [true] });
  const w = waitForPopupSignIn(f.deps);
  await flush();
  let result = null;
  w.done.then((r) => { result = r; });
  await f.tickInterval(5);
  assert.equal(result, null);
  await f.fireTimeout();
  assert.equal(result, 'timeout');
});

test('listener: bounded — times out at POLL_MAX_MS (<= 5 min) and stops polling', async () => {
  assert.ok(POLL_MAX_MS <= 5 * 60 * 1000 && POLL_MAX_MS > 0);
  assert.ok(POLL_INTERVAL_MS >= 1000 && POLL_INTERVAL_MS <= 2000);
  const f = fakes({ sessions: [false] });
  const w = waitForPopupSignIn(f.deps, { maxMs: Number.POSITIVE_INFINITY });
  await flush();
  const [to] = [...f.timeouts.values()];
  assert.equal(to.ms, POLL_MAX_MS, 'a caller-supplied maxMs lifted the cap');
  await f.fireTimeout();
  assert.equal(await w.done, 'timeout');
  assert.equal(f.intervals.size, 0, 'polling continues after the timeout');
  const before = f.checks;
  await f.tickInterval(3);
  assert.equal(f.checks, before);
});

// ---- Login.tsx wiring -----------------------------------------------------
test('Login.tsx decides from isFramed(window) and signInPlan, and gates the password form on the plan only', () => {
  assert.match(LOGIN, /signInPlan\(\{\s*framed:\s*isFramed\(window\)/);
  assert.match(LOGIN, /\{plan\.showPassword && \(/, 'password form is no longer gated on plan.showPassword');
  assert.doesNotMatch(LOGIN, /\{!ssoOnly && \(\s*<>\s*<input/, 'password form gated on something other than the plan');
});

test('Login.tsx opens a named popup, falls back to a new-tab link, and reloads through the safe-redirect rule', () => {
  assert.match(LOGIN, /window\.open\(href, POPUP_NAME, POPUP_FEATURES\)/);
  assert.match(LOGIN, /if \(!win\) \{ setPopupState\('blocked'\)/);
  assert.match(LOGIN, /target="_blank"/);
  assert.match(LOGIN, /reloadTargetAfterSignIn\(window\.location\.search, isSafeRedirect\)/);
  assert.match(LOGIN, /Sign-in opens in a new window/);
});

test('the shipped SPA bundle carries popup sign-in', () => {
  const dir = new URL('../docs/admin-app/assets/', import.meta.url);
  const joined = readdirSync(dir).filter((f) => f.endsWith('.js')).map((f) => readFileSync(new URL(f, dir), 'utf8')).join('\n');
  assert.match(joined, /appcrane-sso/, 'docs/admin-app is stale: rebuild studio-web');
  assert.match(joined, /Sign-in opens in a new window/);
});
