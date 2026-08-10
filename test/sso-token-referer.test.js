import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// SSO session token must never survive into a deep-link navigation (v2.38.0).
//
// The SSO callbacks hand the platform bearer back as `?oidc_token=…` on the
// /login URL. Referrer-Policy is strict-origin-when-cross-origin, which sends
// the FULL URL as Referer on a SAME-ORIGIN hop — and tenant apps are served
// same-origin at /<slug>. So navigating to a deep link while oidc_token is
// still in the address bar hands that app's container a live session token in
// its access logs. Anyone who can deploy an app could harvest other users'
// tokens by sending them /login?redirect=/theirapp/.
//
// This was unreachable before v2.38.0 only by accident: both callbacks gated
// the forward on `startsWith('http')`, a value isSafeRedirect always rejects,
// so the token-scrubbing else-branch always ran. v2.38.0 restored real deep
// links, which made the other branch live for the first time. The scrub must
// therefore happen BEFORE the branch, not inside one arm of it.

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const LOGIN = readFileSync(join(ROOT, 'studio-web/src/components/Login.tsx'), 'utf8');
const ADMIN_APP = readFileSync(join(ROOT, 'studio-web/src/AdminApp.tsx'), 'utf8');

test('Login.tsx scrubs oidc_token before it can reach a redirect target', () => {
  const scrub = LOGIN.indexOf("searchParams.delete('oidc_token')");
  const branch = LOGIN.indexOf('isSafeRedirect(redirect)');
  assert.notEqual(scrub, -1, 'Login.tsx no longer deletes oidc_token at all');
  assert.notEqual(branch, -1, 'the redirect branch moved — re-check this guard');
  assert.ok(scrub < branch,
    'oidc_token is scrubbed inside/after the redirect branch. It must be removed ' +
    'from the URL BEFORE window.location.replace(redirect), or the deep-link ' +
    'target receives the session token as Referer.');
});

test('the scrub is committed to the address bar, not just to a local object', () => {
  // Deleting the param off a `new URL(...)` copy changes nothing the browser
  // sends — Referer is taken from the live document URL. Only history.replaceState
  // (or an actual navigation) updates that.
  assert.match(LOGIN, /history\.replaceState\(/,
    'Login.tsx mutates a URL copy but never writes it back via history.replaceState, ' +
    'so document.URL still carries oidc_token when the redirect fires');
});

test('AdminApp.tsx scrubs oidc_token before its own deep-link replace', () => {
  const replace = ADMIN_APP.indexOf('window.location.replace(redirect');
  assert.notEqual(replace, -1, 'AdminApp deep-link navigation moved — re-check this guard');
  const before = ADMIN_APP.slice(0, replace);
  assert.match(before, /searchParams\.delete\('oidc_token'\)/,
    'AdminApp.tsx navigates to a deep link without scrubbing oidc_token first');
});

test('neither SSO start sends an absolute redirect', () => {
  // The server-side validator refuses absolute URLs — including our own origin —
  // so `window.location.origin + '/launch'` was silently dropped and fell back.
  assert.doesNotMatch(LOGIN, /location\.origin \+ '\/launch'/,
    "startOidc/startSaml send an origin-prefixed redirect; the server rejects it. Use '/launch'.");
});

test('the shipped SPA bundle carries the scrub, not just the source', () => {
  // studio-web/ is compiled into docs/admin-app/ and THAT is what production
  // serves. A source-only fix that was never rebuilt would leave the live app
  // vulnerable while every assertion above passes.
  const assetsDir = join(ROOT, 'docs/admin-app/assets');
  const bundles = readdirSync(assetsDir).filter(f => f.endsWith('.js'));
  assert.ok(bundles.length, 'no built SPA bundle found under docs/admin-app/assets');

  const joined = bundles.map(f => readFileSync(join(assetsDir, f), 'utf8')).join('\n');
  assert.match(joined, /replaceState/,
    'the built bundle has no history.replaceState — docs/admin-app/ is stale, ' +
    'rebuild studio-web before committing');
  assert.match(joined, /oidc_token/,
    'the built bundle does not reference oidc_token — wrong bundle or stale build');
});
