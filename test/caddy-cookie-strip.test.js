import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The platform session cookie must never reach an app container (v2.39.0).
//
// Caddy forwards Cookie verbatim; apps are mounted same-origin at /<slug> and
// cc_token is path=/, so a logged-in visitor's browser attaches it to every
// request into the app. cc_token is also accepted as a bearer, so an app's own
// backend could read it off the request and call the platform API as whoever
// visited. Verified end-to-end before this fix: a lifted platform_admin session
// reached /api/settings, /api/users, /api/audit, and the DECRYPTED env vars of
// an app the admin was not even assigned to (?reveal=true), leaving no audit
// entry, for the 24h life of the session.
//
// Nothing legitimate needs the cookie inside the container: identity arrives via
// X-AppCrane-* headers, and an app's server talks to the platform over
// /api/service with its own token. The browser's own fetch('/api/me') is
// unaffected — that matches the platform catch-all, not an app block.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cookie-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const mkApp = (name, slug, slot, extra = {}) => {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,auth_mode,auth_bypass_paths,domain) VALUES (?,?,?,?,?,?,?)'
  ).run(name, slug, slot, 'managed', extra.auth_mode ?? 'forward_auth',
        extra.auth_bypass_paths ?? null, extra.domain ?? null).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO deployments (app_id, env, status) VALUES (?,?,?)').run(id, env, 'live');
  }
  return id;
};

mkApp('Normal', 'normal', 1);
mkApp('Headless', 'headless', 2, { auth_mode: 'headless' });
mkApp('Bypass', 'bypass', 3, { auth_bypass_paths: JSON.stringify(['/ws/runner']) });
mkApp('Custom', 'custom', 4, { domain: 'custom.test.local' });

const { generateCaddyfile } = await import('../server/services/caddy.js');
const cf = generateCaddyfile();

// Split the file into `handle` blocks so we can assert per-route rather than
// "the string appears somewhere", which would pass with one strip and eleven
// unprotected routes.
function handleBlocks(text) {
  const blocks = [];
  const re = /^\s*handle ([^\s{]*)\s*\{$/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    const start = m.index;
    let depth = 0, i = text.indexOf('{', start), end = i;
    for (; i < text.length; i++) {
      if (text[i] === '{') depth++;
      else if (text[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    blocks.push({ path: m[1] || '(catch-all)', body: text.slice(start, end + 1) });
  }
  return blocks;
}

const BLOCKS = handleBlocks(cf);
const stripsCookie = b => /request_header Cookie "\(\^\|;\\s\*\)cc_token=\[\^;\]\*" ""/.test(b.body);
const proxiesToApp = b => /reverse_proxy 127\.0\.0\.1:(4\d{3}|[5-9]\d{3})/.test(b.body)
  && !/reverse_proxy 127\.0\.0\.1:5001/.test(b.body);

test('the generated Caddyfile actually has app routes to check', () => {
  // Guards every assertion below: if generation silently produced nothing, the
  // per-block loops would pass vacuously.
  assert.ok(BLOCKS.length >= 8, `expected app handle blocks, found ${BLOCKS.length}`);
  assert.ok(BLOCKS.some(b => b.path === '/normal*'), 'production route missing');
  assert.ok(BLOCKS.some(b => b.path === '/normal-sandbox*'), 'sandbox route missing');
});

test('EVERY handle block that proxies to an app strips the platform cookie', () => {
  const appBlocks = BLOCKS.filter(proxiesToApp);
  assert.ok(appBlocks.length >= 6, `expected several app-proxying blocks, got ${appBlocks.length}`);
  const unprotected = appBlocks.filter(b => !stripsCookie(b)).map(b => b.path);
  assert.deepEqual(unprotected, [],
    `these routes forward cc_token into an app container:\n  ${unprotected.join('\n  ')}`);
});

test('headless apps are covered too — they need it most', () => {
  // Headless skips forward_auth entirely, so it gets no identity headers and
  // stripIncoming does not run. The browser still sends it the cookie. If the
  // strip were placed inside the !isHeadless branch this would fail.
  for (const path of ['/headless*', '/headless-sandbox*']) {
    const b = BLOCKS.find(x => x.path === path);
    assert.ok(b, `${path} block missing`);
    assert.ok(stripsCookie(b), `${path} is headless and forwards cc_token`);
    assert.doesNotMatch(b.body, /forward_auth/, 'test premise broken: this app is not headless');
  }
});

test('auth-bypass paths are covered', () => {
  const b = BLOCKS.find(x => x.path === '/bypass/ws/runner*');
  assert.ok(b, 'bypass block missing — check parseBypassPaths');
  assert.ok(stripsCookie(b), 'auth-bypass route forwards cc_token');
});

test('the whole Cookie header is never dropped — apps keep their own cookies', () => {
  // A blanket `request_header -Cookie` would sign every user out of every
  // hosted app. The fix must be by name.
  assert.doesNotMatch(cf, /request_header -Cookie\b/,
    'blanket Cookie removal would destroy apps\' own sessions');
});

// ---------------------------------------------------------------------------
// Semantics of the rule itself. Caddy uses Go RE2; these patterns use only
// syntax shared with JS, so exercising them here is a faithful check of what
// the directives do to a real Cookie header.
// ---------------------------------------------------------------------------
function applyStrip(cookie) {
  return cookie
    .replace(new RegExp('(^|;\\s*)cc_token=[^;]*', 'g'), '')
    .replace(new RegExp('^;\\s*'), '');
}

test('cc_token is removed wherever it sits in the header', () => {
  assert.equal(applyStrip('cc_token=SECRET'), '');
  assert.equal(applyStrip('cc_token=SECRET; app_sid=keep'), 'app_sid=keep');
  assert.equal(applyStrip('app_sid=keep; cc_token=SECRET'), 'app_sid=keep');
  assert.equal(applyStrip('a=1; cc_token=SECRET; b=2'), 'a=1; b=2');
});

test('no leftover token material in any position', () => {
  for (const c of ['cc_token=S', 'cc_token=S; a=1', 'a=1; cc_token=S', 'a=1; cc_token=S; b=2']) {
    assert.doesNotMatch(applyStrip(c), /cc_token|(^|\W)S(\W|$)/,
      `token survived the strip in: ${c}`);
  }
});

test("an app's own cookies are preserved exactly", () => {
  assert.equal(applyStrip('app_sid=abc; theme=dark'), 'app_sid=abc; theme=dark');
  assert.equal(applyStrip('session=x'), 'session=x');
});

test('a similarly-named app cookie is NOT corrupted', () => {
  // The (^|;\s*) anchor is why. Without it, a substring match on `cc_token=`
  // would eat part of these and hand the app a mangled cookie header.
  assert.equal(applyStrip('my_cc_token=mine'), 'my_cc_token=mine');
  assert.equal(applyStrip('xcc_token=mine; a=1'), 'xcc_token=mine; a=1');
  assert.equal(applyStrip('my_cc_token=mine; cc_token=SECRET'), 'my_cc_token=mine');
});

test('no leading or doubled separator is left behind', () => {
  for (const c of ['cc_token=S; a=1', 'a=1; cc_token=S; b=2', 'cc_token=S']) {
    const out = applyStrip(c);
    assert.doesNotMatch(out, /^;/, `leading separator left: "${out}"`);
    assert.doesNotMatch(out, /;\s*;/, `doubled separator left: "${out}"`);
  }
});
