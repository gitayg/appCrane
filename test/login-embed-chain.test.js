import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import Database from 'better-sqlite3';

// An embedded app must be able to sign its user in INSIDE the frame.
//
// The chain a signed-out visitor to an embedded app actually walks:
//
//   GET /<slug>                     Caddy forward_auth → /api/identity/verify
//   302 → /login?redirect=…          forwardToLaunch in server/index.js
//   302 → /launch?redirect=…         sendAdminSpa — this is what the frame renders
//
// Measured against a real server before this fix: verify put the deep link in
// the query as an ABSOLUTE url, https://<host>/<slug>. /login's open-redirect
// guard (isSafeRedirect) correctly refuses absolute URLs, logged "dropped
// unsafe redirect target", and forwarded to a bare /launch. The frame-ancestors
// relaxation keys on `?redirect=/<slug>`, never saw one, and /launch was served
// with X-Frame-Options: SAMEORIGIN — so the embed came up as an empty box. The
// same drop also sent EVERY signed-out visitor to /launch instead of their app.
//
// Driven end to end against the real server process, because the pieces live
// in two files and each looked correct in isolation — which is the whole bug.
// A unit test of either half would have passed.

const HOST = 'app.example.com';
let child;
let base;
let dataDir;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-embed-chain-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY: 'e'.repeat(64), CRANE_DOMAIN: HOST, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  // The setup gate 503s every non-public path until an admin exists.
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('admin','admin@example.com','platform_admin','x',1)").run();
  db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Roadmap','product-roadmap-v2',9001,'github')").run();
  db.prepare("INSERT INTO apps (name,slug,slot,source_type,frame_ancestors) VALUES ('Locked','locked-app',9002,'github','''none''')").run();
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

const noFollow = (url, headers = {}) => fetch(url, { redirect: 'manual', headers: { Accept: 'text/html', ...headers } });
const frameAncestors = (r) => (r.headers.get('content-security-policy') || '').match(/frame-ancestors ([^;]+)/)?.[1] ?? null;

async function verifyAs(forwardedHost, uri) {
  return noFollow(`${base}/api/identity/verify?app=product-roadmap-v2`, {
    'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': forwardedHost, 'X-Forwarded-Uri': uri,
  });
}

test('verify sends a signed-out visitor to /login with the deep link as a same-host PATH', async () => {
  const r = await verifyAs(HOST, '/product-roadmap-v2');
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login');
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2',
    'an absolute redirect is refused by /login\'s open-redirect guard and dropped, which blanks the embed and loses the deep link');
});

test('the verify 302 itself is frameable for an embeddable app, and stays locked otherwise', async () => {
  // The first response an embedded frame receives. Whether a browser enforces
  // X-Frame-Options on a redirect is not something to depend on.
  const r = await verifyAs(HOST, '/product-roadmap-v2');
  assert.equal(r.headers.get('x-frame-options'), null, 'the verify 302 still carries X-Frame-Options');
  assert.equal(frameAncestors(r), `'self' https://*.example.com https://example.com`);

  const locked = await noFollow(`${base}/api/identity/verify?app=locked-app`, {
    'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': HOST, 'X-Forwarded-Uri': '/locked-app',
  });
  const fa = frameAncestors(locked);
  assert.ok(locked.headers.get('x-frame-options') === 'SAMEORIGIN' || fa === "'none'",
    `an app set to 'none' became frameable at verify: fa=${fa}`);
});

test('the deep link survives /login to /launch', async () => {
  const r = await noFollow(`${base}/login?redirect=%2Fproduct-roadmap-v2`);
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/launch?redirect=%2Fproduct-roadmap-v2');
});

test('every hop of the chain is frameable by the platform domain when the target app is embeddable', async () => {
  const expected = `'self' https://*.example.com https://example.com`;

  const login = await noFollow(`${base}/login?redirect=%2Fproduct-roadmap-v2`);
  assert.equal(login.headers.get('x-frame-options'), null, '/login 302 still carries X-Frame-Options');
  assert.equal(frameAncestors(login), expected);

  const launch = await noFollow(`${base}/launch?redirect=%2Fproduct-roadmap-v2`);
  assert.equal(launch.status, 200);
  assert.equal(launch.headers.get('x-frame-options'), null, '/launch still carries X-Frame-Options — the frame renders empty');
  assert.equal(frameAncestors(launch), expected);
});

test('the whole chain, followed from verify, ends frameable', async () => {
  // The property the embedder cares about, independent of how each hop is built.
  let url = (await verifyAs(HOST, '/product-roadmap-v2')).headers.get('location').replace(`https://${HOST}`, base);
  let r;
  for (let hop = 0; hop < 5; hop++) {
    r = await noFollow(url);
    if (r.status !== 302) break;
    url = new URL(r.headers.get('location'), base).toString();
  }
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-frame-options'), null, 'the page the iframe finally renders is SAMEORIGIN-locked');
  assert.ok(frameAncestors(r), 'the rendered page has no frame-ancestors');
});

test('an app that opted out of embedding stays locked through the chain', async () => {
  const r = await noFollow(`${base}/launch?redirect=%2Flocked-app`);
  const fa = frameAncestors(r);
  assert.ok(r.headers.get('x-frame-options') === 'SAMEORIGIN' || fa === "'none'",
    `an app set to 'none' became frameable: XFO=${r.headers.get('x-frame-options')} fa=${fa}`);
});

test('the dashboard with no app redirect keeps X-Frame-Options', async () => {
  const r = await noFollow(`${base}/launch`);
  assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN',
    'the relaxation must apply only to a sign-in step targeting an embeddable app, never the bare dashboard');
});

test('a redirect to an app that does not exist relaxes nothing', async () => {
  const r = await noFollow(`${base}/launch?redirect=%2Fno-such-app`);
  assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN');
});

test('the open-redirect guard still drops absolute and protocol-relative targets at /login', async () => {
  for (const evil of ['https://attacker.example/x', '//attacker.example/x', '/\\attacker.example']) {
    const r = await noFollow(`${base}/login?redirect=${encodeURIComponent(evil)}`);
    assert.equal(r.headers.get('location'), '/launch', `unsafe redirect ${evil} was forwarded`);
    assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN', `unsafe redirect ${evil} relaxed framing`);
  }
});

test('verify never hands /login a same-host path that is itself an open redirect', async () => {
  // The only way to reach one: unwrapNestedRedirect pulls the innermost
  // ?redirect= out of a looped /login URL, so the target is attacker-chosen.
  // `https://<host>//attacker.example/x` is same-host and parses, but its
  // pathname `//attacker.example/x` is protocol-relative in a browser. /login
  // would drop it as well; verify must not be the hop that manufactures it.
  const sameHost = encodeURIComponent(`https://${HOST}//attacker.example/x`);
  let r = await verifyAs(HOST, `/product-roadmap-v2/login?redirect=${sameHost}`);
  assert.equal(new URL(r.headers.get('location')).searchParams.get('redirect'), null,
    'a same-host URL with a protocol-relative path was forwarded as a path');

  // Not a URL at all once unwrapped: dropped, not passed through verbatim.
  r = await verifyAs(HOST, `/product-roadmap-v2/login?redirect=${encodeURIComponent('//attacker.example/x')}`);
  assert.equal(new URL(r.headers.get('location')).searchParams.get('redirect'), null,
    'an unparseable unwrapped target was passed through verbatim');
});

test('a request that arrived on a different host keeps the absolute form', async () => {
  // Never silently re-point a request from another host at a same-named path here.
  const r = await verifyAs('other.example.org', '/product-roadmap-v2');
  const redirect = new URL(r.headers.get('location')).searchParams.get('redirect');
  assert.equal(redirect, 'https://other.example.org/product-roadmap-v2');
});
