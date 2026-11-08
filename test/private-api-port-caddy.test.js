import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { setupFixture, setSetting } from './caddy-app-isolation-fixtures.js';

// APPCRANE_PRIVATE_API_PORT in the generated Caddyfile (services/caddy.js).
//
// Unset, the file is byte-for-byte what it was before the setting existed (the
// golden of test/caddy-app-isolation.test.js, recorded from the unmodified
// generator against the same fixture). Set, the platform host gets a second
// site on that port that stamps X-AppCrane-Ingress: private, and EVERY proxy to
// AppCrane on every public site (reverse_proxy and forward_auth alike) stamps
// X-AppCrane-Ingress: public with header_up's set form, so a client value never
// survives. Checked against the whole file, so a crane-bound proxy added later
// without the stamp fails here.

const HERE = dirname(fileURLToPath(import.meta.url));
const { db, ids } = await setupFixture();
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
const { assertPublicPortAssignable } = await import('../server/services/tcpIngress.js');
setAccessLogDirCheck(() => true);
const GOLDEN = readFileSync(join(HERE, 'caddy-app-isolation-off.golden'), 'utf8');
const CRANE = 'crane.example.test';

beforeEach(() => {
  delete process.env.APPCRANE_PRIVATE_API_PORT;
  setSetting(db, 'app_isolation_domain', '');
  setSetting(db, 'tls_cert_file', '');
  setSetting(db, 'tls_key_file', '');
  db.prepare('UPDATE apps SET custom_domain_auth = 0').run();
});

/** Top-level site blocks: address -> body. */
function sites(text) {
  const out = new Map();
  let depth = 0, name = null, buf = [];
  for (const line of text.split('\n')) {
    const o = (line.match(/\{/g) || []).length, c = (line.match(/\}/g) || []).length;
    if (depth === 0) { if (o > c) { name = line.replace(/\s*\{\s*$/, '').trim(); buf = []; depth = o - c; } continue; }
    depth += o - c;
    if (depth === 0) { out.set(name, buf.join('\n')); continue; }
    buf.push(line);
  }
  return out;
}

/**
 * Every proxy to AppCrane in a site body, with the subdirective block that
 * follows it (or '' for a bare one-line reverse_proxy).
 */
function craneProxies(body) {
  const out = [];
  const re = /^( *)(reverse_proxy|forward_auth) 127\.0\.0\.1:5001( \{)?$/gm;
  let m;
  while ((m = re.exec(body)) !== null) {
    if (!m[3]) { out.push({ kind: m[2], block: '' }); continue; }
    const end = body.indexOf(`\n${m[1]}}`, m.index);
    out.push({ kind: m[2], block: body.slice(m.index, end) });
  }
  return out;
}

const STAMP_PUBLIC = /^\s*header_up X-AppCrane-Ingress public$/m;
const STAMP_PRIVATE = /^\s*header_up X-AppCrane-Ingress private$/m;

function assertEveryPublicProxyStamped(text, { expectSites }) {
  const all = sites(text);
  let n = 0, fa = 0;
  for (const [addr, body] of all) {
    if (addr === `${CRANE}:8443`) continue;
    for (const p of craneProxies(body)) {
      n++;
      if (p.kind === 'forward_auth') fa++;
      assert.match(p.block, STAMP_PUBLIC, `${addr}: ${p.kind} to AppCrane without the public stamp:\n${p.block}`);
      assert.doesNotMatch(p.block, STAMP_PRIVATE, `${addr}: a public site stamps private`);
    }
  }
  for (const s of expectSites) assert.ok(all.has(s), `site ${s} missing`);
  return { n, fa };
}

test('unset: byte-identical to the generator before the setting existed', () => {
  assert.equal(generateCaddyfile(), GOLDEN);
});

test('unusable values are treated as unset: still byte-identical', () => {
  for (const v of ['', '  ', 'abc', '443', '80', '5001', '0', '65536']) {
    process.env.APPCRANE_PRIVATE_API_PORT = v;
    assert.equal(generateCaddyfile(), GOLDEN, JSON.stringify(v));
  }
});

test('set: a private-port site for the platform host, AppCrane only, stamped private', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  const text = generateCaddyfile();
  const s = sites(text);
  const body = s.get(`${CRANE}:8443`);
  assert.ok(body, `no ${CRANE}:8443 site:\n${[...s.keys()].join('\n')}`);
  const proxies = craneProxies(body);
  assert.equal(proxies.length, 1);
  assert.equal(proxies[0].kind, 'reverse_proxy');
  assert.match(proxies[0].block, STAMP_PRIVATE);
  assert.doesNotMatch(body, /reverse_proxy 127\.0\.0\.1:4\d{3}/, 'no app is served on the private port');
  assert.match(body, /handle \/api\/service\* \{\n\s+respond 404/, 'the internal service API stays off the private port too');
  assert.match(body, /\?Strict-Transport-Security/, 'baseline headers');
  // No tls line under automatic HTTPS: Caddy reuses the certificate it holds
  // for the host name.
  assert.doesNotMatch(body, /^\s*tls /m);
});

test('set: every proxy to AppCrane on the platform host is stamped public (forward_auth included)', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  const text = generateCaddyfile();
  const { n, fa } = assertEveryPublicProxyStamped(text, { expectSites: [CRANE, `${CRANE}:8443`] });
  // catch-all, /a2a*, /git/*, agent card, /oauth/*, /.well-known/oauth-*, crash
  // page, plus one forward_auth per live authenticated env.
  assert.ok(n >= 7 + fa, `only ${n} crane proxies found`);
  assert.ok(fa >= 4, `only ${fa} forward_auth blocks found`);
  const crane = sites(text).get(CRANE);
  for (const h of ['/a2a*', '/git/*', '/.well-known/agent-card.json', '/oauth/*', '/.well-known/oauth-*']) {
    const i = crane.indexOf(`handle ${h} {`);
    assert.ok(i >= 0, h);
    assert.match(crane.slice(i, crane.indexOf('\n    }', i)), STAMP_PUBLIC, h);
  }
});

test('set: app hosts and custom-domain sign-in sites stamp every proxy to AppCrane public', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  setSetting(db, 'app_isolation_domain', 'apps.example.test');
  db.prepare('UPDATE apps SET custom_domain_auth = 1 WHERE id = ?').run(ids.boxed);
  const text = generateCaddyfile();
  const { fa } = assertEveryPublicProxyStamped(text, {
    expectSites: [CRANE, `${CRANE}:8443`, 'hub.apps.example.test', 'hub-sandbox.apps.example.test', 'boxed.example.com'],
  });
  assert.ok(fa >= 5, `only ${fa} forward_auth blocks found`);
  // /api/me, /api/directory and /__appcrane/* on an app host go to AppCrane.
  const hub = sites(text).get('hub.apps.example.test');
  for (const h of ['/__appcrane/*', '/api/me', '/api/directory']) {
    const i = hub.indexOf(`handle ${h} {`);
    assert.ok(i >= 0, h);
    assert.match(hub.slice(i, hub.indexOf('\n    }', i)), STAMP_PUBLIC, h);
  }
  // A custom domain WITHOUT sign-in never reaches AppCrane at all.
  assert.equal(craneProxies(sites(text).get('shop.example.com')).length, 0);
});

test('the stamp uses header_up\'s set form, never add or delete, so a client value cannot win', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  setSetting(db, 'app_isolation_domain', 'apps.example.test');
  const text = generateCaddyfile();
  const lines = text.split('\n').filter(l => /X-AppCrane-Ingress/i.test(l));
  assert.ok(lines.length > 10);
  for (const l of lines) assert.match(l, /^\s*header_up X-AppCrane-Ingress (public|private)$/, l);
});

test('set with a manual certificate: the private site serves the same certificate', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  setSetting(db, 'tls_cert_file', '/etc/ssl/crane.pem');
  setSetting(db, 'tls_key_file', '/etc/ssl/crane.key');
  const s = sites(generateCaddyfile());
  assert.match(s.get(CRANE), /^ {4}tls \/etc\/ssl\/crane\.pem \/etc\/ssl\/crane\.key$/m);
  assert.match(s.get(`${CRANE}:8443`), /^ {4}tls \/etc\/ssl\/crane\.pem \/etc\/ssl\/crane\.key$/m);
});

test('an app cannot publish a TCP port on the private API port', () => {
  process.env.APPCRANE_PRIVATE_API_PORT = '8443';
  assert.throws(() => assertPublicPortAssignable(db, 8443, ids.hub), (e) => e.code === 'PORT_RESERVED');
  delete process.env.APPCRANE_PRIVATE_API_PORT;
  assert.doesNotThrow(() => assertPublicPortAssignable(db, 8443, ids.hub));
});
