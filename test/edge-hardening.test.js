import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

// Caddy-edge hardening, v2.44.0.
//
// Three gaps in the generated Caddyfile, all on the boundary AppCrane owns:
//
//   1. The auth-bypass routes — the ONE route class that deliberately runs no
//      forward_auth — carried `log_skip`, so the only unauthenticated surface on
//      the box was also the only one with no request record. It is logged now,
//      with the query string redacted, because the CLI token rides in the query.
//   2. Baseline security headers (HSTS, nosniff, referrer/permissions policy,
//      banner strip) were emitted inside the CRANE_DOMAIN site block only. A
//      Caddy site block inherits NOTHING from another site block, so an app on
//      its own hostname — the one most likely to be handed to someone outside
//      the platform — got none of them.
//   3. `frame_ancestors` could only ever WIDEN the platform default. An app that
//      wanted to be embeddable nowhere had its `'none'` appended to the wildcard
//      allowlist, where CSP3's grammar makes the token inert; it stayed
//      embeddable by the whole registrable domain.
//
// TWO RULES THESE TESTS PIN.
//
// First: the change must be invisible to an app that configured none of it. The
// baseline for that is test/fixtures/caddyfile.pre-edge-hardening.txt — a
// snapshot of what the v2.43.1 generator emitted for the seed in
// test/fixtures/edge-hardening.seed.js. It is a vendored file on purpose: a
// `git show HEAD:` baseline passes locally and dies the moment it is committed,
// and CI's shallow checkout cannot reach HEAD~1 or a release tag at all.
//
// Second: the log assertions run against the ADAPTED JSON, not the Caddyfile
// text. Caddy reorders directives by its own fixed ranking and access logging is
// host-scoped in ways the source text does not show, so what we wrote and what
// Caddy will do are different questions. Only the second one matters.

const HERE = dirname(fileURLToPath(import.meta.url));
const CRANE = 'crane.example.com';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-edge-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
// Must be psl-resolvable, and must match the domain the snapshot was generated
// under: it decides both the site name and whether platformEmbedAncestors
// contributes a default at all (an unresolvable domain silently disables it,
// which would make every frame-ancestors assertion below vacuous).
process.env.CRANE_DOMAIN = CRANE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { seedApps } = await import('./fixtures/edge-hardening.seed.js');
seedApps(db);

const { generateCaddyfile } = await import('../server/services/caddy.js');
const { mergeAncestors, platformEmbedAncestors } = await import('../server/utils/embed.js');

const CF = generateCaddyfile();
const BEFORE = readFileSync(join(HERE, 'fixtures/caddyfile.pre-edge-hardening.txt'), 'utf8');

// ---------------------------------------------------------------------------
// Caddyfile structure helpers. Brace counting is safe on this file: the only
// line carrying braces in a string is handle_errors' `{err.status_code}`
// expression, which opens and closes on itself and nets to zero.
// ---------------------------------------------------------------------------

/** Top-level `name { … }` site blocks → Map(name → body without the braces). */
function siteBlocks(text) {
  const out = new Map();
  let depth = 0, name = null, buf = [];
  for (const line of text.split('\n')) {
    const o = (line.match(/\{/g) || []).length;
    const c = (line.match(/\}/g) || []).length;
    if (depth === 0) {
      if (o > c) { name = line.replace(/\s*\{\s*$/, '').trim(); buf = []; depth = o - c; }
      continue;
    }
    depth += o - c;
    if (depth === 0) { out.set(name, buf.join('\n')); name = null; continue; }
    buf.push(line);
  }
  return out;
}

/** Directive blocks one level inside a site body → Map(header line → full text). */
function innerBlocks(body) {
  const out = new Map();
  let depth = 0, name = null, buf = [];
  for (const line of body.split('\n')) {
    if (depth === 0) {
      const o = (line.match(/\{/g) || []).length;
      const c = (line.match(/\}/g) || []).length;
      if (o > c) { name = line.trim().replace(/\s*\{$/, ''); buf = [line]; depth = o - c; }
      continue;
    }
    buf.push(line);
    depth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
    if (depth === 0) { out.set(name, buf.join('\n')); name = null; }
  }
  return out;
}

const siteNow = siteBlocks(CF);
const siteWas = siteBlocks(BEFORE);
for (const [label, m] of [['generated', siteNow], ['snapshot', siteWas]]) {
  // Legibility guard. Without it, a CRANE_DOMAIN that no longer matches the one
  // the snapshot was taken under fails as a TypeError on undefined at import
  // time, several frames away from the actual cause.
  if (!m.get(CRANE)) throw new Error(`${label} Caddyfile has no ${CRANE} site block`);
}
const craneNow = innerBlocks(siteNow.get(CRANE));
const craneWas = innerBlocks(siteWas.get(CRANE));

test('the fixture and the live generator describe the same site set', () => {
  // Guards every comparison below. If the seed drifts, the "byte-identical"
  // results stop meaning anything, and a Map lookup that returns undefined on
  // both sides would compare equal.
  assert.deepEqual([...siteNow.keys()], [CRANE, 'custom.test.local', 'old.test.local']);
  assert.deepEqual([...siteWas.keys()], [...siteNow.keys()]);
  assert.ok(craneWas.size > 10, 'the snapshot parsed into too few blocks to be the real file');
});

// ---------------------------------------------------------------------------
// 1. Byte identity for the apps that asked for nothing.
// ---------------------------------------------------------------------------

test('an app with no special config produces a byte-identical site block', () => {
  for (const key of ['handle /plain-sandbox*', 'handle /plain*']) {
    assert.ok(craneNow.has(key), `${key} vanished from the generated Caddyfile`);
    assert.equal(craneNow.get(key), craneWas.get(key),
      `${key} changed; a plain app must not notice this release`);
  }
});

test('only the three intended blocks differ from v2.43.1', () => {
  // The whole-file version of the assertion above. Anything that changed and is
  // not on this list is collateral damage from an edge fix, which is exactly the
  // class of regression a per-app spot check misses.
  const expected = new Set([
    'handle /bypasser-sandbox/ws/runner*',  // log_skip removed
    'handle /bypasser/ws/runner*',          // log_skip removed
    'handle /denied-sandbox*',              // 'none' now denies
    'handle /denied*',
    'handle /narrow-sandbox*',              // 'none' + origin now narrows
    'handle /narrow*',
  ]);
  const changed = [...craneNow.keys()]
    .filter(k => craneWas.has(k) && craneNow.get(k) !== craneWas.get(k));
  assert.deepEqual(new Set(changed), expected);
  // The log block is additive, so it shows up as a new key rather than a diff.
  assert.deepEqual(
    [...craneNow.keys()].filter(k => !craneWas.has(k)), ['log'],
    'the crane site gained a block other than the redacting access log');
  assert.deepEqual([...craneWas.keys()].filter(k => !craneNow.has(k)), []);
});

test('the untouched apps keep their exact routing, headless and aliases included', () => {
  for (const key of ['handle /headless*', 'handle /framed*', 'handle /framed-sandbox*',
                     'handle /aliased*', 'handle /oldname*', 'handle /undeployed*',
                     'handle /api/service*', 'handle', 'handle_errors']) {
    assert.equal(craneNow.get(key), craneWas.get(key), `${key} changed unexpectedly`);
  }
  assert.equal(siteNow.get('old.test.local'), siteWas.get('old.test.local'));
});

test('the bypass block changed by exactly one removed line', () => {
  for (const key of ['handle /bypasser-sandbox/ws/runner*', 'handle /bypasser/ws/runner*']) {
    const was = craneWas.get(key).split('\n');
    const now = craneNow.get(key).split('\n');
    assert.deepEqual(was.filter(l => l.trim() !== 'log_skip'), now,
      `${key}: something other than log_skip changed on the bypass route`);
    assert.ok(was.some(l => l.trim() === 'log_skip'), 'snapshot should still contain log_skip');
    // The security invariants that share this block. A bypass route runs no
    // forward_auth, so the identity strip and the 'bypass' stamp are the only
    // things standing between a curl and a forged platform_admin header.
    assert.match(craneNow.get(key), /request_header -X-AppCrane-User-Role/);
    assert.match(craneNow.get(key), /request_header X-AppCrane-Auth-Mode "bypass"/);
  }
});

// ---------------------------------------------------------------------------
// 2. Baseline headers: one definition, both sites.
// ---------------------------------------------------------------------------

/** The set of directives inside a site's top-level `header { … }` block. */
function baselineHeaderSet(siteBody) {
  const blk = innerBlocks(siteBody).get('header');
  if (!blk) return null;
  return new Set(blk.split('\n').slice(1, -1).map(l => l.trim()).filter(Boolean));
}

test('the custom-domain site carries the same baseline headers as the crane domain', () => {
  const crane = baselineHeaderSet(siteNow.get(CRANE));
  const custom = baselineHeaderSet(siteNow.get('custom.test.local'));
  assert.ok(crane && crane.size >= 7, 'the crane baseline header block is missing or truncated');
  assert.ok(custom, 'custom-domain site block has no header block at all');
  // Set comparison, not a spot check: the two blocks must be unable to drift.
  // A per-header list here would pass while a NEW header added to one site only
  // quietly re-opened the same gap this release closed.
  assert.deepEqual(custom, crane);
  // And the gap was real before the change.
  assert.equal(baselineHeaderSet(siteWas.get('custom.test.local')), null);
});

test('the baseline set is the security policy, not an arbitrary list', () => {
  const crane = baselineHeaderSet(siteNow.get(CRANE));
  for (const d of ['?Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                   '?X-Content-Type-Options "nosniff"',
                   '?Referrer-Policy "strict-origin-when-cross-origin"',
                   '?X-Permitted-Cross-Domain-Policies "none"',
                   '-X-Powered-By', '-Server']) {
    assert.ok(crane.has(d), `baseline lost ${d}`);
  }
  // `?` = set-if-absent everywhere a value is set: an app that deliberately
  // chose its own HSTS or referrer policy keeps it.
  for (const d of crane) {
    if (d.startsWith('-')) continue;
    assert.ok(d.startsWith('?'), `${d} is forced onto app responses rather than defaulted`);
  }
  // X-Frame-Options stays out of the baseline — a blanket SAMEORIGIN would veto
  // the per-app frame-ancestors policy emitted below.
  assert.ok(![...crane].some(d => /X-Frame-Options/i.test(d)));
});

test('the crane-domain header block itself did not change', () => {
  assert.equal(craneNow.get('header'), craneWas.get('header'));
});

// ---------------------------------------------------------------------------
// 3. frame-ancestors: union by default, narrowing only via the 'none' sentinel.
// ---------------------------------------------------------------------------

const PLATFORM_FA = platformEmbedAncestors(db);

test('the platform default is actually active in this fixture', () => {
  // Otherwise "the default still unions" would pass by unioning with nothing.
  assert.equal(PLATFORM_FA, "'self' https://*.example.com https://example.com");
});

test('an app that set a value before the change still behaves exactly as it did', () => {
  const csp = (slug) => craneNow.get(`handle /${slug}*`).match(/frame-ancestors ([^"]+)"/)[1];
  assert.equal(csp('framed'), `${PLATFORM_FA} https://portal.example.com`);
  // The real regression test is the byte comparison: 'framed' is a pre-existing
  // union app and its blocks are in the untouched set above.
  assert.equal(craneNow.get('handle /framed*'), craneWas.get('handle /framed*'));
  assert.match(craneNow.get('handle /framed*'), /header -X-Frame-Options/);
});

test("the 'none' sentinel narrows to a single origin", () => {
  const blk = craneNow.get('handle /narrow*');
  assert.match(blk, /header Content-Security-Policy "frame-ancestors https:\/\/portal\.example\.com"/);
  assert.ok(!blk.includes('*.example.com'),
    'the platform wildcard survived an explicit opt-out — the app is still embeddable org-wide');
  // Narrowing to a real origin still needs the XFO strip: an upstream sending
  // SAMEORIGIN would otherwise veto the CSP and the listed embedder gets nothing.
  assert.match(blk, /header -X-Frame-Options/);
});

test("the 'none' sentinel alone denies embedding, and keeps the app's own XFO", () => {
  const blk = craneNow.get('handle /denied*');
  assert.match(blk, /header Content-Security-Policy "frame-ancestors 'none'"/);
  assert.ok(!blk.includes('example.com"'), 'a deny policy must not carry any allowed origin');
  // A deny policy has no embedder to unlock, so stripping the app's own
  // X-Frame-Options would only discard legacy protection for pre-CSP2 browsers.
  assert.ok(!/header -X-Frame-Options/.test(blk),
    'X-Frame-Options is stripped on a deny-everything policy, weakening old browsers for nothing');
  // What the old code emitted, for the record: a wildcard allowlist with an
  // inert 'none' glued on the end.
  assert.match(craneWas.get('handle /denied*'),
    /frame-ancestors 'self' https:\/\/\*\.example\.com https:\/\/example\.com 'none'/);
});

test('mergeAncestors: union is untouched for every value without the sentinel', () => {
  const P = "'self' https://*.ex.com";
  assert.equal(mergeAncestors(P, 'https://a.ex.com'), `${P} https://a.ex.com`);
  assert.equal(mergeAncestors(P, null), P);
  assert.equal(mergeAncestors(P, ''), P);
  assert.equal(mergeAncestors(P, "'self'"), P, 'duplicate tokens must still collapse');
  assert.equal(mergeAncestors(null, 'https://a.ex.com'), 'https://a.ex.com');
  assert.equal(mergeAncestors(null, null), null);
  // 'self' keeps union semantics deliberately: apps set it today expecting the
  // platform default alongside. Only 'none' — which had no coherent meaning —
  // was safe to re-read as "replace".
  assert.ok(mergeAncestors(P, "'self'").includes('*.ex.com'));
});

test('mergeAncestors: the sentinel replaces rather than widens', () => {
  const P = "'self' https://*.ex.com";
  assert.equal(mergeAncestors(P, "'none'"), "'none'");
  assert.equal(mergeAncestors(P, "'none' https://portal.ex.com"), 'https://portal.ex.com');
  assert.equal(mergeAncestors(P, "https://portal.ex.com 'none'"), 'https://portal.ex.com',
    'sentinel position must not matter');
  assert.equal(mergeAncestors(P, "'NONE'"), "'none'", "case must not defeat the opt-out");
  assert.equal(mergeAncestors(P, "  'none'  \n https://a.ex.com "), 'https://a.ex.com');
  // The sentinel never survives into the emitted policy — mixing it with real
  // sources is precisely what made it inert under CSP3's grammar.
  assert.ok(!mergeAncestors(P, "'none' https://portal.ex.com").includes("'none'"));
});

// ---------------------------------------------------------------------------
// 4. Real Caddy. What we wrote is not what Caddy runs.
// ---------------------------------------------------------------------------

const DOCKER = (() => {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch { return false; }
})();
const noDocker = DOCKER ? false : 'docker unavailable';

const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-edge-adapt-'));
const adapt = (text) => {
  const p = join(SCRATCH, 'Caddyfile');
  writeFileSync(p, text);
  const out = execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
    { stdio: 'pipe', timeout: 120000 });
  return JSON.parse(out.toString());
};

test('`caddy adapt` exits 0 on a Caddyfile covering every app shape', { skip: noDocker }, () => {
  // The deploy path gates on this exact command (reloadCaddy). A config it
  // refuses does not break routing — it means the fix silently never applies
  // and the box keeps serving the old config until someone notices.
  const p = join(SCRATCH, 'Caddyfile.shapes');
  writeFileSync(p, CF);
  let status = null;
  try {
    execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
      'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
      { stdio: 'pipe', timeout: 120000 });
    status = 0;
  } catch (e) {
    status = e.status;
    assert.fail(`caddy adapt exited ${e.status}: ${e.stderr?.toString().trim()}`);
  }
  assert.equal(status, 0);
  // The shapes that had to be in the file for that exit code to mean anything.
  for (const k of ['handle /plain*', 'handle /headless*', 'handle /bypasser/ws/runner*',
                   'handle /framed*', 'handle /denied*', 'handle /narrow*']) {
    assert.ok(craneNow.has(k), `${k} missing — adapt passed on a file that proves less than claimed`);
  }
  assert.ok(siteNow.has('custom.test.local') && siteNow.has('old.test.local'));
});

test('adapted JSON: bypass requests are logged, with the query value redacted', { skip: noDocker }, () => {
  const cfg = adapt(CF);
  const srv = cfg.apps.http.servers.srv0;

  // (a) The crane host — which is where every bypass route lives, since access
  // logging in Caddy is host-scoped — has a logger attached.
  const logger = srv.logs?.logger_names?.[CRANE];
  assert.ok(logger && logger.length, `no access logger for ${CRANE} in the adapted config`);

  // (b) No route opts out. log_skip adapts to a `vars` handler carrying
  // log_skip:true, which is why the check has to be on the JSON: the directive
  // does not survive as a recognisable line.
  const skips = [];
  (function walk(routes) {
    for (const rt of routes || []) {
      for (const h of rt.handle || []) {
        if (h.log_skip) skips.push(JSON.stringify(rt.match || 'no-match'));
        if (h.routes) walk(h.routes);
      }
    }
  })(srv.routes);
  assert.deepEqual(skips, [], 'a route still suppresses its own access log');

  // (c) The filter is real, not merely parseable.
  const enc = cfg.logging.logs[logger[0]].encoder;
  assert.equal(enc.format, 'filter');
  assert.equal(enc.wrap.format, 'json');
  const f = enc.fields['request>uri'];
  assert.deepEqual(f, { filter: 'regexp', regexp: '\\?.*', value: '?redacted' });

  // (d) Apply Caddy's own declared filter to the URI a bypass client sends. The
  // token aghook puts in the query string is the whole reason log_skip existed.
  const uri = '/bypasser/ws/runner?token=BYPASSSECRET123&x=2';
  const redacted = uri.replace(new RegExp(f.regexp), f.value);
  assert.equal(redacted, '/bypasser/ws/runner?redacted');
  assert.ok(!redacted.includes('BYPASSSECRET123'), 'the CLI token survives into the log record');
  // The record still identifies the request: path, and by extension the method,
  // status, IP and duration Caddy logs alongside it.
  assert.ok(redacted.startsWith('/bypasser/ws/runner'));

  // (e) Custom-domain hosts must land in skip_hosts rather than falling through
  // to Caddy's DEFAULT logger, which has no filter — that would turn this fix
  // into a new leak on a different host.
  assert.deepEqual(new Set(srv.logs.skip_hosts), new Set(['custom.test.local', 'old.test.local']));
});

test('adapted JSON: v2.43.1 really did drop the bypass record', { skip: noDocker }, () => {
  // Falsification for the test above. Same assertions against the vendored
  // pre-change snapshot: they must fail there, or they are not measuring the fix.
  const cfg = adapt(BEFORE);
  const srv = cfg.apps.http.servers.srv0;
  assert.equal(srv.logs, undefined, 'the pre-change config already had access logging');
  assert.equal(cfg.logging, undefined);
  const skips = [];
  (function walk(routes) {
    for (const rt of routes || []) {
      for (const h of rt.handle || []) {
        if (h.log_skip) skips.push(JSON.stringify(rt.match));
        if (h.routes) walk(h.routes);
      }
    }
  })(srv.routes);
  assert.equal(skips.length, 2, 'expected both bypass routes to carry log_skip before the change');
});

test('adapted JSON: the custom-domain server sets the baseline response headers', { skip: noDocker }, () => {
  const cfg = adapt(CF);
  // Find the route whose host match is the custom domain, in whichever server
  // the adapter placed it, and collect the response headers it sets.
  const set = {};
  for (const srv of Object.values(cfg.apps.http.servers)) {
    (function walk(routes, onCustom) {
      for (const rt of routes || []) {
        const hit = onCustom || (rt.match || []).some(m => (m.host || []).includes('custom.test.local'));
        for (const h of rt.handle || []) {
          if (hit && h.handler === 'headers') {
            for (const [k, v] of Object.entries(h.response?.set || {})) set[k.toLowerCase()] = v;
            for (const [k, v] of Object.entries(h.response?.deferred?.set || {})) set[k.toLowerCase()] = v;
          }
          if (h.routes) walk(h.routes, hit);
        }
      }
    })(srv.routes, false);
  }
  for (const h of ['strict-transport-security', 'x-content-type-options',
                   'referrer-policy', 'x-permitted-cross-domain-policies', 'permissions-policy']) {
    assert.ok(set[h], `custom domain serves no ${h} after adaptation`);
  }
  assert.match(String(set['strict-transport-security']), /max-age=31536000/);
});

// ---------------------------------------------------------------------------
// 5. The access log is conditional. Run last: it mutates the seeded DB.
// ---------------------------------------------------------------------------

test('an install with no bypass route gets no access log at all', () => {
  // Deliberate scoping — the redacting log is switched on for the operators who
  // created the unauthenticated surface, not for every install. The flip side is
  // the coupling: removing the last bypass path turns access logging back off.
  db.prepare("UPDATE apps SET auth_bypass_paths = NULL WHERE slug = 'bypasser'").run();
  const cf = generateCaddyfile();
  assert.ok(!innerBlocks(siteBlocks(cf).get(CRANE)).has('log'),
    'the access log is emitted on an install that has no auth-bypass path');
  assert.ok(!cf.includes('/bypasser/ws/runner'));
  // And it comes back with the route.
  db.prepare(`UPDATE apps SET auth_bypass_paths = '["/ws/runner"]' WHERE slug = 'bypasser'`).run();
  assert.ok(innerBlocks(siteBlocks(generateCaddyfile()).get(CRANE)).has('log'));
});

test('a bypass path on an undeployed env emits neither route nor log', () => {
  // anyBypassRoute gates on a LIVE deployment: the parent handle 503s, so there
  // is no unauthenticated surface to record and no reason to start logging.
  db.prepare("UPDATE apps SET auth_bypass_paths = NULL WHERE slug = 'bypasser'").run();
  db.prepare(`UPDATE apps SET auth_bypass_paths = '["/ws/runner"]' WHERE slug = 'undeployed'`).run();
  const cf = generateCaddyfile();
  assert.ok(!cf.includes('/undeployed/ws/runner'));
  assert.ok(!innerBlocks(siteBlocks(cf).get(CRANE)).has('log'));
  db.prepare("UPDATE apps SET auth_bypass_paths = NULL WHERE slug = 'undeployed'").run();
  db.prepare(`UPDATE apps SET auth_bypass_paths = '["/ws/runner"]' WHERE slug = 'bypasser'`).run();
  assert.equal(generateCaddyfile(), CF, 'the DB was not restored to the seeded state');
});

test('a headless app with a bypass path still gets no log and no exempt route', () => {
  // A headless app skips forward_auth for everything, so a per-path exemption on
  // it is meaningless — and must not be what switches platform logging on.
  db.prepare("UPDATE apps SET auth_bypass_paths = NULL WHERE slug = 'bypasser'").run();
  db.prepare(`UPDATE apps SET auth_bypass_paths = '["/ws/runner"]' WHERE slug = 'headless'`).run();
  const cf = generateCaddyfile();
  assert.ok(!cf.includes('/headless/ws/runner'));
  assert.ok(!innerBlocks(siteBlocks(cf).get(CRANE)).has('log'));
  db.prepare("UPDATE apps SET auth_bypass_paths = NULL WHERE slug = 'headless'").run();
  db.prepare(`UPDATE apps SET auth_bypass_paths = '["/ws/runner"]' WHERE slug = 'bypasser'`).run();
  assert.equal(generateCaddyfile(), CF);
});
