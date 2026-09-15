import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import http from 'node:http';
import net from 'node:net';

// AppCrane's embedding policy vs the app's OWN Content-Security-Policy (v2.77.0).
//
// THE BUG, as measured against caddy:2 before the fix. An app that sends
//
//   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-…';
//                            frame-ancestors 'none'; object-src 'none'
//
// was configured as embeddable in AppCrane, and the app-viewer frame still came
// up blank: "Framing … violates the following Content Security Policy directive:
// frame-ancestors 'none'". The generated Caddyfile said
// `header Content-Security-Policy "frame-ancestors <policy>"`, which READS like
// an override and is not one — a plain `header` set runs before the proxy, and
// reverse_proxy then adds the upstream's CSP alongside it. The response carried
// BOTH headers, and a browser enforces every policy it is handed, so the app's
// 'none' won the intersection.
//
// The fix is a deferred replacement of the app's own frame-ancestors plus an
// added header for apps that have none to replace. Everything else in the app's
// CSP survives.
//
// WHAT THIS FILE PINS, and why in this order:
//   1. the generated text (cheap, runs everywhere)
//   2. the ADAPTED JSON — specifically `deferred: true`, because a replacement
//      that is not deferred never sees the upstream header and silently does
//      nothing at all
//   3. the response a real Caddy actually emits, for every upstream CSP shape
//      that matters. Only (3) could have caught the shipped bug: the old text
//      and the old adapted JSON both looked perfectly reasonable.

const CRANE = 'crane.example.com';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-csp-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
// Must be psl-resolvable: an unresolvable CRANE_DOMAIN silently disables the
// platform default, which would make every assertion here vacuous.
process.env.CRANE_DOMAIN = CRANE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const insert = db.prepare(
  `INSERT INTO apps (name, slug, slot, source_type, auth_mode, frame_ancestors, visibility)
   VALUES (?,?,?,?,?,?,'private')`
);
const deploy = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?,?,'live')");
const mk = (slug, slot, o = {}) => {
  const id = insert.run(slug, slug, slot, 'managed', o.auth_mode ?? 'authenticated',
    o.frame_ancestors ?? null).lastInsertRowid;
  for (const env of ['production', 'sandbox']) deploy.run(id, env);
  return id;
};
mk('inherit', 1);                                                   // platform default only
mk('framed', 2, { frame_ancestors: 'https://portal.example.com' }); // union
mk('denied', 3, { frame_ancestors: "'none'" });                     // deny everything
mk('headless', 4, { auth_mode: 'headless' });                       // no forward_auth

const { generateCaddyfile } = await import('../server/services/caddy.js');
const { platformEmbedAncestors } = await import('../server/utils/embed.js');
const CF = generateCaddyfile();

const PLATFORM_FA = platformEmbedAncestors(db);
const FA = {
  inherit: PLATFORM_FA,
  framed: `${PLATFORM_FA} https://portal.example.com`,
  denied: "'none'",
  headless: PLATFORM_FA,
};

test('the platform default is actually active — otherwise everything below is vacuous', () => {
  assert.equal(PLATFORM_FA, "'self' https://*.example.com https://example.com");
});

/** The body of one `handle /<slug>*` block from the generated file. */
function handleBlock(slug) {
  const lines = CF.split('\n');
  const start = lines.findIndex(l => l.trim() === `handle /${slug}* {`);
  assert.notEqual(start, -1, `handle /${slug}* is not in the generated Caddyfile`);
  let depth = 0;
  const out = [];
  for (let i = start; i < lines.length; i++) {
    out.push(lines[i]);
    depth += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
    if (i > start && depth === 0) break;
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// 1. Generated text
// ---------------------------------------------------------------------------

test('every embeddable route replaces the app\'s own frame-ancestors and adds its own', () => {
  for (const slug of ['inherit', 'framed', 'denied', 'headless']) {
    for (const route of [slug, `${slug}-sandbox`]) {
      const blk = handleBlock(route);
      assert.ok(blk.includes(`Content-Security-Policy "(?i)(^\\s*|;\\s*)frame-ancestors[^;]*" "\${1}frame-ancestors ${FA[slug]}"`),
        `${route}: no frame-ancestors REPLACEMENT — a plain set leaves the app's own policy in a second header`);
      assert.ok(blk.includes(`+Content-Security-Policy "frame-ancestors ${FA[slug]}"`),
        `${route}: no added header — an app whose CSP has no frame-ancestors, or no CSP at all, would gain nothing`);
      assert.match(blk, /^\s+defer$/m,
        `${route}: the header block is not deferred, so the replacement runs before the proxy and never sees the app's header`);
    }
  }
});

test('the sandbox route is not forgotten', () => {
  // The two routes are emitted from one string, but that has been true of other
  // per-app settings that still ended up on production only.
  for (const slug of ['inherit', 'framed', 'denied', 'headless']) {
    const prod = handleBlock(slug).split('\n').filter(l => l.includes('Content-Security-Policy'));
    const sand = handleBlock(`${slug}-sandbox`).split('\n').filter(l => l.includes('Content-Security-Policy'));
    assert.ok(prod.length === 2, `${slug}: expected a replace and an add, got ${prod.length}`);
    assert.deepEqual(sand, prod, `${slug}-sandbox carries a different embedding policy from production`);
  }
});

test("a deny-everything policy keeps the app's own X-Frame-Options", () => {
  // A 'none' policy has no embedder to unlock, so stripping the app's XFO would
  // only discard framing protection on browsers predating frame-ancestors.
  const blk = handleBlock('denied');
  assert.ok(!/-X-Frame-Options/.test(blk),
    "X-Frame-Options is stripped on a deny-everything policy, weakening old browsers for nothing");
  assert.ok(blk.includes(`+Content-Security-Policy "frame-ancestors 'none'"`));
  // And every other policy still strips it: an upstream SAMEORIGIN would veto
  // the CSP we just wrote and the listed embedder would get nothing.
  for (const slug of ['inherit', 'framed']) {
    assert.match(handleBlock(slug), /^\s+-X-Frame-Options$/m, `${slug} lost the X-Frame-Options strip`);
  }
});

test('an app with no policy at all is left completely alone', () => {
  // Platform default off + frame_ancestors NULL → mergeAncestors returns null and
  // AppCrane must not touch the app's headers in any way.
  db.prepare(`INSERT INTO settings (key, value) VALUES ('platform_embed_same_site', 'off')
              ON CONFLICT(key) DO UPDATE SET value = 'off'`).run();
  try {
    assert.equal(platformEmbedAncestors(db), null, 'the platform default did not actually turn off');
    const off = generateCaddyfile();
    const blk = off.split('handle /inherit* {')[1].split('\n    }')[0];
    assert.ok(!blk.includes('Content-Security-Policy'), 'an app with no policy gained a CSP override');
    assert.ok(!blk.includes('X-Frame-Options'), 'an app with no policy had its X-Frame-Options stripped');
    // An app that set its own value still gets one — the override is keyed on the
    // policy, not on the platform default being enabled.
    const framed = off.split('handle /framed* {')[1].split('\n    }')[0];
    assert.ok(framed.includes('+Content-Security-Policy "frame-ancestors https://portal.example.com"'));
  } finally {
    db.prepare("UPDATE settings SET value = 'on' WHERE key = 'platform_embed_same_site'").run();
  }
});

// ---------------------------------------------------------------------------
// 2. Real Caddy
// ---------------------------------------------------------------------------

const DOCKER = (() => {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch { return false; }
})();
const noDocker = DOCKER ? false : 'docker unavailable';
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-csp-caddy-'));

test('the generated Caddyfile still passes real `caddy validate`', { skip: noDocker }, () => {
  // reloadCaddy() gates on Caddy accepting the config. A file it rejects does not
  // break routing — it means this fix silently never applies and the box keeps
  // serving the old config.
  const p = join(SCRATCH, 'Caddyfile');
  writeFileSync(p, CF);
  try {
    execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
      'caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
      { stdio: 'pipe', timeout: 120000 });
  } catch (e) {
    assert.fail(`caddy validate exited ${e.status}: ${e.stderr?.toString().trim()}`);
  }
});

test('adapted JSON: the CSP ops are DEFERRED', { skip: noDocker }, () => {
  // The assertion that distinguishes this fix from the shipped bug. A header
  // handler that is not deferred applies before the proxy: the replacement finds
  // no upstream header to rewrite and the set is simply appended to by the
  // upstream's own. Measured: a bare `header <field> <find> <replace>` adapts
  // WITHOUT `deferred`, and changed nothing at all at runtime.
  const p = join(SCRATCH, 'Caddyfile');
  writeFileSync(p, CF);
  const cfg = JSON.parse(execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
    { stdio: 'pipe', timeout: 120000 }).toString());

  function routeFor(routes, needle, acc = []) {
    for (const rt of routes || []) {
      if (JSON.stringify(rt.match || '').includes(needle)) acc.push(rt);
      for (const h of rt.handle || []) if (h.routes) routeFor(h.routes, needle, acc);
    }
    return acc;
  }
  function cspHandlers(handlers, acc = []) {
    for (const h of handlers || []) {
      if (h.handler === 'subroute') { for (const rt of h.routes || []) cspHandlers(rt.handle, acc); continue; }
      if (h.handler === 'headers' && JSON.stringify(h.response || {}).includes('Content-Security-Policy')) acc.push(h.response);
    }
    return acc;
  }

  for (const slug of ['inherit', 'framed', 'denied', 'headless']) {
    const [rt] = routeFor(cfg.apps.http.servers.srv0.routes, `"/${slug}*"`);
    assert.ok(rt, `/${slug}* route missing from the adapted JSON`);
    const [resp] = cspHandlers(rt.handle);
    assert.ok(resp, `/${slug}*: no CSP response-header handler survived adaptation`);
    assert.equal(resp.deferred, true,
      `/${slug}*: the CSP ops are not deferred — the replacement will run before the proxy and never see the app's own header`);
    assert.ok(resp.replace?.['Content-Security-Policy']?.[0]?.search_regexp,
      `/${slug}*: the replacement op did not survive adaptation`);
    assert.deepEqual(resp.add?.['Content-Security-Policy'], [`frame-ancestors ${FA[slug]}`]);
  }
});

// ---------------------------------------------------------------------------
// 3. End to end. What a browser would actually be handed.
//
// The generated file is rewritten for the harness exactly as
// identity-transparency.test.js does it: http:// site addresses (no ACME in a
// test) and 127.0.0.1 upstreams become host.docker.internal. Nothing under test
// — the header ops, the route shapes — is touched.
// ---------------------------------------------------------------------------

// The real policy that started this, with the origins replaced by example.com.
const APP_CSP = "default-src 'self'; script-src 'self' 'nonce-r4nd0m' https://challenges.example.com; " +
  "style-src 'self' 'unsafe-inline'; frame-src https://challenges.example.com; frame-ancestors 'none'; " +
  "base-uri 'self'; object-src 'none'; form-action 'self'";

// Every upstream shape the override has to survive. The key is the path suffix
// the test requests; the stub upstream reads it back off the request.
const UPSTREAM = {
  none: [['Content-Security-Policy', APP_CSP]],
  nofa: [['Content-Security-Policy', "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'"]],
  two: [['Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"],
        ['Content-Security-Policy', "object-src 'none'; frame-ancestors https://elsewhere.example.com"]],
  bare: [],
  xfo: [['Content-Security-Policy', APP_CSP], ['X-Frame-Options', 'DENY']],
  weird: [['Content-Security-Policy', "default-src 'self';   Frame-Ancestors    'none'   ;object-src 'none'"]],
  last: [['Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none'"]],
  report: [['Content-Security-Policy', APP_CSP],
           ['Content-Security-Policy-Report-Only', "default-src 'self'; frame-ancestors 'none'"]],
  // A directive whose VALUE contains the literal string. An unanchored
  // find-regex rewrites the middle of this URL; the anchored one does not.
  inurl: [['Content-Security-Policy', "default-src 'self'; report-uri https://r.example.com/frame-ancestors/x; frame-ancestors 'none'"]],
  // frame-ancestors FIRST, and a value with leading whitespace: `^` has to be
  // part of the boundary alternation or neither is rewritten at all.
  first: [['Content-Security-Policy', "frame-ancestors 'none'; default-src 'self'"]],
  lead: [['Content-Security-Policy', "  frame-ancestors 'none'; default-src 'self'"]],
};

function rawGet(port, path, host) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    });
    let buf = '';
    sock.on('data', c => buf += c);
    sock.on('end', () => resolve(buf));
    sock.on('error', reject);
  });
}
function parse(raw) {
  const head = raw.split('\r\n\r\n')[0].split('\r\n');
  const headers = [];
  for (const line of head.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers.push([line.slice(0, i).trim().toLowerCase(), line.slice(i + 1).trim()]);
  }
  return { status: Number(head[0].split(' ')[1]), headers };
}
const freePort = () => new Promise(resolve => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

test('what a browser is actually handed, through real Caddy', { skip: noDocker }, async (t) => {
  const listen = (srv) => new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

  // Stands in for /api/identity/verify — authorizes everything; identity
  // forwarding is identity-transparency.test.js's subject, not this file's.
  const verifySrv = http.createServer((_req, res) => { res.writeHead(200); res.end('{}'); });
  // The app container. Which headers it sends is chosen by the request path,
  // which survives `uri strip_prefix /<slug>`.
  const appSrv = http.createServer((req, res) => {
    const kase = req.url.replace(/^\//, '').split('?')[0];
    res.statusCode = 200;
    for (const [k, v] of (UPSTREAM[kase] || [])) res.appendHeader(k, v);
    res.setHeader('Content-Type', 'text/html');
    res.end('<html>app</html>');
  });
  const verifyPort = await listen(verifySrv);
  const appPort = await listen(appSrv);
  const hostPort = await freePort();
  const name = `appcrane-csp-test-${process.pid}`;

  const live = CF
    .replace(/^import .*$/m, '')
    .replace(/^(\S.*) \{$/gm, (_m, addr) => `http://${addr} {`)
    .replace(/127\.0\.0\.1:5001/g, `host.docker.internal:${verifyPort}`)
    .replace(/127\.0\.0\.1:\d+/g, `host.docker.internal:${appPort}`);
  const livePath = join(SCRATCH, 'Caddyfile.live');
  writeFileSync(livePath, live);

  t.after(() => {
    try { execFileSync('docker', ['rm', '-f', name], { stdio: 'ignore', timeout: 30000 }); } catch { /* already gone */ }
    verifySrv.close();
    appSrv.close();
  });

  execFileSync('docker', ['run', '-d', '--rm', '--name', name,
    '--add-host', 'host.docker.internal:host-gateway',
    '-p', `127.0.0.1:${hostPort}:80`,
    '-v', `${livePath}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe', timeout: 120000 });

  // Retry until a REAL HTTP response comes back. A bare TCP connect succeeds
  // against the published docker port long before Caddy is listening, and the
  // empty replies that produces look exactly like "the directive ate the
  // header" — which is how the first draft of this harness mismeasured.
  async function get(path) {
    for (let i = 0; i < 120; i++) {
      try {
        const raw = await rawGet(hostPort, path, CRANE);
        if (raw.startsWith('HTTP/')) return parse(raw);
      } catch { /* not up yet */ }
      await new Promise(r => setTimeout(r, 250));
    }
    return null;
  }

  // Preflight. These assertions are about what Caddy FORWARDS, so the container
  // has to reach the stub on the host — `--add-host host.docker.internal:
  // host-gateway` does not route back to the host on every runner (GitHub
  // Actions answers 502 for every route). A 502 there says nothing about the
  // config under test, so skip with the reason rather than red CI on every push.
  const probe = await get('/inherit/bare');
  if (!probe || probe.status !== 200) {
    t.skip(`caddy container cannot reach the host upstream (${probe ? probe.status : 'no response'}) — host-gateway networking unavailable on this runner`);
    return;
  }

  const csp = (r) => r.headers.filter(([k]) => k === 'content-security-policy').map(([, v]) => v);
  /** Every frame-ancestors a browser would enforce across all CSP headers. */
  const allFa = (r) => csp(r).map(v => v.match(/(?:^|;)\s*frame-ancestors\s*([^;]*)/i)?.[1]?.trim()).filter(Boolean);

  for (const slug of ['inherit', 'framed', 'denied', 'headless']) {
    await t.test(`/${slug}: AppCrane's policy is the only frame-ancestors in the response`, async () => {
      for (const kase of Object.keys(UPSTREAM)) {
        const r = await get(`/${slug}/${kase}`);
        assert.equal(r.status, 200, `/${slug}/${kase} did not reach the upstream`);
        const fa = allFa(r);
        assert.ok(fa.length > 0, `/${slug}/${kase}: no frame-ancestors at all — the app is framable by anyone`);
        for (const v of fa) {
          assert.equal(v, FA[slug],
            `/${slug}/${kase}: a frame-ancestors the browser enforces is "${v}", not AppCrane's "${FA[slug]}". ` +
            `Full CSP: ${JSON.stringify(csp(r))}`);
        }
      }
    });
  }

  await t.test("the app's own CSP survives intact apart from frame-ancestors", async () => {
    const r = await get('/framed/none');
    const app = csp(r).find(v => v.includes('script-src'));
    assert.ok(app, 'the app\'s own CSP was destroyed — script-src and its nonce are gone');
    // Byte-for-byte the app's policy, with only the frame-ancestors value swapped.
    assert.equal(app, APP_CSP.replace("frame-ancestors 'none'", `frame-ancestors ${FA.framed}`));
    for (const d of ["'nonce-r4nd0m'", "object-src 'none'", "form-action 'self'", "base-uri 'self'",
                     'frame-src https://challenges.example.com']) {
      assert.ok(app.includes(d), `the app's CSP lost ${d}`);
    }
  });

  await t.test('a directive whose value merely contains the string is not mangled', async () => {
    const r = await get('/framed/inurl');
    const app = csp(r).find(v => v.includes('report-uri'));
    assert.ok(app.includes('https://r.example.com/frame-ancestors/x'),
      `the report-uri value was rewritten by the frame-ancestors replacement: ${app}`);
  });

  await t.test("the app's own separator survives — no stray ';' and no lost space", async () => {
    // The replacement captures the boundary instead of consuming it. An earlier
    // draft ate the space after the ';' and emitted `…;frame-ancestors …`.
    const ours = `frame-ancestors ${FA.framed}`;
    assert.ok(csp(await get('/framed/first')).includes(`${ours}; default-src 'self'`),
      'frame-ancestors as the FIRST directive was not rewritten, or gained a leading separator');
    // The upstream sent this one with two leading spaces; HTTP strips leading
    // OWS from a field value in transit, so by the time the ops run it is
    // indistinguishable from the case above. Measured, not assumed: the
    // assertion is that it is rewritten, and without a stray separator.
    assert.deepEqual(csp(await get('/framed/lead')), [`${ours}; default-src 'self'`, ours],
      'a policy whose first directive is frame-ancestors was not rewritten — `^` is missing from the boundary alternation');
  });

  await t.test('an app that sends no CSP, and one whose CSP has no frame-ancestors, both gain ours', async () => {
    for (const kase of ['bare', 'nofa']) {
      const r = await get(`/framed/${kase}`);
      assert.deepEqual(allFa(r), [FA.framed], `/framed/${kase}`);
    }
    // …and the one with no frame-ancestors keeps the rest of its policy.
    const nofa = csp(await get('/framed/nofa')).find(v => v.includes('script-src'));
    assert.ok(nofa.includes("'nonce-r4nd0m'"));
  });

  await t.test('X-Frame-Options: the strip applies, except on a deny policy', async () => {
    const xfo = (r) => r.headers.filter(([k]) => k === 'x-frame-options').map(([, v]) => v);
    for (const slug of ['inherit', 'framed', 'headless']) {
      assert.deepEqual(xfo(await get(`/${slug}/xfo`)), [],
        `/${slug}: the app's X-Frame-Options: DENY survived and vetoes the CSP for every listed embedder`);
    }
    assert.deepEqual(xfo(await get('/denied/xfo')), ['DENY'],
      "a deny-everything policy threw away the app's own X-Frame-Options");
  });

  await t.test('Content-Security-Policy-Report-Only is left alone', async () => {
    // Deliberate: report-only blocks nothing, so it cannot veto the platform
    // policy, and rewriting it would corrupt the app's own violation reports.
    const r = await get('/framed/report');
    const ro = r.headers.filter(([k]) => k === 'content-security-policy-report-only').map(([, v]) => v);
    assert.deepEqual(ro, ["default-src 'self'; frame-ancestors 'none'"]);
  });
});
