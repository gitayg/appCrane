import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';
import { setupFixture, setSetting } from './caddy-app-isolation-fixtures.js';

// Per-app origins (services/appOrigin.js) in the generated Caddyfile.
//
// Off (no app_isolation_domain, every custom_domain_auth = 0) the file must be
// byte-for-byte what it was before the feature: the golden was recorded from
// the unmodified generator against this same fixture. On, every app moves to
// its own host and the platform host only redirects to it.

const HERE = dirname(fileURLToPath(import.meta.url));
const { db, ids } = await setupFixture();
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
// The golden carries the rotated-file output; pin the directory check so the
// result does not depend on whether this machine has /var/log/caddy.
setAccessLogDirCheck(() => true);

const ISO = 'apps.example.test';
const CRANE = 'crane.example.test';

function isolation(domain, tls = null) {
  setSetting(db, 'app_isolation_domain', domain);
  setSetting(db, 'app_isolation_tls_cert_file', tls ? tls.cert : '');
  setSetting(db, 'app_isolation_tls_key_file', tls ? tls.key : '');
}
const customDomainAuth = (id, v) => db.prepare('UPDATE apps SET custom_domain_auth = ? WHERE id = ?').run(v, id);

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

/** `handle` blocks of one site body (4-space indent): path -> body. */
function handles(body) {
  const out = new Map();
  const re = /^ {4}handle ?([^\s{]*) \{$/gm;
  let m;
  while ((m = re.exec(body)) !== null) {
    let depth = 0, i = body.indexOf('{', m.index), end = i;
    for (; i < body.length; i++) {
      if (body[i] === '{') depth++;
      else if (body[i] === '}' && --depth === 0) { end = i; break; }
    }
    out.set(m[1] || '(catch-all)', body.slice(m.index, end + 1));
  }
  return out;
}

const STRIP3 = 'request_header Cookie "(^|;\\s*)(cc_token|__Host-cc_token|__Host-cc_app|__Host-cc_handoff)=[^;]*" ""';
const APP_PORT = /reverse_proxy 127\.0\.0\.1:4\d{3}/;

test('off: byte-identical to the generator before per-app origins', () => {
  isolation('');
  const golden = readFileSync(join(HERE, 'caddy-app-isolation-off.golden'), 'utf8');
  assert.equal(generateCaddyfile(), golden);
});

test('off with an invalid isolation domain: still byte-identical', () => {
  isolation('not a domain');
  assert.equal(generateCaddyfile(), readFileSync(join(HERE, 'caddy-app-isolation-off.golden'), 'utf8'));
  isolation('');
});

test('on, on-demand TLS: a global on_demand_tls block is the first block, ahead of the import', () => {
  isolation(ISO);
  const cf = generateCaddyfile();
  const firstBrace = cf.indexOf('{');
  assert.ok(firstBrace < cf.indexOf('import /etc/caddy/sites/'), 'options block must precede the import');
  // One global block: on-demand TLS, then the redacting error logger the bypass
  // paths in this fixture switch on (a second global block is a parse error).
  assert.match(cf.slice(0, cf.indexOf('import')),
    /^# Managed by AppCrane[^\n]*\n\n\{\n {4}on_demand_tls \{\n {8}ask http:\/\/127\.0\.0\.1:5001\/api\/identity\/tls-ask\n {4}\}\n {4}log appcrane_errors \{\n[\s\S]*\n\}\n\n$/);
  assert.equal(cf.slice(0, cf.indexOf('import')).match(/^\{$/gm).length, 1);
  assert.match(sites(cf).get(`hub.${ISO}`), /^ {4}tls \{\n {8}on_demand\n {4}\}$/m);
});

test('on, wildcard cert files: tls <cert> <key> on every app host and no on-demand options', () => {
  isolation(ISO, { cert: '/etc/caddy/certs/w.crt', key: '/etc/caddy/certs/w.key' });
  const cf = generateCaddyfile();
  assert.doesNotMatch(cf, /on_demand/);
  // The only global option left is the redacting error logger (this fixture has bypass paths).
  assert.match(cf, /^# Managed by AppCrane - do not edit manually\n\n\{\n {4}log appcrane_errors \{\n[\s\S]*?\n\}\n\nimport /);
  for (const [name, body] of sites(cf)) {
    if (name.endsWith(`.${ISO}`)) assert.match(body, /^ {4}tls \/etc\/caddy\/certs\/w\.crt \/etc\/caddy\/certs\/w\.key$/m, name);
  }
});

test('on: the platform host redirects every app mount to the app host and proxies no app', () => {
  isolation(ISO);
  const crane = sites(generateCaddyfile()).get(CRANE);
  const h = handles(crane);
  assert.match(h.get('/hub*'), /redir https:\/\/hub\.apps\.example\.test\{uri\} 308/);
  assert.match(h.get('/hub-sandbox*'), /redir https:\/\/hub-sandbox\.apps\.example\.test\{uri\} 308/);
  assert.match(h.get('/oldhub*'), /redir https:\/\/hub\.apps\.example\.test\{uri\} 308/);
  assert.match(h.get('/oldhub-sandbox*'), /redir https:\/\/hub-sandbox\.apps\.example\.test\{uri\} 308/);
  assert.match(h.get('/shop-sandbox*'), /respond "Not deployed" 503/);
  assert.match(h.get('/idle*'), /respond "Not deployed" 503/);
  // Only the legacy machine routes (next test) still proxy an app here.
  const outsideLegacy = crane.replace(/ {8}handle @legacy_machine \{[\s\S]*?\n {8}\}\n/g, '');
  assert.doesNotMatch(outsideLegacy, APP_PORT, 'an app is still proxied on the platform host');
  assert.doesNotMatch(crane, /forward_auth/);
  assert.match(h.get('(catch-all)'), /reverse_proxy 127\.0\.0\.1:5001/);
});

// crane, 28 Oct 2026: a relay agent (ureq) does not re-send a POST on a 308, so
// every relayed device went silent when isolation turned the old address into
// a redirect. Machine methods on exempt paths now reach the app there.
test('on: the old address passes non-GET requests on exempt paths (and headless apps) to the app, safely', () => {
  isolation(ISO);
  const crane = sites(generateCaddyfile()).get(CRANE);
  const h = handles(crane);
  const runner = h.get('/runner*');
  assert.match(runner, /path \/runner\/ws\/runner\* \/runner\/hooks\/\*\n/);
  assert.match(runner, /not method GET HEAD\n/);
  assert.match(runner, /request_header -Cookie\n/);
  assert.match(runner, /request_header -X-AppCrane-User\n/);
  assert.match(runner, /uri strip_prefix \/runner\n/);
  assert.match(runner, /Content-Security-Policy "sandbox"\n[\s\S]*-Set-Cookie\n[\s\S]*-Clear-Site-Data\n[\s\S]*defer/);
  assert.match(runner, /reverse_proxy 127\.0\.0\.1:4005 \{/);
  assert.match(runner, /\n {8}handle \{\n {12}redir https:\/\/runner\.apps\.example\.test\{uri\} 308\n {8}\}/);
  assert.match(h.get('/runner-sandbox*'), /path \/runner-sandbox\/ws\/runner\*[\s\S]*reverse_proxy 127\.0\.0\.1:4006 \{/);
  assert.match(h.get('/open*'), /path \/open\*\n/);
  assert.doesNotMatch(h.get('/hub*'), /legacy_machine/, 'an app with no exempt path keeps a plain redirect');
  assert.doesNotMatch(h.get('/oldhub*'), /legacy_machine/);
  assert.doesNotMatch(h.get('/idle*'), /legacy_machine/, 'an env that is not live gets nothing to proxy to');
  assert.match(crane, /request>uri regexp/, 'the old address is logged while it still carries traffic');
});

test('on: one site per LIVE app environment', () => {
  isolation(ISO);
  const names = [...sites(generateCaddyfile()).keys()].filter(n => n.endsWith(`.${ISO}`)).sort();
  assert.deepEqual(names, ['boxed', 'boxed-sandbox', 'hub', 'hub-sandbox', 'open', 'open-sandbox', 'runner', 'runner-sandbox', 'shop']
    .map(l => `${l}.${ISO}`).sort());
});

test('on: app host verifies in isolated mode, before the prefix rewrite, and strips every session cookie', () => {
  isolation(ISO);
  for (const [host, slug, env, prefix] of [[`hub.${ISO}`, 'hub', 'production', '/hub'], [`hub-sandbox.${ISO}`, 'hub', 'sandbox', '/hub-sandbox']]) {
    const body = sites(generateCaddyfile()).get(host);
    assert.match(body, new RegExp(`^ {4}@appcrane_compat path ${prefix} ${prefix}/\\*$`, 'm'), host);
    const main = handles(body).get('(catch-all)');
    const fa = main.indexOf(`uri /api/identity/verify?app=${slug}&env=${env}&host=isolated`);
    const strip = main.indexOf(STRIP3);
    const rewrite = main.indexOf(`uri @appcrane_compat strip_prefix ${prefix}`);
    const route = main.indexOf('route {');
    assert.ok(route > -1 && fa > route && strip > fa && rewrite > strip, `${host}: order route < forward_auth < cookie strip < rewrite (${route}, ${fa}, ${strip}, ${rewrite})`);
    assert.ok(main.indexOf('request_header -X-AppCrane-User\n') < fa, `${host}: forged identity stripped before verify`);
    assert.doesNotMatch(main, /uri strip_prefix/, `${host}: an unconditional prefix strip`);
    assert.match(main, /X-AppCrane-Auth-Mode "authenticated"/);
  }
});

test('on: /__appcrane/*, /api/me and /api/directory go to AppCrane on every app host', () => {
  isolation(ISO);
  for (const [name, body] of sites(generateCaddyfile())) {
    if (!name.endsWith(`.${ISO}`)) continue;
    const h = handles(body);
    for (const p of ['/__appcrane/*', '/api/me', '/api/directory']) {
      assert.equal(h.get(p), `    handle ${p} {\n        reverse_proxy 127.0.0.1:5001\n    }`, `${name} ${p}`);
    }
  }
});

test('on: every app-proxying route on an app host strips the three session cookies and forged identity', () => {
  isolation(ISO);
  let checked = 0;
  for (const [name, body] of sites(generateCaddyfile())) {
    if (!name.endsWith(`.${ISO}`)) continue;
    for (const [path, hb] of handles(body)) {
      if (!APP_PORT.test(hb)) continue;
      checked++;
      assert.ok(hb.includes(STRIP3), `${name} ${path}: session cookies reach the app`);
      assert.ok(hb.includes('request_header -X-AppCrane-Is-Admin'), `${name} ${path}: forged identity reaches the app`);
    }
  }
  assert.ok(checked >= 12, `expected app routes to check, found ${checked}`);
});

test('on: headless app has no forward_auth; bypass paths at the root and under the prefix; access log only there', () => {
  isolation(ISO);
  const s = sites(generateCaddyfile());
  const open = handles(s.get(`open.${ISO}`)).get('(catch-all)');
  assert.doesNotMatch(open, /forward_auth/);
  assert.match(open, /X-AppCrane-Auth-Mode "headless"/);
  assert.match(open, /uri @appcrane_compat strip_prefix \/open\n/);

  const runner = handles(s.get(`runner.${ISO}`));
  assert.match(runner.get('/ws/runner*'), /X-AppCrane-Auth-Mode "bypass"/);
  assert.doesNotMatch(runner.get('/ws/runner*'), /strip_prefix|forward_auth/);
  assert.match(runner.get('/runner/ws/runner*'), /uri strip_prefix \/runner\n/);
  assert.ok(runner.has('/hooks/*') && runner.has('/runner/hooks/*'));
  assert.match(s.get(`runner.${ISO}`), /request>uri regexp/);
  assert.doesNotMatch(s.get(`hub.${ISO}`), /request>uri regexp/);
});

test('on: a bypass entry under /__appcrane cannot shadow the AppCrane route', () => {
  isolation(ISO);
  db.prepare('UPDATE apps SET auth_bypass_paths = ? WHERE id = ?').run(JSON.stringify(['/__appcrane/session', '/ws/runner']), ids.runner);
  try {
    const h = handles(sites(generateCaddyfile()).get(`runner.${ISO}`));
    assert.ok(!h.has('/__appcrane/session*') && !h.has('/runner/__appcrane/session*'));
    assert.ok(h.has('/ws/runner*'));
  } finally {
    db.prepare('UPDATE apps SET auth_bypass_paths = ? WHERE id = ?').run(JSON.stringify(['/ws/runner', '/hooks/']), ids.runner);
  }
});

test('on: frame-ancestors = the app policy plus the platform origin; \'none\' stays \'none\'', () => {
  isolation(ISO);
  const s = sites(generateCaddyfile());
  assert.match(s.get(`hub.${ISO}`),
    /\+Content-Security-Policy "frame-ancestors 'self' https:\/\/\*\.example\.test https:\/\/example\.test https:\/\/portal\.example\.com https:\/\/crane\.example\.test"/);
  assert.match(s.get(`shop.${ISO}`), /\+Content-Security-Policy "frame-ancestors 'none'"/);
});

test('on: crash page names the app from the host\'s prefix', () => {
  isolation(ISO);
  assert.match(sites(generateCaddyfile()).get(`hub-sandbox.${ISO}`), /rewrite \* \/api\/_crashed\/hub-sandbox\{uri\}/);
});

for (const iso of ['', ISO]) {
  test(`custom_domain_auth = 1 (isolation ${iso ? 'on' : 'off'}): the custom domain runs AppCrane sign-in`, () => {
    isolation(iso);
    customDomainAuth(ids.shop, 1);
    try {
      const s = sites(generateCaddyfile());
      const shop = s.get('shop.example.com');
      const h = handles(shop);
      for (const p of ['/__appcrane/*', '/api/me', '/api/directory']) assert.match(h.get(p), /reverse_proxy 127\.0\.0\.1:5001/);
      const main = h.get('(catch-all)');
      assert.ok(main.indexOf('uri /api/identity/verify?app=shop&env=production&host=isolated') < main.indexOf(STRIP3));
      assert.ok(main.includes(STRIP3));
      assert.doesNotMatch(main, /strip_prefix|frame-ancestors/);
      // The other custom domain keeps today's passthrough.
      assert.match(s.get('boxed.example.com'), /X-AppCrane-Auth-Mode "bypass"/);
      assert.doesNotMatch(s.get('boxed.example.com'), /forward_auth/);
      assert.match(s.get('old-shop.example.com'), /redir https:\/\/shop\.example\.com\{uri\} permanent/);
      if (!iso) {
        // Off, the platform host is untouched by the flag.
        const golden = sites(readFileSync(join(HERE, 'caddy-app-isolation-off.golden'), 'utf8'));
        assert.equal(s.get(CRANE), golden.get(CRANE));
      }
    } finally {
      customDomainAuth(ids.shop, 0);
    }
  });
}

// ── Real Caddy ──────────────────────────────────────────────────────────────

let noDocker = false;
try { execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'ignore', timeout: 15000 }); } catch (_) { noDocker = 'docker or the caddy:2 image is not available'; }
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-isolation-caddy-'));
const NAME = `crane-isolation-live-${process.pid}`;
after(() => {
  try { execFileSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' }); } catch (_) { /* never started */ }
  rmSync(SCRATCH, { recursive: true, force: true });
});

test('caddy:2 adapts the on-demand config: verify runs before the rewrite inside the app-host route', { skip: noDocker }, () => {
  isolation(ISO);
  customDomainAuth(ids.shop, 1);
  try {
    const p = join(SCRATCH, 'Caddyfile.adapt');
    writeFileSync(p, generateCaddyfile().replace('import /etc/caddy/sites/*.caddy\n', ''));
    const cfg = JSON.parse(execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
      'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], { stdio: 'pipe', timeout: 120000 }).toString());
    assert.equal(cfg.apps.tls.automation.on_demand.permission.endpoint, 'http://127.0.0.1:5001/api/identity/tls-ask');
    const site = cfg.apps.http.servers.srv0.routes.find(r => r.match?.some(m => m.host?.includes(`hub.${ISO}`)));
    const flat = JSON.stringify(site);
    const verify = flat.indexOf('/api/identity/verify?app=hub&env=production&host=isolated');
    const rewrite = flat.indexOf('"strip_path_prefix":"/hub"');
    assert.ok(verify > -1 && rewrite > verify, `verify ${verify} must come before rewrite ${rewrite}`);
  } finally {
    customDomainAuth(ids.shop, 0);
  }
});

test('apps directly under the platform host: own site per app, the platform site still redirects, and caddy:2 matches them apart', { skip: noDocker }, () => {
  isolation(CRANE);
  const text = generateCaddyfile();
  const all = sites(text);
  assert.ok(all.has(CRANE), 'the platform site is missing');
  assert.ok(all.has(`hub.${CRANE}`) && all.has(`hub-sandbox.${CRANE}`), 'the app sites are missing');
  assert.match(handles(all.get(CRANE)).get('/hub*'), /redir https:\/\/hub\.crane\.example\.test\{uri\} 308/);
  assert.doesNotMatch(all.get(CRANE).replace(/ {8}handle @legacy_machine \{[\s\S]*?\n {8}\}\n/g, ''), APP_PORT,
    'an app is still proxied on the platform host');
  const p = join(SCRATCH, 'Caddyfile.nested');
  writeFileSync(p, text.replace('import /etc/caddy/sites/*.caddy\n', ''));
  const cfg = JSON.parse(execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], { stdio: 'pipe', timeout: 120000 }).toString());
  const hostsOf = (r) => (r.match || []).flatMap(m => m.host || []);
  const routes = cfg.apps.http.servers.srv0.routes;
  const platform = routes.filter(r => hostsOf(r).includes(CRANE));
  assert.equal(platform.length, 1, 'the platform host is matched by more than one site');
  assert.deepEqual(hostsOf(platform[0]), [CRANE], 'the platform site also matches an app host');
  assert.ok(routes.some(r => hostsOf(r).includes(`hub.${CRANE}`)), 'no route for the app host');
});

function curl(port, host, path, headers = []) {
  const args = ['-s', '-o', '-', '-w', '\n%{http_code} %{redirect_url}', '-H', `Host: ${host}`];
  for (const h of headers) args.push('-H', h);
  return execFileSync('curl', [...args, `http://127.0.0.1:${port}${path}`], { timeout: 20000 }).toString();
}

test('live caddy:2: redirect, prefix strip, cookie strip, AppCrane routes, handoff', { skip: noDocker }, async () => {
  isolation(ISO, { cert: '/unused.crt', key: '/unused.key' });
  // The generated file served over plain HTTP on :8080, with throwaway
  // upstreams on the ports it proxies to: an app that echoes what it received
  // and an AppCrane whose verify accepts only __Host-cc_app=good.
  let cf = generateCaddyfile()
    .replace('import /etc/caddy/sites/*.caddy\n', '')
    .replace(/^ {4}tls \S+ \S+\n/gm, '')
    .replace(/^([a-z0-9.-]+\.(?:test|com)) \{$/gm, 'http://$1:8080 {');
  // The generated file opens with a global block (the error logger); the
  // test-only options go inside it, since a second global block is a parse error.
  assert.ok(cf.includes('\n\n{\n    log appcrane_errors {'), 'no global block to extend');
  cf = cf.replace('\n\n{\n', '\n\n{\n\tauto_https off\n\tadmin off\n') + `
http://:4001 {
\trespond "APP path={uri} cookie=[{header.Cookie}] user=[{header.X-AppCrane-User}]" 200
}
http://:4005 {
\theader {
\t\tSet-Cookie "app=leak"
\t\tClear-Site-Data "\\"cookies\\""
\t\tStrict-Transport-Security "max-age=0"
\t\tAccess-Control-Allow-Origin "*"
\t\tAccess-Control-Allow-Credentials "true"
\t\tNEL "{\\"report_to\\":\\"x\\",\\"max_age\\":99999}"
\t\tReport-To "{\\"group\\":\\"x\\"}"
\t\tLink "</evil.js>; rel=preload"
\t\tRefresh "0; url=https://evil.example"
\t\tCross-Origin-Resource-Policy "cross-origin"
\t\tX-Relay-Id "kept"
\t}
\trespond "RUNNER {method} path={uri} cookie=[{header.Cookie}] user=[{header.X-AppCrane-User}]" 200
}
http://:5001 {
\t@authed {
\t\tpath /api/identity/verify
\t\theader Cookie *__Host-cc_app=good*
\t}
\thandle @authed {
\t\theader X-AppCrane-User "alice"
\t\trespond 200
\t}
\thandle /api/identity/verify {
\t\tredir "https://${CRANE}/api/identity/handoff?app={query.app}&env={query.env}&return={header.X-Forwarded-Uri}" 302
\t}
\thandle {
\t\trespond "APPCRANE host={host} path={uri}" 200
\t}
}
`;
  const p = join(SCRATCH, 'Caddyfile.live');
  writeFileSync(p, cf);
  execFileSync('docker', ['run', '-d', '--name', NAME, '-p', '127.0.0.1::8080', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe' });
  const port = execFileSync('docker', ['port', NAME, '8080/tcp']).toString().trim().split(':').pop();
  for (let i = 0; i < 40; i++) {
    try { if (!curl(port, CRANE, '/').endsWith('000 ')) break; } catch (_) { /* starting */ }
    await new Promise(r => setTimeout(r, 250));
  }
  const hub = `hub.${ISO}`;
  assert.equal(curl(port, CRANE, '/hub/x?q=1'), `\n308 https://${hub}/hub/x?q=1`);
  assert.equal(curl(port, hub, '/hub/x?q=1', ['Cookie: cc_token=P; theme=dark; __Host-cc_token=P2; __Host-cc_app=good; sid=7']),
    'APP path=/x?q=1 cookie=[theme=dark; sid=7] user=[alice]\n200 ');
  assert.equal(curl(port, hub, '/hub', ['Cookie: __Host-cc_app=good']), 'APP path=/ cookie=[] user=[alice]\n200 ');
  assert.equal(curl(port, hub, '/hubfoo/a', ['Cookie: __Host-cc_app=good']), 'APP path=/hubfoo/a cookie=[] user=[alice]\n200 ');
  assert.equal(curl(port, hub, '/x', ['Cookie: __Host-cc_app=good', 'X-AppCrane-User: mallory']), 'APP path=/x cookie=[] user=[alice]\n200 ');
  assert.equal(curl(port, hub, '/__appcrane/session?code=c'), `APPCRANE host=${hub} path=/__appcrane/session?code=c\n200 `);
  assert.equal(curl(port, hub, '/api/me'), `APPCRANE host=${hub} path=/api/me\n200 `);
  assert.equal(curl(port, hub, '/hub/deep?x=1', ['Cookie: cc_token=P; __Host-cc_token=P2']),
    `\n302 https://${CRANE}/api/identity/handoff?app=hub&env=production&return=/hub/deep?x=1`);

  // The old address: a POST to an exempt path reaches the app, with no cookie,
  // no forged identity, a sandboxed response and no Set-Cookie; a GET still
  // redirects; a POST off the exempt paths still redirects.
  const raw = execFileSync('curl', ['-s', '-i', '-X', 'POST', '-H', `Host: ${CRANE}`, '-H', 'Cookie: __Host-cc_token=ADMIN; theme=dark',
    '-H', 'X-AppCrane-User: mallory', `http://127.0.0.1:${port}/runner/hooks/ping?x=1`], { timeout: 20000 }).toString();
  assert.match(raw, /^HTTP\/1\.1 200/);
  assert.match(raw, /RUNNER POST path=\/hooks\/ping\?x=1 cookie=\[\] user=\[\]$/);
  assert.match(raw, /^Content-Security-Policy: sandbox\r?$/mi);
  assert.match(raw, /^X-Content-Type-Options: nosniff\r?$/mi);
  assert.doesNotMatch(raw, /^Set-Cookie:/mi);
  for (const h of ['Clear-Site-Data', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'NEL', 'Report-To', 'Link', 'Refresh', 'Cross-Origin-Resource-Policy']) {
    assert.doesNotMatch(raw, new RegExp(`^${h}:`, 'mi'), `${h} reached the dashboard origin`);
  }
  assert.match(raw, /^Strict-Transport-Security: max-age=31536000; includeSubDomains\r?$/mi);
  assert.doesNotMatch(raw, /max-age=0/);
  assert.match(raw, /^X-Relay-Id: kept\r?$/mi, 'an ordinary app header must still reach the client');
  assert.equal(curl(port, CRANE, '/runner/hooks/ping'), `\n308 https://runner.${ISO}/runner/hooks/ping`);
  assert.match(execFileSync('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'POST', '-H', `Host: ${CRANE}`,
    `http://127.0.0.1:${port}/runner/other`], { timeout: 20000 }).toString(), /^308$/);
});
