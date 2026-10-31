import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { brotliCompressSync, gzipSync } from 'zlib';

// CVE-2026-111497 at the edge: the generated Caddyfile refuses request bodies
// sent with Content-Encoding: br on every hosted-app site, ahead of every route,
// unless a platform admin turned the setting off.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-brotli-caddy-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { seedApps } = await import('./fixtures/edge-hardening.seed.js');
seedApps(db);
const { generateCaddyfile, BROTLI_GUARD_KEY, brotliGuardEnabled } = await import('../server/services/caddy.js');

const setGuard = (v) => {
  if (v === null) db.prepare('DELETE FROM settings WHERE key = ?').run(BROTLI_GUARD_KEY);
  else db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(BROTLI_GUARD_KEY, v);
};

/** Top-level site blocks: name -> body. */
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

test('default (no setting row): every proxying site refuses br bodies before its first route', () => {
  setGuard(null);
  assert.equal(brotliGuardEnabled(db), true);
  const s = sites(generateCaddyfile());
  for (const host of ['crane.example.com', 'custom.test.local']) {
    const body = s.get(host);
    assert.ok(body, `${host} site missing`);
    assert.match(body, /@brotli_body header_regexp Content-Encoding "\(\?i\)\(\^\|,\)\\s\*br\\s\*\(,\|\$\)"/, `${host}: no br matcher`);
    assert.match(body, /handle @brotli_body \{\n\s+header Accept-Encoding "gzip, deflate"\n\s+respond "[^"]*Brotli[^"]*" 415\n\s+\}/, `${host}: no 415 handle`);
    const first = body.indexOf('handle @brotli_body');
    const firstProxy = body.search(/^\s*(handle \/|handle \{|reverse_proxy )/m);
    assert.ok(first >= 0 && first < firstProxy, `${host}: the refusal is not ahead of every route`);
  }
  assert.doesNotMatch(s.get('old.test.local'), /brotli_body/, 'a redirect-only alias site proxies no body and needs no refusal');
});

test('turned off by a platform admin: no refusal anywhere', () => {
  setGuard('off');
  assert.equal(brotliGuardEnabled(db), false);
  assert.doesNotMatch(generateCaddyfile(), /brotli_body|Content-Encoding/);
  setGuard('on');
  assert.match(generateCaddyfile(), /handle @brotli_body/);
  setGuard(null);
});

// ---- real Caddy ---------------------------------------------------------------

const DOCKER = (() => {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch { return false; }
})();
const noDocker = DOCKER ? false : 'docker unavailable';
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-brotli-caddy-run-'));
const NAME = `crane-brotli-caddy-${process.pid}`;
after(() => {
  try { execFileSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' }); } catch (_) {}
  try { rmSync(SCRATCH, { recursive: true, force: true }); } catch (_) {}
});

/** Routes of the adapted server, flattened to the first-level matcher of each. */
function adaptRoutes(cf) {
  const p = join(SCRATCH, 'Caddyfile');
  writeFileSync(p, cf);
  const json = execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], { stdio: 'pipe', timeout: 120000 }).toString();
  return JSON.parse(json).apps.http.servers.srv0.routes;
}

test('adapted JSON: on each site the first terminal route is the br refusal', { skip: noDocker }, () => {
  setGuard(null);
  const routes = adaptRoutes(generateCaddyfile());
  for (const host of ['crane.example.com', 'custom.test.local']) {
    const site = routes.find((r) => r.match?.some((m) => m.host?.includes(host)));
    assert.ok(site, `${host}: no site route in the adapted config`);
    const inner = site.handle.find((h) => h.handler === 'subroute').routes;
    const idx = inner.findIndex((r) => JSON.stringify(r.match || []).includes('header_regexp'));
    assert.notEqual(idx, -1, `${host}: the br matcher vanished on adapt`);
    const firstTerminal = inner.findIndex((r) => JSON.stringify(r.handle || []).match(/"handler":"(subroute|reverse_proxy|static_response)"/) && r.match);
    assert.equal(idx, firstTerminal, `${host}: a route runs before the br refusal (index ${firstTerminal} vs ${idx})`);
    assert.match(JSON.stringify(inner[idx]), /"status_code":415/);
  }
});

function curl(port, host, path, headers, bodyFile) {
  const args = ['-s', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'POST', '-H', `Host: ${host}`, '--data-binary', `@${bodyFile}`];
  for (const h of headers) args.push('-H', h);
  return execFileSync('curl', [...args, `http://127.0.0.1:${port}${path}`], { timeout: 20000 }).toString().trim();
}

test('live Caddy: br bodies get 415 on app, bypass, headless, platform and custom-domain routes; gzip does not', { skip: noDocker }, async () => {
  setGuard(null);
  // Same file, served over plain HTTP on :8080 so it can run in a throwaway container.
  // Test-only options go inside the generated global block (it holds the
  // redacting error logger); a second global block is a parse error.
  const gen = generateCaddyfile();
  assert.ok(gen.includes('\n\n{\n    log appcrane_errors {'), 'no global block to extend');
  const cf = gen.replace('\n\n{\n', '\n\n{\n\tauto_https off\n\tadmin off\n')
    .replace('import /etc/caddy/sites/*.caddy\n', '')
    .replace(/^(crane\.example\.com|custom\.test\.local|old\.test\.local) \{$/gm, 'http://$1:8080 {');
  const p = join(SCRATCH, 'Caddyfile.live');
  writeFileSync(p, cf);
  execFileSync('docker', ['run', '-d', '--name', NAME, '-p', '127.0.0.1::8080', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe' });
  const port = execFileSync('docker', ['port', NAME, '8080/tcp']).toString().trim().split(':').pop();
  const br = join(SCRATCH, 'body.br'), gz = join(SCRATCH, 'body.gz');
  writeFileSync(br, brotliCompressSync('{"a":1}'));
  writeFileSync(gz, gzipSync('{"a":1}'));
  for (let i = 0; i < 40; i++) {
    try { if (curl(port, 'crane.example.com', '/', [], gz) !== '000') break; } catch (_) { /* starting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const cases = [
    ['crane.example.com', '/plain/api/x'], ['crane.example.com', '/plain-sandbox/x'], ['crane.example.com', '/headless/x'],
    ['crane.example.com', '/bypasser/ws/runner'], ['crane.example.com', '/api/auth/login'], ['crane.example.com', '/git/a.git/git-upload-pack'],
    ['crane.example.com', '/a2a'], ['custom.test.local', '/upload'],
  ];
  for (const [host, path] of cases) {
    for (const ce of ['br', 'gzip, BR']) {
      assert.equal(curl(port, host, path, ['Content-Type: application/json', `Content-Encoding: ${ce}`], br), '415', `${host}${path} [${ce}]`);
    }
    assert.notEqual(curl(port, host, path, ['Content-Type: application/json', 'Content-Encoding: gzip'], gz), '415', `${host}${path} gzip was refused`);
  }
});

test('settings route: platform admin reads and flips the switch; others are refused; bad input is 400', async () => {
  const express = (await import('express')).default;
  const settingsRoutes = (await import('../server/routes/settings.js')).default;
  const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
  const mk = (role, n) => {
    const key = generateApiKey('dhk_user');
    db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)').run(`br${n}`, `br${n}@t.test`, role, hashApiKey(key), 'human');
    return key;
  };
  const ADMIN = mk('platform_admin', 1), USER = mk('user', 2);
  const api = express();
  api.use(express.json());
  api.use('/api/settings', settingsRoutes);
  const srv = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  const B = `http://127.0.0.1:${srv.address().port}/api/settings/edge/brotli`;
  const call = async (method, key, body) => {
    const r = await fetch(B, { method, headers: { 'X-API-Key': key, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  try {
    setGuard(null);
    assert.deepEqual((await call('GET', ADMIN)).body, { enabled: true });
    assert.equal((await call('GET', USER)).status, 403);
    assert.equal((await call('PUT', USER, { enabled: false })).status, 403);
    assert.equal(brotliGuardEnabled(db), true, 'a non-admin changed the switch');
    assert.equal((await call('PUT', ADMIN, { enabled: 'no' })).status, 400);
    assert.equal((await call('PUT', ADMIN, { enabled: false })).status, 200);
    assert.equal(brotliGuardEnabled(db), false);
    assert.doesNotMatch(generateCaddyfile(), /brotli_body/);
    assert.equal((await call('PUT', ADMIN, { enabled: true })).status, 200);
    assert.match(generateCaddyfile(), /handle @brotli_body/);
  } finally {
    srv.close();
    setGuard(null);
  }
});
