import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import http from 'http';
import express from 'express';
import { setupFixture, setSetting } from './caddy-app-isolation-fixtures.js';

// Caddy answers a dead upstream with its own AppCrane page (503) instead of an
// empty 502: on every site, and on the platform host when the upstream that
// failed is AppCrane itself, so its /api/_crashed page cannot render either.
// The page never carries the upstream's address.

process.env.LOG_LEVEL = 'error';
const { db, ids } = await setupFixture();
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
const { unavailablePage, HEREDOC_MARKER } = await import('../server/services/caddyErrorPage.js');
setAccessLogDirCheck(() => false);

const ISO = 'apps.example.test';
const isolation = (d) => setSetting(db, 'app_isolation_domain', d);

/** Top-level site blocks: address -> body (heredoc bodies kept verbatim). */
function sites(text) {
  const out = new Map();
  let depth = 0, name = null, buf = [], inDoc = false;
  for (const line of text.split('\n')) {
    if (inDoc) { buf.push(line); if (line.startsWith(HEREDOC_MARKER)) inDoc = false; continue; }
    if (line.includes(`<<${HEREDOC_MARKER}`)) { buf.push(line); inDoc = true; continue; }
    const o = (line.match(/\{/g) || []).length, c = (line.match(/\}/g) || []).length;
    if (depth === 0) { if (o > c) { name = line.replace(/\s*\{\s*$/, '').trim(); buf = []; depth = o - c; } continue; }
    depth += o - c;
    if (depth === 0) { out.set(name, buf.join('\n')); continue; }
    buf.push(line);
  }
  return out;
}

const pages = (text) => [...text.matchAll(new RegExp(`<<${HEREDOC_MARKER}\\n([\\s\\S]*?)\\n${HEREDOC_MARKER} 503`, 'g'))].map(m => m[1]);

function assertClean(page, label) {
  assert.doesNotMatch(page, /127\.0\.0\.1|localhost|host\.docker\.internal/, `${label}: names an upstream host`);
  assert.doesNotMatch(page, /:\d{2,5}\b/, `${label}: carries a port`);
  assert.doesNotMatch(page, /\{(err|http|env|file|system|time)\./, `${label}: carries a Caddy placeholder`);
  assert.doesNotMatch(page, /\{\$/, `${label}: carries a Caddyfile env substitution`);
  assert.doesNotMatch(page, /<(script|link|img|iframe)\b|src=|url\(/i, `${label}: loads something`);
  assert.match(page, /prefers-color-scheme: dark/, `${label}: no dark theme`);
  assert.match(page, /<meta name="appcrane-unavailable"/, `${label}: no marker the viewer can detect`);
}

test('every site block answers 502/503/504 with the page, and the page names no upstream', () => {
  for (const iso of ['', ISO]) {
    isolation(iso);
    process.env.APPCRANE_PRIVATE_API_PORT = '8443';
    try {
      const cf = generateCaddyfile();
      const blocks = sites(cf);
      const proxied = [...blocks].filter(([, b]) => /reverse_proxy /.test(b));
      assert.ok(proxied.length >= (iso ? 8 : 4), `few proxied sites: ${[...blocks.keys()].join(', ')}`);
      for (const [name, body] of proxied) {
        assert.match(body, /^ {4}handle_errors \{$/m, `${name}: no handle_errors`);
        const ps = pages(body);
        assert.equal(ps.length, 1, `${name}: expected one static page, found ${ps.length}`);
        assertClean(ps[0], name);
      }
    } finally {
      delete process.env.APPCRANE_PRIVATE_API_PORT;
    }
  }
  isolation('');
});

test('platform host: the page takes over only when the failed upstream is AppCrane, and comes first', () => {
  const body = sites(generateCaddyfile()).get('crane.example.test');
  const errors = body.slice(body.indexOf('    handle_errors {'));
  const crane = errors.indexOf('handle @cranedown');
  const app = errors.indexOf('handle @appdown');
  assert.ok(crane > 0 && app > crane, 'the AppCrane-down handler must precede the crash-page rewrite');
  assert.match(errors, /@cranedown expression `\{err\.status_code\} in \[502, 503, 504\] && \{http\.reverse_proxy\.upstream\.port\} == "5001"`/);
  assert.match(errors.slice(app), /rewrite \* \/api\/_crashed\{uri\}/, 'the AppCrane crash page still handles app failures');
  assert.match(pages(body)[0], /AppCrane is unavailable/);
  assert.match(pages(body)[0], /href="\/dashboard"/);
});

test('custom domain without AppCrane sign-in: the page names the app and links nowhere', () => {
  const body = sites(generateCaddyfile()).get('shop.example.com');
  const page = pages(body)[0];
  assert.match(page, /<title>shop is unavailable<\/title>/);
  assert.match(page, /Production/);
  assert.doesNotMatch(page, /href=|crane\.example\.test/, 'the platform host is named on a public custom domain');
});

test('app hosts: the page names the environment and links to the dashboard', () => {
  isolation(ISO);
  try {
    const blocks = sites(generateCaddyfile());
    const sand = [...blocks].find(([n]) => n.startsWith('hub-sandbox.') || n.startsWith('hub--sandbox.') || (n.includes('hub') && n.includes('sandbox')));
    assert.ok(sand, `no hub sandbox host in ${[...blocks.keys()].join(', ')}`);
    const page = pages(sand[1])[0];
    assert.match(page, /<div class="env">Sandbox<\/div>/);
    assert.match(page, /href="https:\/\/crane\.example\.test\/dashboard"/);
  } finally { isolation(''); }
});

test('an app name cannot end the heredoc, inject a directive or a placeholder', () => {
  db.prepare('UPDATE apps SET name = ? WHERE id = ?').run(`x\n${HEREDOC_MARKER} 200\n}\nevil.example.test {\n respond {file./etc/passwd} <b>`, ids.shop);
  try {
    const cf = generateCaddyfile();
    assert.equal(cf.split('\n').filter(l => l.startsWith(HEREDOC_MARKER)).every(l => l === `${HEREDOC_MARKER} 503`), true);
    assert.ok(!sites(cf).has('evil.example.test'), 'a site block was injected');
    const page = pages(sites(cf).get('shop.example.com'))[0];
    assertClean(page, 'shop');
    assert.match(page, /&#123;file\.\/etc\/passwd&#125; &lt;b&gt;/);
  } finally {
    db.prepare('UPDATE apps SET name = ? WHERE id = ?').run('shop', ids.shop);
  }
});

// ---- real Caddy ----

let dockerOk = false;
try { execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'ignore', timeout: 15000 }); dockerOk = true; } catch { /* skipped below */ }
const scratch = mkdtempSync(join(tmpdir(), 'crane-unavailable-'));
const containers = [];
after(() => {
  for (const c of containers) { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'ignore' }); } catch { /* gone */ } }
  rmSync(scratch, { recursive: true, force: true });
});

test('caddy adapt accepts every generated variant', { skip: !dockerOk && 'docker or caddy:2 unavailable', timeout: 120_000 }, () => {
  for (const [label, iso, priv] of [['off', '', ''], ['isolation', ISO, ''], ['private port', '', '8443']]) {
    isolation(iso);
    if (priv) process.env.APPCRANE_PRIVATE_API_PORT = priv;
    const file = join(scratch, `Caddyfile-${label.replace(/ /g, '-')}`);
    writeFileSync(file, generateCaddyfile().replace(/^import .*$/m, ''));
    delete process.env.APPCRANE_PRIVATE_API_PORT;
    execFileSync('docker', ['run', '--rm', '-v', `${file}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
      'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], { stdio: 'pipe', timeout: 60000 });
  }
  isolation('');
});

function get(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path, headers: { Host: 'crane.example.test', Accept: 'text/html' } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
  });
}

test('live: app down -> AppCrane crash page; AppCrane down -> the static page, with no upstream address', { skip: !dockerOk && 'docker or caddy:2 unavailable', timeout: 180_000 }, async (t) => {
  const crane = express();
  crane.get('/api/identity/verify', (_req, res) => res.status(200).end());
  crane.all('/api/_crashed/*splat', (_req, res) => res.status(503).type('text').send('appcrane crash page'));
  crane.get('/dashboard', (_req, res) => res.type('text').send('dashboard'));
  const srv = await new Promise(r => { const s = crane.listen(0, '0.0.0.0', () => r(s)); });
  const cranePort = srv.address().port;

  const live = generateCaddyfile()
    .replace(/^import .*$/m, '')
    .replace(/^(\S.*) \{$/gm, (_m, addr) => `http://${addr} {`)
    .replace(/127\.0\.0\.1:5001/g, `host.docker.internal:${cranePort}`)
    .replace(/== "5001"/g, `== "${cranePort}"`)
    .replace(/127\.0\.0\.1:(\d+)/g, 'host.docker.internal:$1');
  const file = join(scratch, 'Caddyfile-live');
  writeFileSync(file, live);
  const name = `appcrane-unavailable-caddy-${process.pid}`;
  containers.push(name);
  const caddyPort = 21000 + (process.pid % 20000);
  execFileSync('docker', ['run', '-d', '--rm', '--name', name, '--add-host', 'host.docker.internal:host-gateway',
    '-p', `127.0.0.1:${caddyPort}:80`, '-v', `${file}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe', timeout: 90000 });

  let up = null;
  for (let i = 0; i < 80 && !up; i++) {
    try { const r = await get(caddyPort, '/dashboard'); if (r.status === 200) up = r; } catch { /* starting */ }
    if (!up) await new Promise(r => setTimeout(r, 250));
  }
  if (!up) { srv.close(); t.skip('caddy container cannot reach the host (host-gateway networking unavailable)'); return; }

  const appDown = await get(caddyPort, '/hub/');
  assert.equal(appDown.status, 503);
  assert.equal(appDown.body, 'appcrane crash page', 'with AppCrane up, a dead app still gets the AppCrane crash page');

  await new Promise(r => { srv.closeAllConnections?.(); srv.close(r); });
  for (const path of ['/hub/', '/dashboard', '/hub-sandbox/x?y=1']) {
    const r = await get(caddyPort, path);
    assert.equal(r.status, 503, `${path}: ${r.status}`);
    assert.match(r.headers['content-type'] || '', /text\/html/);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.match(r.body, /AppCrane is unavailable/, `${path}: ${r.body.slice(0, 200)}`);
    assertClean(r.body, path);
    assert.ok(!r.body.includes(String(cranePort)), `${path}: AppCrane's port leaked`);
  }
});

test('unavailablePage escapes braces and markup in every value', () => {
  const p = unavailablePage({ name: '{env.HOME}<i>', env: 'sandbox', link: '/dashboard?a="b"' });
  assert.match(p, /&#123;env\.HOME&#125;&lt;i&gt; is unavailable/);
  assert.match(p, /href="\/dashboard\?a=&quot;b&quot;"/);
});
