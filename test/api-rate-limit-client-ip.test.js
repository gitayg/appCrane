// Rate limits key the real client behind Caddy, and only behind a trusted hop.
//
// Before: trust proxy was unset, so every request Caddy forwarded (including
// forward_auth's /api/identity/verify) had req.ip 127.0.0.1 and shared ONE
// 600/min bucket. One looping browser 429'd sign-in for every user.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { networkInterfaces, tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { resolveTrustProxy, configureTrustProxy } from '../server/utils/clientIp.js';
import { createApiRateLimit, rateLimitKey } from '../server/middleware/apiRateLimit.js';

const LIMITS = { authed: 50, ip: 5, verify: 12, windowMs: 60_000 };
const A = '203.0.113.10';
const B = '203.0.113.20';

const servers = [];
after(() => { for (const s of servers) s.close(); });

async function startApp({ trust, host = '127.0.0.1' } = {}) {
  const app = express();
  if (trust === undefined) configureTrustProxy(app, undefined);
  else app.set('trust proxy', trust);
  app.use('/api', createApiRateLimit(LIMITS));
  app.get('/api/whoami', (req, res) => res.json({ ip: req.ip }));
  app.get('/api/identity/verify', (req, res) => res.json({ ip: req.ip }));
  const srv = await new Promise(r => { const s = app.listen(0, host, () => r(s)); });
  servers.push(srv);
  return `http://${host}:${srv.address().port}`;
}

async function hit(base, path, xff) {
  const headers = xff ? { 'X-Forwarded-For': xff } : {};
  const r = await fetch(base + path, { headers });
  const body = await r.text();
  return { status: r.status, body: r.status === 200 ? JSON.parse(body) : body };
}

async function flood(base, path, xff, n) {
  const statuses = [];
  for (let i = 0; i < n; i++) statuses.push((await hit(base, path, xff)).status);
  return statuses;
}

test('resolveTrustProxy: safe default, refuses settings that trust any peer', () => {
  const warned = [];
  const warn = (m) => warned.push(m);
  assert.equal(resolveTrustProxy(undefined, warn), 'loopback');
  assert.equal(resolveTrustProxy('', warn), 'loopback');
  assert.equal(resolveTrustProxy('true', warn), 'loopback');
  assert.equal(resolveTrustProxy('*', warn), 'loopback');
  assert.equal(resolveTrustProxy('2', warn), 'loopback');
  assert.equal(resolveTrustProxy('loopback, true', warn), 'loopback');
  assert.equal(warned.length, 4);
  assert.equal(resolveTrustProxy('false', warn), false);
  assert.deepEqual(resolveTrustProxy('loopback, 10.0.0.5', warn), ['loopback', '10.0.0.5']);
});

test('server/index.js configures trust proxy before mounting the API rate limiter', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'index.js'), 'utf8');
  const trustAt = src.indexOf('configureTrustProxy(app, process.env.TRUST_PROXY');
  const limitAt = src.indexOf("app.use('/api', apiRateLimit)");
  assert.ok(trustAt > 0, 'configureTrustProxy(app, process.env.TRUST_PROXY, ...) call missing');
  assert.ok(limitAt > trustAt, 'trust proxy must be set before the rate limiter is mounted');
});

test('BEFORE (no trust proxy): one client behind the proxy locks out another', async () => {
  const base = await startApp({ trust: false });
  const a = await flood(base, '/api/whoami', A, LIMITS.ip + 1);
  assert.equal(a.at(-1), 429);
  assert.equal((await hit(base, '/api/whoami', B)).status, 429, 'documents the old shared 127.0.0.1 bucket');
});

test('via loopback proxy: req.ip is the forwarded client and each client has its own bucket', async () => {
  const base = await startApp();
  assert.equal((await hit(base, '/api/whoami', A)).body.ip, A);
  const a = await flood(base, '/api/whoami', A, LIMITS.ip + 2);
  assert.equal(a.at(-1), 429, 'client A floods its own bucket');
  const b = await hit(base, '/api/whoami', B);
  assert.equal(b.status, 200, 'client B is not locked out by A');
  assert.equal(b.body.ip, B);
});

test('via loopback proxy: an appended forged entry cannot select another bucket (right-most hop wins)', async () => {
  const base = await startApp();
  assert.equal((await hit(base, '/api/whoami', `${B}, ${A}`)).body.ip, A);
  await flood(base, '/api/whoami', `${B}, ${A}`, LIMITS.ip + 1);
  assert.equal((await hit(base, '/api/whoami', A)).status, 429, 'the forged left entry counted against A');
  assert.equal((await hit(base, '/api/whoami', B)).status, 200, 'B was untouched');
});

test('forward_auth verify has its own per-client bucket: a verify flood does not 429 the API, nor vice versa', async () => {
  const base = await startApp();
  const v = await flood(base, '/api/identity/verify', A, LIMITS.verify + 1);
  assert.equal(v.filter(s => s === 200).length, LIMITS.verify, 'verify limit is its own, higher than the API bucket');
  assert.equal(v.at(-1), 429);
  assert.equal((await hit(base, '/api/whoami', A)).status, 200, 'same client can still use the API');
  assert.equal((await hit(base, '/api/identity/verify', B)).status, 200, 'another client can still pass forward_auth');
  const base2 = await startApp();
  await flood(base2, '/api/whoami', A, LIMITS.ip + 1);
  assert.equal((await hit(base2, '/api/identity/verify', A)).status, 200, 'API flood does not break forward_auth');
});

test('credentials still key by credential, not address', () => {
  const k1 = rateLimitKey({ headers: { authorization: 'Bearer abc' }, path: '/identity/verify', ip: A });
  const k2 = rateLimitKey({ headers: { 'x-api-key': 'abc' }, path: '/x', ip: A });
  assert.equal(k1.kind, 'authed');
  assert.match(k1.key, /^t:[0-9a-f]{32}$/);
  assert.match(k2.key, /^k:[0-9a-f]{32}$/);
});

const lanAddr = Object.values(networkInterfaces()).flat()
  .find(i => i && i.family === 'IPv4' && !i.internal)?.address;

test('direct non-loopback client: forged X-Forwarded-For is ignored and keyed by socket address',
  { skip: lanAddr ? false : 'no non-loopback IPv4 interface to bind' }, async () => {
    const base = await startApp({ host: lanAddr });
    const r = await hit(base, '/api/whoami', A);
    assert.equal(r.body.ip, lanAddr, 'req.ip must be the socket address, not the forged XFF');
    const statuses = [];
    for (let i = 0; i < LIMITS.ip + 1; i++) statuses.push((await hit(base, '/api/whoami', `198.51.100.${i + 1}`)).status);
    assert.equal(statuses.at(-1), 429, 'rotating forged XFF values must not buy fresh buckets');
  });

// ---------------------------------------------------------------------------
// Real Caddy: a client-forged XFF sent THROUGH Caddy cannot select a victim's bucket.
// ---------------------------------------------------------------------------
const DOCKER = (() => {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 });
    execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch { return false; }
})();

test('through caddy:2 reverse_proxy: a forged client XFF cannot drain another client\'s bucket',
  { skip: DOCKER ? false : 'docker or caddy:2 image unavailable' }, async (t) => {
    const base = await startApp();
    const port = new URL(base).port;
    const dir = mkdtempSync(join(tmpdir(), 'crane-ratelimit-caddy-'));
    writeFileSync(join(dir, 'Caddyfile'),
      `{\n    auto_https off\n    admin off\n}\n:8080 {\n    reverse_proxy host.docker.internal:${port}\n}\n`);
    const name = `crane-ratelimit-${randomBytes(4).toString('hex')}`;
    execFileSync('docker', ['run', '-d', '--rm', '--name', name, '--add-host', 'host.docker.internal:host-gateway',
      '-p', '127.0.0.1::8080', '-v', `${join(dir, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe' });
    try {
      const mapped = execFileSync('docker', ['port', name, '8080/tcp']).toString().trim().split('\n')[0];
      const caddy = `http://127.0.0.1:${mapped.split(':').pop()}`;
      let first;
      for (let i = 0; i < 80 && !first; i++) {
        try { first = await hit(caddy, '/api/whoami', B); } catch { await new Promise(r => setTimeout(r, 250)); }
      }
      assert.ok(first, 'caddy never answered');
      if (first.status === 502) { t.skip('caddy cannot reach a 127.0.0.1-bound upstream on this docker host'); return; }
      assert.equal(first.status, 200);
      assert.notEqual(first.body.ip, B, 'Caddy must not pass the client-forged XFF through');
      for (let i = 0; i < LIMITS.ip + 1; i++) await hit(caddy, '/api/whoami', B);
      assert.equal((await hit(caddy, '/api/whoami', B)).status, 429, 'the forger is limited in its own bucket');
      assert.equal((await hit(base, '/api/whoami', B)).status, 200,
        'the real client B (as Caddy would forward it) was not drained by the forged header');
    } finally {
      execFileSync('docker', ['rm', '-f', name], { stdio: 'pipe' });
      rmSync(dir, { recursive: true, force: true });
    }
  });
