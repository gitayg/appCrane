import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// OIDC fetches (services/idpFetch.js): the configured discovery URL's origin
// may be a private or loopback IdP, but a token_endpoint or jwks_uri the
// discovery document points somewhere else must be https on a public address;
// metadata addresses are refused everywhere; redirects are not followed; and
// every request has a wall-clock deadline.

const dataDir = mkdtempSync(join(tmpdir(), 'crane-idp-fetch-'));
process.env.DATA_DIR = dataDir;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { idpFetch } = await import('../server/services/idpFetch.js');
const { getDiscovery } = await import('../server/routes/oidc.js');
const { findSigningKey, clearJwksCache } = await import('../server/services/idpJwks.js');

let idp, other, idpBase, otherBase;
let jwksHits = 0;
const sockets = new Set();

function serve(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.on('connection', (c) => { sockets.add(c); c.on('close', () => sockets.delete(c)); });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

before(async () => {
  other = await serve((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ keys: [{ kid: 'k1' }], token: 'x' })); });
  otherBase = `http://127.0.0.1:${other.address().port}`;
  idp = await serve((req, res) => {
    if (req.url === '/redirect/.well-known/openid-configuration') { res.writeHead(302, { Location: `${otherBase}/.well-known/openid-configuration` }); return res.end(); }
    if (req.url === '/hang') return; // never answers
    if (req.url === '/slow-jwks') { jwksHits += 1; return setTimeout(() => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ keys: [{ kid: 'real' }] })); }, 50); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ issuer: idpBase, jwks_uri: `${idpBase}/jwks`, token_endpoint: `${idpBase}/token`, keys: [{ kid: 'k1' }] }));
  });
  idpBase = `http://127.0.0.1:${idp.address().port}`;
});

after(() => {
  for (const s of sockets) s.destroy();
  idp?.close(); other?.close();
  rmSync(dataDir, { recursive: true, force: true });
});

test('the configured IdP origin works on loopback over http', async () => {
  const r = await idpFetch(`${idpBase}/jwks`, { trusted: idpBase });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).keys[0].kid, 'k1');
  const post = await idpFetch(`${idpBase}/token`, { trusted: `${idpBase}/.well-known/openid-configuration`, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'a=1' });
  assert.equal(post.ok, true);
});

test('a URL on another origin must be https and public', async () => {
  await assert.rejects(idpFetch(`${otherBase}/jwks`, { trusted: idpBase }), /must be https/);
  await assert.rejects(idpFetch('https://127.0.0.1:1/jwks', { trusted: idpBase }), { code: 'EBLOCKEDADDRESS' });
  await assert.rejects(idpFetch('https://10.1.2.3/token', { trusted: idpBase, method: 'POST', body: 'x' }), { code: 'EBLOCKEDADDRESS' });
});

test('metadata addresses are refused even as the configured IdP', async () => {
  await assert.rejects(idpFetch('http://169.254.169.254/latest/meta-data', { trusted: 'http://169.254.169.254' }), { code: 'EBLOCKEDADDRESS' });
});

test('a redirect is not followed', async () => {
  await assert.rejects(idpFetch(`${idpBase}/redirect/.well-known/openid-configuration`, { trusted: `${idpBase}/redirect` }), /redirects are not followed/);
});

test('a request that never answers is cut off at the deadline', async () => {
  const t0 = Date.now();
  const outcome = await Promise.race([
    idpFetch(`${idpBase}/hang`, { trusted: idpBase, timeoutMs: 300 }).then(() => 'answered', (e) => e.message),
    new Promise((r) => { const t = setTimeout(() => r('still waiting after 3s'), 3000); t.unref(); }),
  ]);
  assert.match(outcome, /did not answer/);
  assert.ok(Date.now() - t0 < 3000);
});

test('discovery does not follow a redirect to another host', async () => {
  await assert.rejects(getDiscovery(`${idpBase}/redirect`), /redirect/);
  const doc = await getDiscovery(idpBase);
  assert.equal(doc.issuer, idpBase);
});

test('ID-JAG JWKS: a jwks_uri off the IdP origin is refused', async () => {
  clearJwksCache();
  await assert.rejects(findSigningKey(`${otherBase}/jwks`, 'k1', Date.now(), idpBase), /must be https/);
  clearJwksCache();
  assert.equal((await findSigningKey(`${idpBase}/jwks`, 'k1', Date.now(), idpBase)).kid, 'k1');
});

test('concurrent unknown kids share one forced JWKS refresh', async () => {
  clearJwksCache();
  const uri = `${idpBase}/slow-jwks`;
  await findSigningKey(uri, 'real', Date.now(), idpBase);
  assert.equal(jwksHits, 1);
  const keys = await Promise.all(Array.from({ length: 50 }, (_, i) => findSigningKey(uri, `made-up-${i}`, Date.now(), idpBase)));
  assert.ok(keys.every((k) => k === null));
  assert.equal(jwksHits, 2, `50 concurrent made-up kids caused ${jwksHits - 1} JWKS fetches`);
  clearJwksCache();
  await Promise.all(Array.from({ length: 20 }, () => findSigningKey(uri, 'real', Date.now(), idpBase)));
  assert.equal(jwksHits, 3, 'a cold cache fetched once per caller');
});
