// The credential bucket's key is an unverified header value, so a made-up Bearer
// per request used to skip the per-address limit and add one Map entry per
// request. Measured before the fix: 700 random Bearers from one address gave 700
// 200s and 701 buckets; 200k more added 46 MB of heap.
//
// A credential only gets a bucket of its own once a request with it authenticated.
// Counting only 401s would not do: public routes ignore the header and never send
// one, so a made-up credential on them would stay free (first test). Keys that
// authenticated must not share anything with their address (office NAT, containers
// behind one gateway).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-fix-auth-rl-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { createApiRateLimit, DEFAULT_LIMITS, rateLimitKey } = await import('../server/middleware/apiRateLimit.js');
const { configureTrustProxy } = await import('../server/utils/clientIp.js');
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { requireAuth } = await import('../server/middleware/auth.js');

const LIMITS = { authed: 50, ip: 5, verify: 80, windowMs: 60_000 };
const A = '203.0.113.10';
const B = '203.0.113.20';
const servers = [];
after(() => { for (const s of servers) s.close(); });

const randomBearer = () => ({ authorization: `Bearer ${randomBytes(16).toString('hex')}` });
const bearer = (k) => ({ authorization: `Bearer ${k}` });

// One request through the limiter. `auth` says how the route ended it: 'ok' is what
// requireAuth leaves (req.user), 'bad' a 401, 'public' a route ignoring the header.
function fire(lim, { headers = {}, ip = A, path = '/x', auth = 'public', cookie = false, hold = false } = {}) {
  let code = 200;
  let onClose = null;
  const req = { headers, path, ip, socket: { remoteAddress: ip } };
  const res = {
    statusCode: 200,
    status(c) { code = c; this.statusCode = c; return this; },
    json() { return this; },
    once(ev, fn) { if (ev === 'close') onClose = fn; },
  };
  let passed = false;
  lim(req, res, () => { passed = true; });
  const finish = () => {
    if (passed && auth === 'ok') { req.user = { id: 1 }; if (cookie) req.authed_by_cookie = true; }
    if (passed && auth === 'bad') res.statusCode = 401;
    onClose?.();
  };
  if (hold) return { code, finish };
  finish();
  return code;
}
const count = (codes) => codes.reduce((o, c) => ({ ...o, [c]: (o[c] || 0) + 1 }), {});
const fireMany = (lim, n, opts) => count(Array.from({ length: n }, () => fire(lim, typeof opts === 'function' ? opts() : opts)));

test('the attack, on a route that ignores credentials and never sends 401: stops at the address ceiling', () => {
  const lim = createApiRateLimit(LIMITS);
  assert.deepEqual(fireMany(lim, LIMITS.authed + 30, () => ({ headers: randomBearer(), auth: 'public' })), { 200: LIMITS.authed, 429: 30 });
  const lim2 = createApiRateLimit(LIMITS);
  assert.deepEqual(fireMany(lim2, LIMITS.authed + 30, () => ({ headers: { 'x-api-key': randomBytes(16).toString('hex') } })), { 200: LIMITS.authed, 429: 30 });
});

test('the attack, on a route that does send 401: same ceiling', () => {
  const lim = createApiRateLimit(LIMITS);
  assert.deepEqual(fireMany(lim, LIMITS.authed + 30, () => ({ headers: randomBearer(), auth: 'bad' })), { 200: LIMITS.authed, 429: 30 });
});

test('made-up credentials create no bucket of their own at all', () => {
  const lim = createApiRateLimit(LIMITS);
  fireMany(lim, 5000, () => ({ headers: randomBearer() }));
  assert.equal(lim.buckets.size, 1, 'only the address ceiling');
  assert.equal(lim.verified.size, 0, 'nothing unauthenticated is remembered');
});

test('the default ceiling is the authed limit, and the exact measured attack is bounded', () => {
  const lim = createApiRateLimit();
  const r = fireMany(lim, DEFAULT_LIMITS.authed + 100, () => ({ headers: randomBearer() }));
  assert.deepEqual(r, { 200: DEFAULT_LIMITS.authed, 429: 100 });
  assert.equal(lim.buckets.size, 1);
});

test('the ceiling is per address: another address and credential-less traffic are not affected', () => {
  const lim = createApiRateLimit(LIMITS);
  fireMany(lim, LIMITS.authed + 1, () => ({ headers: randomBearer() }));
  assert.equal(fire(lim, { headers: randomBearer(), ip: B }), 200);
  assert.equal(fire(lim, {}), 200, 'the anonymous bucket is separate');
});

test('valid keys behind one address each keep their own limit, far past what they would share', () => {
  const lim = createApiRateLimit(LIMITS);
  const keys = Array.from({ length: 6 }, (_, i) => bearer(`real-key-${i}`));
  for (const headers of keys) {
    assert.deepEqual(fireMany(lim, LIMITS.authed, { headers, auth: 'ok' }), { 200: LIMITS.authed });
    assert.equal(fire(lim, { headers, auth: 'ok' }), 429, 'a key still has its own limit');
  }
});

test('a valid key that signed in is untouched by a flood from its own address', () => {
  const lim = createApiRateLimit(LIMITS);
  const key = { headers: bearer('real-key'), auth: 'ok' };
  assert.equal(fire(lim, key), 200);
  assert.equal(fireMany(lim, LIMITS.authed + 5, () => ({ headers: randomBearer() }))[429], 5, 'the flood is over the ceiling');
  assert.deepEqual(fireMany(lim, 20, key), { 200: 20 });
});

test('a key not seen yet is refused while its address is over the ceiling, and gets in when the window ends', (t) => {
  const lim = createApiRateLimit(LIMITS);
  fireMany(lim, LIMITS.authed + 1, () => ({ headers: randomBearer() }));
  assert.equal(fire(lim, { headers: bearer('new-key'), auth: 'ok' }), 429);
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  Date.now = () => realNow() + LIMITS.windowMs + 1;
  assert.equal(fire(lim, { headers: bearer('new-key'), auth: 'ok' }), 200);
});

test('a dashboard fan-out before the first response proves the key costs the address nothing', () => {
  const lim = createApiRateLimit(LIMITS);
  const inFlight = Array.from({ length: 40 }, () => fire(lim, { headers: bearer('spa-token'), auth: 'ok', hold: true }));
  assert.ok(inFlight.every((r) => r.code === 200));
  inFlight.forEach((r) => r.finish());
  assert.deepEqual(fireMany(lim, LIMITS.authed, () => ({ headers: randomBearer() })), { 200: LIMITS.authed }, 'the fan-out was not refunded');
});

test('a key that starts failing loses its standing', () => {
  const lim = createApiRateLimit(LIMITS);
  const headers = bearer('revoked-soon');
  fire(lim, { headers, auth: 'ok' });
  fire(lim, { headers, auth: 'bad' });
  assert.equal(lim.verified.size, 0);
  assert.deepEqual(fireMany(lim, LIMITS.authed + 2, { headers, auth: 'bad' }), { 200: LIMITS.authed, 429: 2 });
});

test('a valid session cookie does not vouch for a made-up Bearer sent beside it', () => {
  const lim = createApiRateLimit(LIMITS);
  const r = fireMany(lim, LIMITS.authed + 5, () => ({ headers: randomBearer(), auth: 'ok', cookie: true }));
  assert.deepEqual(r, { 200: LIMITS.authed, 429: 5 });
  assert.equal(lim.verified.size, 0);
});

test('the limiter keys the credential requireAuth reads: X-API-Key over Bearer', () => {
  const k = rateLimitKey({ headers: { 'x-api-key': 'abc', authorization: 'Bearer other' }, path: '/x', ip: A });
  assert.match(k.key, /^k:/);
  const lim = createApiRateLimit(LIMITS);
  // A real key in X-API-Key authenticates the request; a rotating Bearer beside it must not earn buckets.
  const r = fireMany(lim, LIMITS.authed + 3, () => ({ headers: { 'x-api-key': 'real', ...randomBearer() }, auth: 'ok' }));
  assert.deepEqual(r, { 200: LIMITS.authed, 429: 3 });
  assert.equal(lim.verified.size, 1);
});

test('API_RATE_LIMIT_IP_AUTHED sets the ceiling when the limits object does not', (t) => {
  process.env.API_RATE_LIMIT_IP_AUTHED = '7';
  t.after(() => { delete process.env.API_RATE_LIMIT_IP_AUTHED; });
  const lim = createApiRateLimit(LIMITS);
  assert.deepEqual(fireMany(lim, 10, () => ({ headers: randomBearer() })), { 200: 7, 429: 3 });
  process.env.API_RATE_LIMIT_IP_AUTHED = 'not-a-number';
  const lim2 = createApiRateLimit(LIMITS);
  assert.equal(fireMany(lim2, LIMITS.authed + 1, () => ({ headers: randomBearer() }))[429], 1, 'garbage falls back to the authed limit');
});

test('a credentialed /identity/verify has its own ceiling, so a busy app page cannot starve the API', () => {
  const lim = createApiRateLimit(LIMITS);
  const r = fireMany(lim, LIMITS.verify + 5, () => ({ headers: randomBearer(), path: '/identity/verify' }));
  assert.deepEqual(r, { 200: LIMITS.verify, 429: 5 }, 'made-up credentials on verify are capped at the verify limit');
  assert.equal(fire(lim, { headers: randomBearer() }), 200, 'the API ceiling was not consumed by verify traffic');
});

test('the bucket map cannot pass maxBuckets however many addresses take part, and the oldest entries go first', () => {
  const lim = createApiRateLimit({ ...LIMITS, maxBuckets: 100 });
  for (let i = 0; i < 1000; i++) fire(lim, { headers: randomBearer(), ip: `198.51.${i >> 8}.${i & 255}` });
  assert.ok(lim.buckets.size <= 100, `map grew to ${lim.buckets.size}`);
  assert.ok(![...lim.buckets.keys()].includes('ipauth:198.51.0.0'), 'the oldest entry should have been evicted');
  assert.ok([...lim.buckets.keys()].includes('ipauth:198.51.3.231'), 'the newest entry should still be there');
});

test('the remembered valid credentials are bounded too, oldest first', () => {
  const lim = createApiRateLimit({ ...LIMITS, maxVerified: 50 });
  for (let i = 0; i < 500; i++) fire(lim, { headers: bearer(`key-${i}`), auth: 'ok', ip: `198.51.${i >> 8}.${i & 255}` });
  assert.equal(lim.verified.size, 50);
});

test('a valid credential is remembered for verifiedTtlMs after its last proof, then has to prove itself again', (t) => {
  const lim = createApiRateLimit({ ...LIMITS, verifiedTtlMs: 10 * 60_000 });
  fire(lim, { headers: bearer('k'), auth: 'ok' });
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  Date.now = () => realNow() + 10 * 60_000 + 1;
  fireMany(lim, LIMITS.authed + 1, () => ({ headers: randomBearer() }));
  assert.equal(fire(lim, { headers: bearer('k'), auth: 'ok' }), 429, 'the memory outlived its TTL');
});

test('expired buckets are dropped as new ones arrive, without waiting for the sweeper', (t) => {
  const lim = createApiRateLimit({ ...LIMITS, windowMs: 1000 });
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  for (let i = 0; i < 40; i++) fire(lim, { headers: bearer(`k${i}`), auth: 'ok' });
  assert.equal(lim.verified.size, 40);
  for (let i = 0; i < 40; i++) fire(lim, { headers: bearer(`k${i}`), auth: 'ok' });
  assert.equal(lim.buckets.size, 41);
  Date.now = () => realNow() + 5000;
  fire(lim, { headers: bearer('k0'), auth: 'ok' });
  assert.equal(lim.buckets.size, 1, 'only the live credential bucket remains');
});

// ---- over real HTTP, with the real requireAuth --------------------------------

let db;
before(() => { initDb(); db = getDb(); });
function mkKey(n) {
  const key = generateApiKey('dhk_user');
  db.prepare('INSERT INTO users (name, email, role, active, api_key_hash) VALUES (?, ?, ?, ?, ?)').run(`u${n}`, `u${n}@t.test`, 'user', 1, hashApiKey(key));
  return key;
}
async function startApp(host, limits = LIMITS) {
  const app = express();
  configureTrustProxy(app, undefined);
  app.use('/api', createApiRateLimit(limits));
  app.get('/api/whoami', (req, res) => res.json({ ip: req.ip }));
  app.get('/api/private', requireAuth, (req, res) => res.json({ id: req.user.id }));
  app.use((err, req, res, next) => res.status(err.status || 500).json({ error: err.message }));
  const srv = await new Promise(r => { const s = app.listen(0, host, () => r(s)); });
  servers.push(srv);
  return `http://${host}:${srv.address().port}`;
}
async function get(url, headers) { const r = await fetch(url, { headers }); await r.arrayBuffer(); return r.status; }

test('real requireAuth: valid keys from one address outlast its ceiling; made-up ones get 401 then 429', async () => {
  const base = await startApp('127.0.0.1');
  const codes = [];
  for (let k = 0; k < 3; k++) {
    const key = mkKey(`a${k}`);
    for (let i = 0; i < LIMITS.authed; i++) codes.push(await get(`${base}/api/private`, { 'x-api-key': key }));
    assert.equal(await get(`${base}/api/private`, { 'x-api-key': key }), 429, 'own limit');
  }
  assert.deepEqual(count(codes), { 200: LIMITS.authed * 3 });

  const fake = [];
  for (let i = 0; i < LIMITS.authed + 5; i++) fake.push(await get(`${base}/api/private`, randomBearer()));
  assert.deepEqual(count(fake), { 401: LIMITS.authed, 429: 5 });
});

test('real requireAuth: a session or key on a public route first, then a private one, keeps working', async () => {
  const base = await startApp('127.0.0.1');
  const key = mkKey('b');
  assert.equal(await get(`${base}/api/whoami`, { 'x-api-key': key }), 200);
  assert.equal(await get(`${base}/api/private`, { 'x-api-key': key }), 200);
  const flood = [];
  for (let i = 0; i < LIMITS.authed + 1; i++) flood.push(await get(`${base}/api/whoami`, randomBearer()));
  assert.equal(count(flood)[429] >= 1, true);
  assert.equal(await get(`${base}/api/private`, { 'x-api-key': key }), 200, 'the flood reached a proven key');
});

async function floodSpoofed(base, xff) {
  const codes = [];
  for (let i = 0; i < LIMITS.authed + 5; i++) codes.push(await get(`${base}/api/whoami`, { ...randomBearer(), 'X-Forwarded-For': xff(i) }));
  return count(codes);
}

test('through the loopback proxy: a client-supplied XFF prefix does not move the ceiling', async () => {
  const base = await startApp('127.0.0.1');
  // What a proxy that appends sends: "<whatever the client claimed>, <real peer>".
  const r = await floodSpoofed(base, (i) => `10.9.${i >> 8}.${i & 255}, ${A}`);
  assert.deepEqual(r, { 200: LIMITS.authed, 429: 5 });
});

const lanAddr = Object.values(networkInterfaces()).flat().find(i => i && i.family === 'IPv4' && !i.internal)?.address;

test('direct from a non-loopback peer: a rotating XFF does not move the ceiling',
  { skip: lanAddr ? false : 'no non-loopback IPv4 interface to bind' }, async () => {
    const base = await startApp(lanAddr);
    const r = await floodSpoofed(base, (i) => `10.9.${i >> 8}.${i & 255}`);
    assert.deepEqual(r, { 200: LIMITS.authed, 429: 5 });
  });
