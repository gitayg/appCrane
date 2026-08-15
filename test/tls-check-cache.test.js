import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// /api/server/tls-check — cached, and its two probes run together (v2.45.2).
//
// The route reaches OUT to the internet twice: hstspreload.org, and the
// platform's own domain to see its certificate from outside. Both were awaited
// in SERIES behind an 8s timeout each, and nothing cached the result — so every
// visit to the Settings page could spend up to 16 seconds on a question whose
// answer is DNS, a certificate and a public preload list, none of which change
// between two page loads a minute apart.
//
// Settings mounts several panels at once, so this fired on every open. It is the
// single slowest thing that page does.
//
// The parallelism assertion is on OVERLAP, not on elapsed time: the second probe
// must start before the first finishes. A wall-clock threshold would be a test
// that passes here and fails on a loaded runner, which is the exact shape
// scripts/check-test-portability.sh exists to reject.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tlscache-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')")
  .run(hashApiKey(KEY));

// Every outbound call the route makes, recorded with when it started and ended
// so overlap can be measured rather than inferred.
const PROBE_MS = 120;
let calls = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  // Only the route's OUTBOUND probes are stubbed. This test's own client talks
  // to 127.0.0.1 through the same global, and swallowing that made every
  // assertion below read `undefined` instead of a response.
  const u = String(url);
  const isProbe = u.startsWith('https://hstspreload.org/') || u.startsWith('https://crane.test.local/');
  if (!isProbe) return realFetch(url, init);

  const entry = { url: u, start: Date.now(), end: null };
  calls.push(entry);
  await new Promise(r => setTimeout(r, PROBE_MS));
  entry.end = Date.now();
  return {
    ok: true,
    status: 200,
    // 'preloaded' on purpose. With the default ACME mode this makes the route
    // emit an HSTS_PRELOADED_ACME warning, so `warnings` is a NON-EMPTY array
    // that the cache has to carry. An earlier fixture answered 'unknown', which
    // left warnings empty in both the live and cached payloads — the parity test
    // below then passed against a build that dropped warnings from the cache
    // entirely, because there were none to drop. Mutation-tested.
    json: async () => ({ status: 'preloaded' }),
  };
};
after(() => { globalThis.fetch = realFetch; });

const monitoring = (await import('../server/routes/monitoring.js')).default;
const app = express();
app.use(express.json());
app.use('/api', monitoring);
const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const tlsCheck = (qs = '') =>
  fetch(`${BASE}/api/server/tls-check${qs}`, { headers: { 'X-API-Key': KEY } })
    .then(r => r.json());

beforeEach(() => { calls = []; });

test('the two probes overlap — they are not awaited one after the other', async () => {
  const body = await tlsCheck('?refresh=1');
  assert.equal(body.domain, 'crane.test.local');
  assert.equal(calls.length, 2, `expected both probes, got ${JSON.stringify(calls.map(c => c.url))}`);

  const [first, second] = calls.sort((a, b) => a.start - b.start);
  assert.ok(second.start < first.end,
    `the second probe started at +${second.start - first.start}ms, after the first finished at ` +
    `+${first.end - first.start}ms — they are still running in series, so their timeouts add up`);
});

test('a second read is served from cache and makes no outbound calls at all', async () => {
  await tlsCheck('?refresh=1');
  assert.equal(calls.length, 2, 'setup: the priming read should have probed');

  calls = [];
  const body = await tlsCheck();
  assert.equal(calls.length, 0,
    `a cached read still reached the network: ${JSON.stringify(calls.map(c => c.url))}`);
  assert.equal(body.cached, true, 'the cached read should say so');
  assert.equal(body.domain, 'crane.test.local', 'the cached payload must still be the real answer');
});

test('refresh=1 bypasses the cache — the recheck button has to mean something', async () => {
  await tlsCheck('?refresh=1');
  calls = [];

  const body = await tlsCheck('?refresh=1');
  assert.equal(calls.length, 2, 'refresh=1 did not re-probe');
  assert.equal(body.cached, false);
});

test('the cached payload carries the same fields a fresh one does', async () => {
  const fresh = await tlsCheck('?refresh=1');
  const cached = await tlsCheck();
  // Guards the guard: if the fixture ever stops producing a warning, the parity
  // assertion below goes vacuous and would accept a cache that drops them.
  assert.ok(fresh.warnings.length > 0,
    'fixture no longer produces a warning — the parity check underneath is not testing anything');
  const shape = o => Object.keys(o).filter(k => k !== 'cached').sort();
  assert.deepEqual(shape(cached), shape(fresh),
    'the cache returns a different shape than a live read — callers would see fields appear and vanish');
  assert.deepEqual(
    { ...cached, cached: undefined },
    { ...fresh, cached: undefined },
    'the cached answer differs from the one that was cached');
});

test('changing TLS mode re-probes without waiting for the TTL', async () => {
  // The cache key covers manual-vs-ACME, because that is what the answer depends
  // on: an admin who uploads a certificate must not be shown the ACME verdict
  // from before the change.
  await tlsCheck('?refresh=1');
  calls = [];
  assert.equal((await tlsCheck()).cached, true, 'setup: should be cached before the change');

  db.prepare("INSERT INTO settings (key, value) VALUES ('tls_cert_file','/etc/ssl/c.pem')").run();
  db.prepare("INSERT INTO settings (key, value) VALUES ('tls_key_file','/etc/ssl/k.pem')").run();

  calls = [];
  const after2 = await tlsCheck();
  assert.equal(after2.cached, false,
    'switching to a manual certificate served the cached ACME answer');
  assert.equal(after2.tls_mode, 'manual');
  assert.equal(calls.length, 2, 'the mode change should have triggered a real re-probe');
});
