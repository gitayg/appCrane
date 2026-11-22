import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { crawlServed, scanBuiltDir, builtDirsIn, redact } from '../server/services/servedOutputScan.js';
import { lineSecretRule, secretMatches } from '../server/services/releaseSecretScan.js';
import { buildDist, serveDir, SECRETS, ANON, REF } from './served-output-fixtures.js';

// Built-output secret scan: a real dist on disk, served by a real HTTP server
// with an SPA fallback, crawled the way the release check crawls a sandbox.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-served-'));
const servers = [];
after(() => {
  for (const s of servers) { s.closeAllConnections?.(); s.close(); }
  rmSync(ROOT, { recursive: true, force: true });
});

const rules = (r) => r.findings.map((f) => `${f.file}|${f.rule}`).sort();
const noSecretIn = (obj) => {
  const s = JSON.stringify(obj, (_k, v) => (v instanceof Set ? [...v] : v instanceof Map ? [...v.keys()].map(redact) : v));
  for (const [name, v] of Object.entries(SECRETS)) assert.ok(!s.includes(v), `${name} leaked`);
  for (const v of Object.values(SECRETS)) assert.ok(!s.includes(v.slice(0, 20)), 'a long prefix leaked');
  return s;
};

test('crawl finds the service_role JWT, sk_live key, a key in a source map and a served .env; the anon key is not a finding', async () => {
  const dir = join(ROOT, 'crawl');
  const dist = buildDist(dir, { basePath: '/shop-sandbox/' });
  const s = await serveDir(dist);
  servers.push(s);
  const r = await crawlServed({ baseUrl: `http://localhost:${s.address().port}`, basePath: '/shop-sandbox/' });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.html, true);
  assert.deepEqual(rules(r), [
    '/.env|anthropic-key',
    '/.env|served-env-file',
    '/assets/index-a1b2c3.js|stripe-live-secret',
    '/assets/index-a1b2c3.js|supabase-service-role-key',
    '/assets/lazy-k3j4.js.map|github-token',
    '/maps/vendor.map|openai-key',
  ]);
  const scanned = r.scanned.map((x) => x.path);
  for (const p of ['/', '/assets/index-a1b2c3.js', '/assets/vendor-9z8y7x.js', '/maps/vendor.map', '/assets/lazy-k3j4.js', '/assets/lazy-k3j4.js.map', '/assets/index-d4e5f6.css', '/.env']) {
    assert.ok(scanned.includes(p), `${p} not fetched: ${scanned.join(', ')}`);
  }
  assert.ok(!scanned.includes('/.env.local'), 'the SPA fallback for a missing .env path is not a served .env');
  assert.deepEqual([...r.supabase.anonKeys.keys()], [ANON], 'the anon key is collected as RLS input');
  assert.deepEqual([...r.supabase.refs], [REF]);
  assert.ok(r.supabase.tables.has('profiles') && r.supabase.tables.has('notes'));
  for (const f of r.findings) {
    if (f.rule !== 'served-env-file') assert.match(f.preview, /^.{6}\.\.\. \(\d+ chars\)$/);
  }
  noSecretIn(r);
});

test('an unreachable app is a failed crawl, not a clean one', async () => {
  const s = await serveDir(ROOT);
  const port = s.address().port;
  await new Promise((res) => s.close(res));
  const r = await crawlServed({ baseUrl: `http://localhost:${port}`, timeoutMs: 2000 });
  assert.equal(r.ok, false);
  assert.match(r.error, /could not fetch \//);
  assert.equal(r.findings.length, 0);
});

test('built output on disk: same findings, source map and .env included, anon key not flagged', () => {
  const dir = join(ROOT, 'disk');
  buildDist(dir);
  assert.deepEqual(builtDirsIn(dir), [join(dir, 'dist')]);
  const r = scanBuiltDir(dir, builtDirsIn(dir));
  assert.deepEqual(rules(r), [
    'dist/.env|anthropic-key',
    'dist/.env|served-env-file',
    'dist/assets/index-a1b2c3.js|stripe-live-secret',
    'dist/assets/index-a1b2c3.js|supabase-service-role-key',
    'dist/assets/lazy-k3j4.js.map|github-token',
    'dist/maps/vendor.map|openai-key',
  ]);
  assert.equal(r.supabase.anonKeys.size, 1);
  noSecretIn(r);
});

test('the shared pattern set: service_role, sk_live, weak JWT secrets; anon and placeholders are not matches', () => {
  assert.equal(lineSecretRule(`const k = "${SECRETS.serviceRole}";`), 'supabase-service-role-key');
  assert.equal(lineSecretRule(`stripe("${SECRETS.stripeLive}")`), 'stripe-live-secret');
  assert.equal(lineSecretRule('const secret = process.env.JWT_SECRET || "supersecretkey";'), 'weak-jwt-secret');
  assert.equal(lineSecretRule('jwt.sign({ id }, "supersecretkey", { expiresIn: "1h" })'), 'weak-jwt-secret');
  assert.equal(lineSecretRule("app.use(session({ secret: 'keyboard cat' }))"), 'weak-jwt-secret');
  assert.equal(lineSecretRule('const secret = process.env.JWT_SECRET;'), null);
  assert.equal(lineSecretRule(`apiKey: "${ANON}"`), null, 'anon key in an apiKey assignment');
  assert.deepEqual(secretMatches(`a="${ANON}";b="Bearer ${ANON}"`), [], 'anon key, also as a Bearer literal');
  assert.deepEqual(secretMatches('<input placeholder="x"> k="sk_live_xxxxxxxxxxxxxxxxxxxx"'), []);
});
