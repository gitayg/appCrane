import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'http';
import { readFileSync } from 'fs';

// v2.66.2. AppCrane's health contract — 200 + JSON carrying {status, version} —
// is a contract only an app AppCrane BUILDS has agreed to. That app declares
// be.health in deployhub.json and its author writes the route.
//
// A catalogue image has never heard of AppCrane. Enforcing the shape there does
// not catch unhealthy containers, it destroys healthy ones: BookStack answered
// /status with 200 and {"database":true,"cache":true,"session":true} — a richer
// signal than the contract asks for — and the deploy tore the container down
// for missing two field names. No health_path existed that would have passed,
// so the app was undeployable, along with most of the catalogue.
//
// What an image app still owes: a 200 at the health path inside the window.

const { __testables } = await import('../server/services/deployer.js');
const probe = __testables?.probeHealthEndpoint;

async function serve(handler) {
  const s = createServer(handler);
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}/health`, close: () => s.close() };
}

test('a real BookStack /status body passes for an image app and fails a built app', async () => {
  const BOOKSTACK = JSON.stringify({ database: true, cache: true, session: true });
  const s = await serve((_q, r) => { r.writeHead(200, { 'content-type': 'application/json' }); r.end(BOOKSTACK); });
  try {
    assert.deepEqual(await probe(s.url, 4000, { strict: false }), { ok: true },
      'a healthy third-party image must deploy');

    const strictResult = await probe(s.url, 4000);
    assert.equal(strictResult.ok, false, 'an app AppCrane builds still owes the declared contract');
    assert.equal(strictResult.reason, 'missing_fields');
  } finally { s.close(); }
});

test('a non-JSON 200 passes for an image app', async () => {
  // Most images serve HTML at any path a human would pick as a health path.
  const s = await serve((_q, r) => { r.writeHead(200, { 'content-type': 'text/html' }); r.end('<html>ok</html>'); });
  try {
    assert.deepEqual(await probe(s.url, 4000, { strict: false }), { ok: true });
    assert.equal((await probe(s.url, 4000)).reason, 'not_json');
  } finally { s.close(); }
});

test('relaxing the body contract does not relax the status contract', async () => {
  // The guard that keeps this from becoming "every container is healthy".
  const s = await serve((_q, r) => { r.writeHead(500); r.end('boom'); });
  try {
    const r = await probe(s.url, 3000, { strict: false });
    assert.equal(r.ok, false, 'a 500 must still fail, strict or not');
    assert.equal(r.reason, 'timeout');
  } finally { s.close(); }
});

test('the deployer chooses strictness by a rule, not by guesswork', () => {
  // The rule moved into healthProbeTarget.js when generated PHP builds joined
  // images as "third-party" (v2.70.1) -- a Laravel app AppCrane containerised
  // never agreed to the {status, version} shape either. What this test protects
  // is unchanged: the decision is a rule keyed on what built the release, and
  // the deploy path actually passes the result through instead of hardcoding it.
  const rule = readFileSync(new URL('../server/services/healthProbeTarget.js', import.meta.url), 'utf8');
  assert.match(rule, /source_type\s*!==\s*'image'/,
    'an image is third-party, anything else AppCrane built');
  assert.match(rule, /runtime\s*!==\s*'php'/,
    'a generated PHP build is third-party in the same sense');

  const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  assert.match(src, /strictHealth\s*=\s*probeTarget\.strict/,
    'the deploy path must take strictness from the rule, not recompute it');
  assert.match(src, /probeHealthEndpoint\(healthUrl,\s*30000,\s*\{\s*strict:\s*strictHealth\s*\}\)/,
    'the deploy path must actually pass the flag through');
});
