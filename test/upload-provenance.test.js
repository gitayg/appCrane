import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import express from 'express';

// An uploaded release has to be identifiable (v2.53.0).
//
// POST /api/apps/:slug/deploy/upload recorded
//   commit_hash = req.body.commit_sha || 'unknown'
// — a value the UPLOADER supplied, checked against nothing. Two different
// bundles could claim one SHA, and the honest caller (which sends no
// commit_sha, because there is no git repo behind an upload) got the literal
// string 'unknown'. So for upload-deployed apps the question rollback and
// audit both ask — which bytes is this release? — had no answer on record.
//
// v2.3.1 removed 'upload' as a source type for exactly that reason. These tests
// cover the answer to it rather than the removal: a SHA-256 AppCrane computes
// over the received bytes, before extraction, from the file on disk.
//
// Drives the REAL router over a real socket with a real multipart body. An
// earlier regression in this repo stayed green because the test asserted on a
// query string instead of calling the thing, so the assertions here are on what
// the route wrote to the database and returned on the wire.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-upload-prov-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A `docker` on PATH that refuses everything.
//
// The route fires deployApp without awaiting it, so an unshimmed run reaches
// the real daemon: the first version of this test built images, raced six
// deploys over one container name, and left a container behind on the
// developer's machine. None of that is under test here — the digest is computed
// and stored before the deploy is even started — and a test that needs a
// working Docker to assert on a database column is a test that will fail for
// reasons unrelated to what it covers.
const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), '#!/bin/sh\necho "docker unavailable in test" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const KEY = generateApiKey('dhk_admin');

const SLUG = 'upload-only-app';
let appId;
let userId;

before(() => {
  userId = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','u@x.io','platform_admin',?,1,'human')"
  ).run(hashApiKey(KEY)).lastInsertRowid;
  appId = db.prepare(
    "INSERT INTO apps (name, slug, slot, source_type) VALUES ('Upload Only', ?, 91, 'upload')"
  ).run(SLUG).lastInsertRowid;
});

// --- a server that mounts the real deploy router -----------------------------
//
// Nothing is stubbed on the request path: the router mounts requireAuth and
// requireAppAccess itself, so the test authenticates with a real API key
// against a real user row. Only the container start is out of scope — deployApp
// runs async after the response and fails on a machine with no Docker, which
// does not touch the columns under test.

const deployRouter = (await import('../server/routes/deploy.js')).default;

const server = await new Promise((res) => {
  const api = express();
  api.use('/api/apps', deployRouter);
  const s = api.listen(0, () => res(s));
});
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

/**
 * Build a tiny real .zip so safeExtract has something valid to open.
 *
 * zip rather than tar.gz because safeExtract's tar branch passes
 * --no-overwrite-dir, which is GNU tar only; macOS ships bsdtar and rejects it.
 * That is a pre-existing platform gap in safeExtract, not something this change
 * introduced — AppCrane deploys on Linux — but it means a tar fixture cannot
 * run these assertions on a developer machine. The zip branch is the same
 * safeExtract, and the digest under test is computed before either branch runs.
 */
function makeBundle(marker) {
  const dir = mkdtempSync(join(tmpdir(), 'bundle-src-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  writeFileSync(join(dir, 'src', 'index.js'), `console.log(${JSON.stringify(marker)});\n`);
  const out = join(mkdtempSync(join(tmpdir(), 'bundle-out-')), 'app.zip');
  execFileSync('zip', ['-qr', out, '.'], { cwd: dir });
  return out;
}

async function upload(path, { env = 'sandbox', commitSha = null } = {}) {
  const body = new FormData();
  body.set('env', env);
  if (commitSha) body.set('commit_sha', commitSha);
  body.set('file', new Blob([readFileSync(path)]), 'app.zip');
  const r = await fetch(`${BASE}/api/apps/${SLUG}/deploy/upload`, {
    method: 'POST', body, headers: { 'X-API-Key': KEY },
  });
  return { status: r.status, json: await r.json() };
}

const rowFor = (id) => db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

// ---------------------------------------------------------------------------

test("an upload with no commit_sha is identified by its bytes, not by 'unknown'", async () => {
  const bundle = makeBundle('alpha');
  const { status, json } = await upload(bundle);
  assert.equal(status, 200, JSON.stringify(json));

  const row = rowFor(json.deployment.id);
  assert.notEqual(row.commit_hash, 'unknown',
    "the honest caller — no git repo, so no commit_sha — recorded the literal string 'unknown', " +
    'which is the same value for every such release and identifies nothing');
  assert.equal(row.commit_hash, `sha256:${sha256(bundle)}`,
    'commit_hash must be the digest of the bytes the server received');
  assert.equal(row.artifact_sha256, sha256(bundle));
  assert.ok(row.artifact_bytes > 0);
});

test('the digest comes from the bytes — a false commit_sha cannot set the identity', async () => {
  const bundle = makeBundle('beta');
  const lie = 'a'.repeat(40);
  const { json } = await upload(bundle, { commitSha: lie });
  const row = rowFor(json.deployment.id);

  assert.equal(row.commit_hash, `sha256:${sha256(bundle)}`,
    'the uploader-supplied SHA used to BE the identity; it must no longer be able to set it');
  assert.notEqual(row.commit_hash, lie);
  assert.equal(row.declared_commit_sha, lie,
    'the claim is still worth recording — it is often a real SHA from the build machine — but ' +
    'beside the digest, never in place of it');
});

test('two different bundles claiming ONE commit_sha get two different identities', async () => {
  const claim = 'b'.repeat(40);
  const a = await upload(makeBundle('one'), { commitSha: claim });
  const b = await upload(makeBundle('two'), { commitSha: claim });

  const ra = rowFor(a.json.deployment.id);
  const rb = rowFor(b.json.deployment.id);
  assert.equal(ra.declared_commit_sha, rb.declared_commit_sha, 'both claimed the same SHA');
  assert.notEqual(ra.commit_hash, rb.commit_hash,
    'this is the collision the old scheme allowed: two unrelated artifacts, one recorded identity, ' +
    'and a rollback that cannot tell which one it is restoring');
});

test('the response echoes the digest so the uploader can compare it locally', async () => {
  const bundle = makeBundle('gamma');
  const { json } = await upload(bundle);
  assert.equal(json.artifact.sha256, sha256(bundle),
    'without this the client has no way to confirm the bytes deployed are the bytes it sent');
  assert.equal(json.artifact.filename, 'app.zip');
});

test('the deploy log states the identity, unprompted', async () => {
  const bundle = makeBundle('delta');
  const { json } = await upload(bundle, { commitSha: 'f'.repeat(40) });

  // Polled rather than read once. The line is emitted from inside deployApp,
  // which the route starts without awaiting, so a single read races it. It is
  // written there and not in the route on purpose: appendLog rebuilds
  // deployments.log from its own buffer, so a log line written by the route is
  // discarded as soon as the deploy begins.
  const deadline = Date.now() + 5000;
  let row;
  do {
    row = rowFor(json.deployment.id);
    if (row.log && row.log.includes(sha256(bundle))) break;
    await new Promise((r) => setTimeout(r, 25));
  } while (Date.now() < deadline);

  assert.match(row.log, new RegExp(sha256(bundle)),
    'an operator reading the deploy log is the audience for provenance; it must not require a DB query');
  assert.match(row.log, /NOT verified/,
    'the uploader-declared SHA appears in the log too, and must be labelled — an unlabelled 40-char ' +
    'hex string beside a digest reads as a verified commit');
});
