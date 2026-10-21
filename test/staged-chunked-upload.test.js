import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, statSync, readdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import crypto from 'crypto';
import express from 'express';

// Chunked staged uploads (routes/stagedFiles.js), mounted the way index.js
// mounts them: after the global 50 MB express.json, beside routes/files.js.
// The happy path ends in the managed repo through appcrane_push_to_managed_app
// { staged_token }, read back with an independent git.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-chunk-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.STAGED_MAX_BYTES = String(64 * 1024);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const stagedMod = await import('../server/routes/stagedFiles.js');
const filesRoutes = (await import('../server/routes/files.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const { callTool } = await import('../server/services/mcpTools.js');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/api/files/staged', stagedMod.default);
app.use('/api/files', filesRoutes);
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.close();
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

let n = 0;
function mkUser(role = 'user') {
  n++;
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`c${n}`, `c${n}@example.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, role, name: `c${n}`, kind: 'human', key };
}
function mcpKey(user, readOnly = 0) {
  const key = generateApiKey('dhk_mcp');
  db.prepare('INSERT INTO user_mcp_keys (user_id,key_hash,label,read_only) VALUES (?,?,?,?)').run(user.id, hashApiKey(key), 'k', readOnly);
  return key;
}
const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };

const owner = mkUser();
const other = mkUser();
const outsider = mkUser();
await lg.createAppRepo('chunky');
db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES ('chunky','chunky',?,'managed','local','main')").run(getNextSlot(db));
const theApp = db.prepare("SELECT * FROM apps WHERE slug = 'chunky'").get();
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(theApp.id, owner.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(theApp.id, other.id);

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
async function call(method, path, key, body, headers = {}) {
  const init = { method, headers: { 'X-API-Key': key, ...headers } };
  if (body !== undefined) {
    if (Buffer.isBuffer(body)) { init.body = body; init.headers['Content-Type'] ??= 'application/octet-stream'; }
    else { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  }
  const r = await fetch(BASE + path, init);
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, json };
}
const start = (key, body = { slug: 'chunky', filename: 'big.bin' }) => call('POST', '/api/files/staged/chunked', key, body);
const put = (key, handle, offset, buf, headers) => call('PUT', `/api/files/staged/${handle}?offset=${offset}`, key, buf, headers);
const finalize = (key, handle, digest) => call('POST', `/api/files/staged/${handle}/finalize`, key, { sha256: digest });

test('create: needs access to the app; read-only keys and .env names refused; handle is opaque', async () => {
  assert.equal((await start(outsider.key)).status, 403);
  assert.equal((await start(owner.key, { slug: 'nope', filename: 'x' })).status, 404);
  assert.equal((await start(mcpKey(owner, 1))).status, 403);
  assert.equal((await start(owner.key, { slug: 'chunky', filename: '.env.production' })).status, 400);
  const ok = await start(mcpKey(owner));
  assert.equal(ok.status, 201);
  assert.match(ok.json.handle, /^[A-Za-z0-9_-]{22}$/);
  const dir = join(ROOT, 'staged', ok.json.handle);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(ROOT, 'staged')).mode & 0o777, 0o700);
});

test('handle is owned by its creator: another user gets 404 on PUT and finalize', async () => {
  const { json } = await start(owner.key);
  const buf = Buffer.from('hello');
  assert.equal((await put(other.key, json.handle, 0, buf)).status, 404);
  assert.equal((await finalize(other.key, json.handle, sha(buf))).status, 404);
  assert.equal((await put(owner.key, json.handle, 0, buf)).status, 200);
});

test('offset must equal the bytes received so far; a mismatch is refused and changes nothing', async () => {
  const { json } = await start(owner.key);
  const a = Buffer.from('aaaa');
  assert.equal((await put(owner.key, json.handle, 0, a)).json.received_bytes, 4);
  const bad = await put(owner.key, json.handle, 2, Buffer.from('zz'));
  assert.equal(bad.status, 409);
  assert.equal(bad.json.error.code, 'OFFSET_MISMATCH');
  assert.equal(bad.json.received_bytes, 4);
  assert.equal((await put(owner.key, json.handle, 0, a)).status, 409);
  assert.equal((await put(owner.key, json.handle, 4, Buffer.from('bb'))).json.received_bytes, 6);
});

test('chunks must be application/octet-stream (a JSON body is refused, not parsed)', async () => {
  const { json } = await start(owner.key);
  const r = await put(owner.key, json.handle, 0, Buffer.from('{"a":1}'), { 'Content-Type': 'application/json' });
  assert.equal(r.status, 415);
});

test('size cap: a chunk that would cross STAGED_MAX_BYTES is refused and rolled back', async () => {
  const { json } = await start(owner.key);
  const half = Buffer.alloc(40 * 1024, 1);
  assert.equal((await put(owner.key, json.handle, 0, half)).status, 200);
  const over = await put(owner.key, json.handle, half.length, half);
  assert.equal(over.status, 413);
  const file = join(ROOT, 'staged', json.handle, 'big.bin');
  assert.equal(statSync(file).size, half.length);
});

test('size cap holds without a Content-Length (chunked transfer encoding)', async () => {
  const { json } = await start(owner.key);
  const body = new ReadableStream({
    start(c) { for (let i = 0; i < 10; i++) c.enqueue(new Uint8Array(10 * 1024)); c.close(); },
  });
  const r = await fetch(`${BASE}/api/files/staged/${json.handle}?offset=0`, {
    method: 'PUT', body, duplex: 'half', headers: { 'X-API-Key': owner.key, 'Content-Type': 'application/octet-stream' },
  });
  assert.equal(r.status, 413);
  assert.equal(statSync(join(ROOT, 'staged', json.handle, 'big.bin')).size, 0);
});

test('sha256 mismatch at finalize is refused and nothing is staged', async () => {
  const { json } = await start(owner.key);
  await put(owner.key, json.handle, 0, Buffer.from('payload'));
  const r = await finalize(owner.key, json.handle, sha(Buffer.from('something else')));
  assert.equal(r.status, 422);
  assert.equal(r.json.error.code, 'SHA256_MISMATCH');
  assert.equal(db.prepare('SELECT COUNT(*) c FROM staged_files WHERE token = ?').get(json.handle).c, 0);
});

test('TTL: an expired handle answers 404; the sweep removes expired uploads and keeps live ones', async () => {
  const live = (await start(owner.key)).json.handle;
  const dead = (await start(owner.key)).json.handle;
  const metaPath = join(ROOT, 'staged', dead, 'upload.json');
  const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
  writeFileSync(metaPath, JSON.stringify({ ...meta, expires_ms: Date.now() - 1000 }));
  assert.equal((await put(owner.key, dead, 0, Buffer.from('x'))).status, 404);
  assert.ok(stagedMod.sweepChunkedUploads() >= 1);
  assert.equal(existsSync(join(ROOT, 'staged', dead)), false);
  assert.equal(existsSync(join(ROOT, 'staged', live)), true);
});

test('happy path: chunks + finalize + appcrane_push_to_managed_app land the exact bytes in the repo', async () => {
  const key = mcpKey(owner);
  const bytes = crypto.randomBytes(50 * 1024);
  const { json } = await start(key, { slug: 'chunky', filename: 'blob.bin' });
  let off = 0;
  for (const size of [20000, 20000, bytes.length - 40000]) {
    const r = await put(key, json.handle, off, bytes.subarray(off, off + size));
    assert.equal(r.status, 200);
    off += size;
  }
  const fin = await finalize(key, json.handle, sha(bytes));
  assert.equal(fin.status, 200);
  assert.equal(fin.json.token, json.handle);
  assert.equal(fin.json.size_bytes, bytes.length);
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'file-stage' AND app_id = ? ORDER BY id DESC LIMIT 1").get(theApp.id);
  assert.deepEqual(Object.keys(JSON.parse(audit.detail)).sort(), ['bytes', 'chunked', 'filename', 'sha256']);
  assert.equal((await finalize(key, json.handle, sha(bytes))).status, 404, 'a finalized handle is no longer an upload');

  await callTool({ id: owner.id, role: 'user', name: owner.name, kind: 'human' }, 'appcrane_push_to_managed_app',
    { slug: 'chunky', files: [{ path: 'assets/blob.bin', staged_token: fin.json.token }], message: 'add blob' }, { id: 1 });
  const landed = execFileSync('git', [`--git-dir=${lg.repoPath('chunky')}`, 'cat-file', 'blob', 'refs/heads/main:assets/blob.bin'], { env: CLEAN, maxBuffer: 1 << 24 });
  assert.equal(sha(landed), sha(bytes));
});

test('the push into the repo still refuses a traversal dest and a .env dest (existing guards)', async () => {
  for (const dest of ['../escape.bin', '.env']) {
    const { json } = await start(owner.key, { slug: 'chunky', filename: 'f.bin' });
    const b = Buffer.from(`for ${dest}`);
    await put(owner.key, json.handle, 0, b);
    const fin = await finalize(owner.key, json.handle, sha(b));
    await assert.rejects(callTool({ id: owner.id, role: 'user', name: owner.name, kind: 'human' }, 'appcrane_push_to_managed_app',
      { slug: 'chunky', files: [{ path: dest, staged_token: fin.json.token }] }, { id: 1 }));
  }
  const tree = execFileSync('git', [`--git-dir=${lg.repoPath('chunky')}`, 'ls-tree', '-r', '--name-only', 'refs/heads/main'], { env: CLEAN }).toString();
  assert.ok(!tree.includes('.env') && !tree.includes('escape'));
});

test('sweep ignores finalized uploads (sweepStagedFiles owns them) and stray names', async () => {
  const { json } = await start(owner.key, { slug: 'chunky', filename: 'keep.bin' });
  const b = Buffer.from('keep');
  await put(owner.key, json.handle, 0, b);
  assert.equal((await finalize(owner.key, json.handle, sha(b))).status, 200);
  writeFileSync(join(ROOT, 'staged', 'not-a-handle'), 'x');
  stagedMod.sweepChunkedUploads(Date.now() + 365 * 86400_000);
  assert.ok(readdirSync(join(ROOT, 'staged')).includes('not-a-handle'));
  assert.equal(existsSync(join(ROOT, 'staged', json.handle, 'keep.bin')), true);
});
