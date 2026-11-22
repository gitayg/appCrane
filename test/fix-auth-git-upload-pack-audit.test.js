// A direct POST to git-upload-pack returns a pack without ever touching GET
// info/refs, so someone with access who knows a SHA used to skip the only audit
// row a fetch left. Real upload-pack, real git clone, no stubs.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

const run = promisify(execFile);
const ROOT = mkdtempSync(join(tmpdir(), 'crane-fix-auth-git-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { createGitHttpRouter } = await import('../server/routes/gitHttp.js');

const appId = db.prepare(`INSERT INTO apps (name, slug, slot, source_type, repo_backend) VALUES ('a', 'gh-a', 1, 'managed', 'local')`).run().lastInsertRowid;
const key = generateApiKey('dhk_user');
const userId = db.prepare('INSERT INTO users (name, email, role, active, api_key_hash) VALUES (?, ?, ?, ?, ?)').run('m', 'm@t.test', 'user', 1, hashApiKey(key)).lastInsertRowid;
db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(appId, userId, 'user');
await lg.createAppRepo('gh-a');
await lg.pushFilesToManagedRepo('gh-a', [{ path: 'secret.txt', content: 'source bytes\n' }], { branch: 'main', message: 'x' });
const sha = execFileSync('git', ['--git-dir', lg.repoPath('gh-a'), 'rev-parse', 'refs/heads/main']).toString().trim();

const app = express();
app.use('/git', createGitHttpRouter());
const srv = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const port = srv.address().port;
after(() => srv.close());

const pkt = (s) => (s.length + 4).toString(16).padStart(4, '0') + s;
const wantBody = () => pkt(`want ${sha} ofs-delta\n`) + '0000' + pkt('done\n');
const authHeader = { authorization: 'Basic ' + Buffer.from(`x:${key}`).toString('base64') };
const post = (headers = {}, body = wantBody()) => fetch(`http://127.0.0.1:${port}/git/gh-a.git/git-upload-pack`, {
  method: 'POST', headers: { 'content-type': 'application/x-git-upload-pack-request', ...authHeader, ...headers }, body,
});
const rows = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ? ORDER BY id').all(action);
const clear = () => db.prepare("DELETE FROM audit_log WHERE action IN ('git-fetch', 'git-upload-pack')").run();

test('a direct POST that returns a pack leaves a git-upload-pack row naming the user, the app and the address', async () => {
  clear();
  const r = await post();
  const buf = Buffer.from(await r.arrayBuffer());
  assert.equal(r.status, 200);
  assert.ok(buf.includes('PACK'), 'the POST really returned a pack');
  const got = rows('git-upload-pack');
  assert.equal(got.length, 1);
  assert.equal(got[0].user_id, userId);
  assert.equal(got[0].app_id, appId);
  assert.deepEqual(JSON.parse(got[0].detail), { slug: 'gh-a', transport: 'smart-http', ip: '127.0.0.1' });
  assert.equal(rows('git-fetch').length, 0, 'the direct POST is not a git-fetch');
});

test('a POST the route refuses leaves no row', async () => {
  clear();
  const wrongType = await post({ 'content-type': 'text/plain' });
  assert.equal(wrongType.status, 415);
  await wrongType.arrayBuffer();
  const noAuth = await fetch(`http://127.0.0.1:${port}/git/gh-a.git/git-upload-pack`, { method: 'POST', headers: { 'content-type': 'application/x-git-upload-pack-request' }, body: wantBody() });
  assert.equal(noAuth.status, 401);
  await noAuth.arrayBuffer();
  assert.equal(rows('git-upload-pack').length, 0);
});

test('a real clone is still exactly one git-fetch, plus upload-pack rows of its own', async () => {
  clear();
  const dir = join(ROOT, 'clone');
  await run('git', ['clone', `http://x:${key}@127.0.0.1:${port}/git/gh-a.git`, dir], { env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
  assert.equal(rows('git-fetch').length, 1);
  assert.ok(rows('git-upload-pack').length >= 1);
});

test('a failing audit write does not break the fetch', async (t) => {
  const realPrepare = db.prepare.bind(db);
  db.prepare = (sql) => { if (/INSERT INTO audit_log/.test(sql)) throw new Error('audit down'); return realPrepare(sql); };
  t.after(() => { db.prepare = realPrepare; });
  const r = await post();
  const buf = Buffer.from(await r.arrayBuffer());
  assert.equal(r.status, 200);
  assert.ok(buf.includes('PACK'));
});
