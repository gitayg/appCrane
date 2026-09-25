import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// v2.93.0: a coder release follows the sandbox deploy it starts. Reported on
// a real instance: Tiny Barons' sandbox deploys failed at `vite build` from
// July to September ("Cannot find module @rollup/rollup-linux-x64-musl"), each
// one silently, while the panel said "Deploying: sandbox #N" forever and the
// user had to relay the build error to the coder by hand.
const DIR = mkdtempSync(join(tmpdir(), 'crane-relwatch-'));
process.env.DATA_DIR = DIR;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { watchReleaseDeploy, failureExcerpt, fixPrompt, _resetAutoFixed } = await import('../server/services/builder/releaseWatch.js');
const { subscribe } = await import('../server/services/builder/builderSession.js');
after(() => rmSync(DIR, { recursive: true, force: true }));

const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('u','u@x','platform_admin','h',1,'human')").run().lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES ('TB','tb',911,'managed','local','main')").run().lastInsertRowid;
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('s1','tb',?,'b','idle')").run(uid);

const ROLLUP_LOG = [
  '[02:58:12] Using app-provided Dockerfile (validated)',
  '[02:58:20]   Step 11/33 : RUN npm install --include=dev',
  ...Array.from({ length: 80 }, (_, i) => `[02:58:${i}]   at Module._load (node:internal/modules/cjs/loader:${i})`),
  "[02:58:58]   Error: Cannot find module @rollup/rollup-linux-x64-musl. npm has a bug related to optional dependencies",
  '[02:58:58]   npm error command sh -c tsc -b && vite build',
  "The command '/bin/sh -c npm run build' returned a non-zero code: 1",
].join('\n');

function deploy(status, log = '', version = null) {
  return db.prepare("INSERT INTO deployments (app_id, env, version, status, log) VALUES (?, 'sandbox', ?, ?, ?)").run(appId, version, status, log).lastInsertRowid;
}
function watchEvents() { const ev = []; const off = subscribe('s1', (e) => ev.push(e)); return { ev, off }; }

test('a deploy that goes live is reported with its version, in the chat and the transcript', async () => {
  const id = deploy('building');
  const { ev, off } = watchEvents();
  setTimeout(() => db.prepare("UPDATE deployments SET status = 'live', version = '0.6.0' WHERE id = ?").run(id), 60);
  const out = await watchReleaseDeploy({ sessionId: 's1', deploymentId: id, commit: 'dbe8fce68be8', userId: uid, pollMs: 20, deps: { sendFix: async () => assert.fail('a live deploy was sent to the coder') } });
  off();
  assert.equal(out, 'live');
  const done = ev.find((e) => e.type === 'deploy');
  assert.equal(done.status, 'live');
  assert.equal(done.version, '0.6.0');
  assert.match(done.message, /live on sandbox as v0\.6\.0/);
  assert.ok(db.prepare("SELECT 1 FROM coder_session_messages WHERE session_id = 's1' AND content LIKE '%live on sandbox as v0.6.0%'").get(),
    'the outcome is not in the transcript, so a reload loses it');
});

test('a failed deploy goes to the coder by itself, with the failing log lines, once per release commit', async () => {
  _resetAutoFixed();
  const sent = [];
  const id = deploy('failed', ROLLUP_LOG);
  const { ev, off } = watchEvents();
  const out = await watchReleaseDeploy({ sessionId: 's1', deploymentId: id, commit: 'cdd13e5c1234', userId: uid, pollMs: 20, deps: { sendFix: async (a) => { sent.push(a); } } });
  assert.equal(out, 'failed');
  assert.equal(sent.length, 1, 'the failure was not handed to the coder');
  assert.equal(sent[0].userId, uid);
  assert.match(sent[0].prompt, /Cannot find module @rollup\/rollup-linux-x64-musl/, 'the prompt lost the actual error');
  assert.match(sent[0].prompt, /Do not release/);
  const failed = ev.find((e) => e.type === 'deploy');
  assert.equal(failed.status, 'failed');
  assert.match(failed.log_excerpt, /rollup-linux-x64-musl/);

  // The same commit failing again (a redeploy) is not sent a second time.
  const again = deploy('failed', ROLLUP_LOG);
  await watchReleaseDeploy({ sessionId: 's1', deploymentId: again, commit: 'cdd13e5c1234', userId: uid, pollMs: 20, deps: { sendFix: async (a) => { sent.push(a); } } });
  off();
  assert.equal(sent.length, 1, 'the same failure was sent to the coder twice');
});

test('when the hand-off itself fails, the user is told to take it from the log', async () => {
  _resetAutoFixed();
  const id = deploy('failed', ROLLUP_LOG);
  const { ev, off } = watchEvents();
  await watchReleaseDeploy({ sessionId: 's1', deploymentId: id, commit: 'ffff0000', userId: uid, pollMs: 20, deps: { sendFix: async () => { throw new Error('session paused'); } } });
  off();
  assert.ok(ev.some((e) => e.type === 'error' && /Could not hand the failed deploy to the coder \(session paused\)/.test(e.message)));
});

test('the excerpt keeps the error lines and stays bounded', () => {
  const x = failureExcerpt(ROLLUP_LOG + '\n' + 'x'.repeat(20000));
  assert.match(x, /rollup-linux-x64-musl/);
  assert.ok(x.length <= 6100, `excerpt is ${x.length} chars`);
  assert.doesNotMatch(failureExcerpt('\u001b[91mnpm error\u001b[0m'), /\u001b/, 'terminal colour codes reached the prompt');
  assert.match(fixPrompt({ commit: 'abc', deploymentId: 7, excerpt: 'E' }), /deploy #7/);
});

test('the release route watches every sandbox deploy it starts', () => {
  const route = readFileSync(new URL('../server/routes/coder.js', import.meta.url), 'utf8');
  assert.match(route, /for \(const t of result\.auto_deploy\?\.triggered \|\| \[\]\) \{\s*if \(t\.env !== 'sandbox'[\s\S]{0,120}watchReleaseDeploy\(\{ sessionId: session\.id, deploymentId: t\.deployment_id/);
});
