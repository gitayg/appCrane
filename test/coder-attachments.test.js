import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Files and images attached to a coder message. Stored on the host per session
// under an opaque id, copied into the container when the turn runs, and named
// to the agent by path (Claude Code's Read tool reads text, images and PDFs).
// docker is a shim that records `cp` and `exec`, so this asserts what would
// reach the container.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-coderattach-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-coderattach';
process.env.GIT_TERMINAL_PROMPT = '0';

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const SHIM = join(ROOT, 'bin');
const LOG = join(ROOT, 'docker.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(LOG, '');
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  image)   echo 5 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
  cp)      printf 'CP %s %s\\n' "$2" "$3" >> "${LOG}" ;;
  exec)
    for a in "$@"; do last="$a"; done
    case "$last" in
      *claude\\ -p*)
        printf 'TURN %s\\n' "$last" | tr '\\n' ' ' >> "${LOG}"; printf '\\n' >> "${LOG}"
        sleep "\${CRANE_TEST_TURN_SECONDS:-0}"
        printf '%s\\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
        printf '%s\\n' '{"type":"result","usage":{"input_tokens":1,"output_tokens":1}}' ;;
    esac ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const coderRoutes = (await import('../server/routes/coder.js')).default;
const { attachmentsDirFor } = await import('../server/services/builder/appContainer.js');
const { safeAttachmentName, MAX_ATTACHMENT_BYTES } = await import('../server/services/builder/coderAttachments.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });
after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const API_KEY = 'testkey-coderattach';
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')")
  .run(hashApiKey(API_KEY));
const SLUG = 'attachapp';
await lg.createAppRepo(SLUG, { description: 'attach' });
await lg.pushFilesToManagedRepo(SLUG, [{ path: 'package.json', content: '{"name":"attachapp"}\n' }], { message: 'seed' });
db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')")
  .run(SLUG, 994, SLUG);
const api = express();
api.use(express.json({ limit: '50mb' }));
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
after(() => server.close());
const call = async (method, path, body) => {
  const r = await REAL_FETCH(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json() };
};
const waitFor = async (fn, label) => {
  const end = Date.now() + 20000;
  while (Date.now() < end) { if (await fn()) return; await new Promise(r => setTimeout(r, 50)); }
  throw new Error(`timed out waiting for ${label}`);
};
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32, 7)]);
const log = () => readFileSync(LOG, 'utf8');

const s1 = await call('POST', `/api/coder/${SLUG}/session`);
const sid = s1.body.session_id;
// A second session of the same app, directly in the DB: its attachments must
// not be usable from the first.
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('other-session', ?, 1, 'b', 'paused')").run(SLUG);

test('a name is reduced to a safe file name that still says what it is', () => {
  assert.equal(safeAttachmentName('../../etc/passwd'), 'passwd');
  assert.equal(safeAttachmentName('Screen Shot 2026-09-24 at 1.02.03 AM.png'), 'Screen_Shot_2026-09-24_at_1.02.03_AM.png');
  assert.equal(safeAttachmentName("x'; rm -rf / #.txt"), 'txt');
  assert.equal(safeAttachmentName("x'; rm -rf #.txt"), 'x_rm_-rf_.txt');
  assert.equal(safeAttachmentName('.env'), 'env');
  assert.equal(safeAttachmentName(''), 'file');
});

let imgId, txtId;
test('uploads are stored per session, outside the workspace, and images are recognised', async () => {
  assert.equal(s1.status, 201, JSON.stringify(s1.body));
  const img = await call('POST', `/api/coder/${SLUG}/session/${sid}/attachments`, { name: 'shot.png', data: PNG.toString('base64') });
  assert.equal(img.status, 201, JSON.stringify(img.body));
  assert.equal(img.body.attachment.is_image, true);
  assert.match(img.body.attachment.id, /^[A-Za-z0-9_-]{22}$/);
  imgId = img.body.attachment.id;
  const txt = await call('POST', `/api/coder/${SLUG}/session/${sid}/attachments`, { name: '../notes.txt', data: Buffer.from('hello').toString('base64') });
  assert.equal(txt.body.attachment.is_image, false);
  assert.equal(txt.body.attachment.name, 'notes.txt');
  txtId = txt.body.attachment.id;

  const stored = readdirSync(attachmentsDirFor(SLUG, sid));
  assert.deepEqual(stored.sort(), [`${imgId}__shot.png`, `${txtId}__notes.txt`].sort());
  assert.equal(existsSync(join(ROOT, 'app-containers', SLUG, 'workspace', `${imgId}__shot.png`)), false,
    'an attachment landed in the workspace, where it would show as a change and be released');
});

test('an oversized or empty upload is refused with a reason', async () => {
  const big = await call('POST', `/api/coder/${SLUG}/session/${sid}/attachments`,
    { name: 'big.bin', data: Buffer.alloc(MAX_ATTACHMENT_BYTES + 1).toString('base64') });
  assert.equal(big.status, 413, JSON.stringify(big.body));
  assert.match(big.body.error.message, /limit is 10 MB/);
  const empty = await call('POST', `/api/coder/${SLUG}/session/${sid}/attachments`, { name: 'x', data: '' });
  assert.equal(empty.status, 400);
});

test("another session's attachment, or a made-up id, is refused rather than skipped", async () => {
  const other = await call('POST', `/api/coder/${SLUG}/session/other-session/attachments`, { name: 'o.png', data: PNG.toString('base64') });
  assert.equal(other.status, 201);
  const cross = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'x', attachments: [other.body.attachment.id] });
  assert.equal(cross.status, 404, JSON.stringify(cross.body));
  const bad = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'x', attachments: ['../../etc/passwd'] });
  assert.equal(bad.status, 400, JSON.stringify(bad.body));
  assert.doesNotMatch(log(), /TURN/, 'a refused message still ran a turn');
});

test('the files reach the container and the prompt names their paths', async () => {
  process.env.CRANE_TEST_TURN_SECONDS = '2';
  const d = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'make the coin look like this', attachments: [imgId] });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  // A follow-up typed while it runs keeps its own file.
  const f = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'and read this', attachments: [txtId] });
  assert.equal(f.body.queued, true);
  assert.match(f.body.followup.attachments, /notes\.txt/);

  await waitFor(() => (log().match(/^TURN /gm) || []).length >= 2, 'both turns');
  const cps = log().split('\n').filter(l => l.startsWith('CP '));
  assert.ok(cps.some(l => l.includes(`${imgId}__shot.png`) && l.includes(`:/tmp/appcrane-attachments/${imgId}__shot.png`)), cps.join('\n'));
  assert.ok(cps.some(l => l.includes(`:/tmp/appcrane-attachments/${txtId}__notes.txt`)), 'the follow-up ran without its file');
  const turns = log().split('\n').filter(l => l.startsWith('TURN '));
  assert.match(turns[0], new RegExp(`/tmp/appcrane-attachments/${imgId}__shot\\.png \\(image\\)`), turns[0]);
  assert.match(turns[1], new RegExp(`/tmp/appcrane-attachments/${txtId}__notes\\.txt`), 'the follow-up prompt does not name its file');

  const rows = db.prepare("SELECT attachments FROM coder_session_messages WHERE session_id = ? AND role = 'user' AND attachments IS NOT NULL ORDER BY id").all(sid);
  assert.deepEqual(rows.map(r => JSON.parse(r.attachments)[0].name), ['shot.png', 'notes.txt']);
});
