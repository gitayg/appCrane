import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// One request's own page (/requests/:id) reads GET /api/enhancements/:id, and a
// request sent to the coder links to the session it went to. Who may see what
// mirrors the routes that already exist:
//   - a request: platform admin (GET /), the requester (/my), or someone with
//     request.view_app on its app (/owned; owners by default). Anyone else gets
//     the same 404 as an unknown id.
//   - a coder session: GET /api/coder/:slug/session/:id, unchanged. Any member
//     of the app may read any of its sessions; only the session's owner may
//     send to it (coder-session-owner.test.js). A session of another app is
//     refused.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-reqdetail-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const mk = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const mkApp = (slug) => db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')")
  .run(slug.toUpperCase(), Math.floor(Math.random() * 1e6), slug).lastInsertRowid;
const A = mkApp('rqa'), B = mkApp('rqb');

const PLATFORM = mk('platform', 'platform_admin');
const OWNER = mk('owner'), MEMBER = mk('member'), REQUESTER = mk('requester'), OUTSIDER = mk('outsider'), BOWNER = mk('bowner');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(A, OWNER.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(A, MEMBER.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(B, BOWNER.id);

const req = (slug, user, message, extra = {}) => db.prepare(`
  INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, done_note, coder_session_id, vuln_key)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(slug, user?.id ?? null, extra.user_name ?? (user ? 'someone' : null), message,
  extra.status ?? 'new', extra.done_note ?? null, extra.coder_session_id ?? null, extra.vuln_key ?? null).lastInsertRowid;

const R_A = req('rqa', REQUESTER, 'Make the button blue', { status: 'done', done_note: 'Made it blue.', coder_session_id: 'cs-a' });
const R_VULN = req('rqa', null, 'Upgrade x 1.0 → 1.1 (GHSA-1)\n\n- Package: x 1.0 (npm)', { user_name: 'AppCrane dependency scan', vuln_key: '[1,"npm","x","GHSA-1"]' });
const R_PLATFORM = req('_platform', MEMBER, 'Platform idea');

db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('cs-a', 'rqa', ?, 'b', 'shipped')").run(OWNER.id);
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('cs-b', 'rqb', ?, 'b', 'idle')").run(BOWNER.id);

const enh = (await import('../server/routes/enhancements.js')).default;
const coder = (await import('../server/routes/coder.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/enhancements', enh); a.use('/api/coder', coder); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const get = async (path, who) => {
  const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`, { headers: { 'x-api-key': who.key } });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

test('platform admin, the app owner and the requester each see the request, with everything the page shows', async () => {
  for (const who of [PLATFORM, OWNER, REQUESTER]) {
    const r = await get(`/api/enhancements/${R_A}`, who);
    assert.equal(r.status, 200, `refused (${r.status})`);
    const q = r.body.request;
    assert.equal(q.id, R_A);
    assert.equal(q.message, 'Make the button blue');
    assert.equal(q.app_slug, 'rqa');
    assert.equal(q.app_name, 'RQA');
    assert.equal(q.bucket, 'shipped');
    assert.equal(q.done_note, 'Made it blue.');
    assert.equal(q.coder_session_id, 'cs-a');
    assert.equal(q.dependency_scan, false);
    assert.ok(q.created_at);
    assert.equal('user_id' in q, false, 'the requester\'s user id is not part of the page');
  }
});

test('a member without request.view_app, an outsider and another app\'s owner get 404 — same as an unknown id', async () => {
  const unknown = await get('/api/enhancements/999999', PLATFORM);
  assert.equal(unknown.status, 404);
  for (const who of [MEMBER, OUTSIDER, BOWNER]) {
    const r = await get(`/api/enhancements/${R_A}`, who);
    assert.equal(r.status, 404, `allowed (${r.status})`);
    assert.deepEqual(r.body, unknown.body, 'not-allowed must look exactly like not-found');
  }
  assert.equal((await get('/api/enhancements/abc', PLATFORM)).status, 404);
});

test('a platform request: platform admin and its requester only', async () => {
  assert.equal((await get(`/api/enhancements/${R_PLATFORM}`, PLATFORM)).status, 200);
  assert.equal((await get(`/api/enhancements/${R_PLATFORM}`, MEMBER)).status, 200);
  assert.equal((await get(`/api/enhancements/${R_PLATFORM}`, OWNER)).status, 404);
});

test('a dependency-scan request carries its advisory body and says so', async () => {
  const r = await get(`/api/enhancements/${R_VULN}`, OWNER);
  assert.equal(r.status, 200);
  assert.equal(r.body.request.dependency_scan, true);
  assert.equal(r.body.request.user_name, 'AppCrane dependency scan');
  assert.match(r.body.request.message, /- Package: x 1\.0 \(npm\)/);
  assert.equal('vuln_key' in r.body.request, false);
  assert.equal((await get(`/api/enhancements/${R_VULN}`, MEMBER)).status, 404);
});

test('the session a request went to: readable by the app owner and a platform admin, refused for a member, another app or an outsider', async () => {
  // The coder is the app owner's and platform admins' alone (coder-owner-only.test.js).
  assert.equal((await get('/api/coder/rqa/session/cs-a', MEMBER)).status, 403);
  for (const who of [OWNER, PLATFORM]) {
    const r = await get('/api/coder/rqa/session/cs-a', who);
    assert.equal(r.status, 200, `refused (${r.status})`);
    assert.equal(r.body.session.id, 'cs-a');
    assert.equal(r.body.session.user_id, OWNER.id, 'the panel needs the owner to tell another user it is not theirs');
  }
  const foreign = await get('/api/coder/rqa/session/cs-b', OWNER);
  assert.equal(foreign.status, 403, 'another app\'s session must not open under this app');
  assert.equal(foreign.body.error.code, 'FORBIDDEN');
  assert.equal((await get('/api/coder/rqa/session/cs-a', OUTSIDER)).status, 403);
  assert.equal((await get('/api/coder/rqa/session/cs-a', BOWNER)).status, 403);
  assert.equal((await get('/api/coder/rqa/session/nope', OWNER)).status, 404);
});

// ── source shape: the links ────────────────────────────────────────────────

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');
const srv = (p) => readFileSync(new URL(`../server/${p}`, import.meta.url), 'utf8');

test('the coder link names the session the request went to, and the frame opens that one', () => {
  const bar = web('components/coder/SendToCoderBar.tsx');
  assert.match(bar, /\?coder=1&session=\$\{encodeURIComponent\(sessionId\)\}/);
  assert.match(bar, /navigate\(coderSessionHref\(slug, r\.session_id\)\)/, 'after sending, open the session they went to');
  const studio = web('pages/AppStudio.tsx');
  assert.match(studio, /href=\{coderSessionHref\(e\.app_slug, e\.coder_session_id\)\}/);
  assert.doesNotMatch(studio, /\?coder=1`/, 'a bare ?coder=1 link opens the app\'s latest session, not the request\'s');
  assert.match(web('pages/RequestDetail.tsx'), /coderSessionHref\(row\.app_slug, row\.coder_session_id\)/);
  const frame = web('pages/AppFrame.tsx');
  assert.match(frame, /setCoderSession\(searchParams\.get\('session'\)\)/);
  assert.match(frame, /sessionId=\{coderSession\}/);
  const hook = web('components/coder/useCoderSession.ts');
  assert.match(hook, /if \(pinned\) \{[\s\S]{0,300}?coderApi\.session\(slug, pinned\)/, 'a pinned session is fetched by id, not looked up as the latest');
  const panel = web('components/coder/CoderPanel.tsx');
  assert.match(panel, /useCoderSession\(slug, open && usable, props\.sessionId\)/);
  assert.match(panel, /!isLiveStatus\(s\.status\) \? 'ended'/);
  assert.match(panel, /s\.session\.user_id !== props\.viewerId \? 'other_user'/);
  assert.match(panel, /const canSend = !!s\.sessionId && !s\.resumingSince && !readOnly/);
  const note = web('components/coder/CoderPinNote.tsx');
  assert.match(note, /a coder session that has ended/);
  assert.match(note, /a coder session that belongs to another user/);
});

test('/requests/:id is a page: SPA route, served on a direct load, linked from the lists and the digest', () => {
  assert.match(web('AdminApp.tsx'), /<Route path="\/requests\/:id" element=\{<Layout><RequestDetail \/><\/Layout>\} \/>/);
  assert.match(srv('index.js'), /app\.get\('\/requests\/\*splat', \(req, res\) => sendHtml\(res, adminSpa\)\)/);
  assert.match(web('pages/AppStudio.tsx'), /href=\{`\/requests\/\$\{e\.id\}`\}/);
  assert.match(web('pages/MyRequests.tsx'), /<Link to=\{`\/requests\/\$\{r\.id\}`\}/);
  assert.match(srv('services/vulnRequests.js'), /\/requests\/\$\{Number\(requestId\)\}`/);
});
