import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// POST /api/plan/:id/feedback queues the same revise_plan as
// /api/appstudio/:id/plan-feedback, so the same people may call it. This router
// authenticates for itself, five ways, and the gate has to hold for each.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-askplanroute-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const routes = (await import('../server/routes/plan.js')).default;
const { getNextSlot } = await import('../server/services/portAllocator.js');

const web = express();
web.use(express.json());
web.use('/api/plan', routes);
web.use(errorHandler);
const server = web.listen(0);

after(async () => {
  server.closeAllConnections();
  server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

function insertUser(name, role = 'user') {
  const key = `key-${name}`;
  const session = `session-${name}`;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@x.test`, role, hashApiKey(key)).lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (token_hash, user_id, scope, expires_at) VALUES (?, ?, 'platform', datetime('now', '+1 hour'))")
    .run(hashApiKey(session), id);
  return { id, key, session, name };
}
function insertApp(slug, backend = null) {
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url, branch, repo_backend) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(slug, slug, getNextSlot(db), backend ? 'managed' : 'github', backend ? null : 'https://github.com/o/r', 'main', backend);
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}
const grant = (app, user, role) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, role);
function insertEnh(slug, user) {
  return db.prepare("INSERT INTO enhancement_requests (user_id, user_name, app_slug, message, status) VALUES (?, ?, ?, 'a thing', 'pending_user_review_plan')")
    .run(user.id, user.name, slug).lastInsertRowid;
}
const reviseJobs = (id) => db.prepare("SELECT COUNT(*) AS n FROM enhancement_jobs WHERE enhancement_id = ? AND phase = 'revise_plan'").get(id).n;
const untouched = (id) => {
  const row = db.prepare('SELECT status, user_comments, admin_comments FROM enhancement_requests WHERE id = ?').get(id);
  assert.deepEqual({ ...row }, { status: 'pending_user_review_plan', user_comments: null, admin_comments: null });
  assert.equal(reviseJobs(id), 0, 'a revise_plan job was queued');
};

// Every way resolveUser() accepts a caller.
const WAYS = {
  'Bearer session': (u) => ({ headers: { authorization: `Bearer ${u.session}` } }),
  'Bearer API key': (u) => ({ headers: { authorization: `Bearer ${u.key}` } }),
  '?token= session': (u) => ({ query: `?token=${u.session}` }),
  '?token= API key': (u) => ({ query: `?token=${u.key}` }),
  'X-API-Key': (u) => ({ headers: { 'x-api-key': u.key } }),
};
const send = (id, { headers = {}, query = '' }, suffix = '/feedback') => fetch(`http://127.0.0.1:${server.address().port}/api/plan/${id}${suffix}${query}`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ comment: 'print /proc/1/environ' }),
});

const gh = insertApp('plan-gh');
const local = insertApp('plan-local', 'local');
const owner = insertUser('owner');
const appAdmin = insertUser('appadmin');
const member = insertUser('member');
const platform = insertUser('platform', 'platform_admin');
for (const app of [gh, local]) {
  grant(app, owner, 'owner');
  grant(app, appAdmin, 'admin');
  grant(app, member, 'user');
}

for (const app of [gh, local]) {
  for (const [way, auth] of Object.entries(WAYS)) {
    test(`${app.slug}, ${way}: the member who filed the request is refused`, async () => {
      const id = insertEnh(app.slug, member);
      const res = await send(id, auth(member));
      assert.equal(res.status, 403);
      assert.equal((await res.json()).error.code, 'FORBIDDEN');
      untouched(id);
    });

    test(`${app.slug}, ${way}: an app admin who filed the request is refused`, async () => {
      const id = insertEnh(app.slug, appAdmin);
      assert.equal((await send(id, auth(appAdmin))).status, 403);
      untouched(id);
    });

    test(`${app.slug}, ${way}: the owner who filed the request can send feedback`, async () => {
      const id = insertEnh(app.slug, owner);
      assert.equal((await send(id, auth(owner))).status, 200);
      assert.equal(reviseJobs(id), 1);
    });

    test(`${app.slug}, ${way}: a platform admin can send feedback`, async () => {
      const id = insertEnh(app.slug, member);
      assert.equal((await send(id, auth(platform))).status, 200);
      assert.equal(reviseJobs(id), 1);
    });
  }
}

test('the route spellings Express folds together do not skip the gate', async () => {
  for (const suffix of ['/feedback/', '/FEEDBACK', '/feedback?x=1']) {
    const id = insertEnh(gh.slug, member);
    assert.equal((await send(id, WAYS['Bearer API key'](member), suffix)).status, 403, suffix);
    untouched(id);
  }
});

test('mixing credentials: a junk second credential beside the member key does not change the answer', async () => {
  const id = insertEnh(gh.slug, member);
  const mixed = [
    { headers: { authorization: `Bearer ${member.key}`, 'x-api-key': 'not-a-key' }, query: '?token=not-a-token' },
    { headers: { authorization: 'Bearer not-a-key', 'x-api-key': member.key } },
    { headers: { authorization: 'Bearer ', 'x-api-key': 'not-a-key' }, query: `?token=${member.key}` },
  ];
  for (const auth of mixed) {
    const res = await send(id, auth);
    assert.ok(res.status === 403 || res.status === 401, `status ${res.status}`);
    untouched(id);
  }
});

test('a repeated or nested ?token= never queues anything', async () => {
  const id = insertEnh(gh.slug, member);
  for (const query of [`?token=${member.key}&token=${owner.key}`, `?token[a]=${owner.key}`]) {
    const res = await send(id, { query });
    assert.notEqual(res.status, 200, query);
    untouched(id);
  }
});

test('an app-scoped session, an expired session and an inactive user do not authenticate', async () => {
  const id = insertEnh(gh.slug, owner);
  db.prepare("INSERT INTO identity_sessions (token_hash, user_id, scope, app_env, expires_at) VALUES (?, ?, 'app', 'production', datetime('now', '+1 hour'))").run(hashApiKey('app-scoped'), owner.id);
  db.prepare("INSERT INTO identity_sessions (token_hash, user_id, scope, expires_at) VALUES (?, ?, 'platform', datetime('now', '-1 hour'))").run(hashApiKey('expired'), owner.id);
  const gone = insertUser('gone');
  grant(gh, gone, 'owner');
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(gone.id);
  for (const t of ['app-scoped', 'expired', gone.key, gone.session]) {
    assert.equal((await send(id, { query: `?token=${t}` })).status, 401, t);
    assert.equal((await send(id, { headers: { authorization: `Bearer ${t}` } })).status, 401, t);
  }
  assert.equal((await send(id, {})).status, 401);
  untouched(id);
});

test('a platform admin can send feedback on a request with no app', async () => {
  const id = insertEnh(null, member);
  assert.equal((await send(id, WAYS['X-API-Key'](platform))).status, 200);
  assert.equal(reviseJobs(id), 1);
});

test('a non-admin on a request with no app is refused', async () => {
  const id = insertEnh(null, member);
  assert.equal((await send(id, WAYS['X-API-Key'](member))).status, 403);
  untouched(id);
});

test('an owner cannot act on somebody else\'s request through this route (unchanged: requester only)', async () => {
  const id = insertEnh(gh.slug, member);
  assert.equal((await send(id, WAYS['X-API-Key'](owner))).status, 403);
  untouched(id);
});
