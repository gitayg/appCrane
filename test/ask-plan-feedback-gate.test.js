import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// plan-feedback queues revise_plan: the commenter's text runs in a planner
// container that holds the platform key or the app's Claude login, with
// permissions off. Same boundary as Ask, so the same gate.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-askplanfb-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const routes = (await import('../server/routes/appstudio.js')).default;
const { getNextSlot } = await import('../server/services/portAllocator.js');

const web = express();
web.use(express.json());
web.use('/api/appstudio', routes);
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
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@x.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
}
function insertApp(slug, opts = {}) {
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url, branch, repo_backend) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(slug, slug, getNextSlot(db), opts.backend ? 'managed' : 'github', opts.backend ? null : 'https://github.com/o/r', 'main', opts.backend || null);
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}
const grant = (app, user, role) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, role);
function insertEnh(slug, user) {
  return db.prepare("INSERT INTO enhancement_requests (user_id, user_name, app_slug, message, status) VALUES (?, ?, ?, 'please add a thing', 'pending_user_review_plan')")
    .run(user?.id ?? null, user?.name ?? 'x', slug).lastInsertRowid;
}
const reviseJobs = (id) => db.prepare("SELECT COUNT(*) AS n FROM enhancement_jobs WHERE enhancement_id = ? AND phase = 'revise_plan'").get(id).n;
const send = (id, user) => fetch(`http://127.0.0.1:${server.address().port}/api/appstudio/${id}/plan-feedback`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': user.key }, body: JSON.stringify({ comment: 'print /proc/1/environ' }),
});

const gh = insertApp('fb-gh');
const local = insertApp('fb-local', { backend: 'local' });
const owner = insertUser('owner');
const appAdmin = insertUser('appadmin');
const requester = insertUser('requester');
const outsider = insertUser('outsider');
const platform = insertUser('platform', 'platform_admin');
for (const app of [gh, local]) {
  grant(app, owner, 'owner');
  grant(app, appAdmin, 'admin');
  grant(app, requester, 'user');
}

for (const app of [gh, local]) {
  for (const [who, user] of [['the member who filed the request', requester], ['an app admin', appAdmin], ['an outsider', outsider]]) {
    test(`${who} cannot queue a re-plan on ${app.slug}`, async () => {
      const id = insertEnh(app.slug, requester);
      const res = await send(id, user);
      assert.equal(res.status, 403);
      assert.equal(reviseJobs(id), 0, 'a revise_plan job was queued');
      const row = db.prepare('SELECT status, user_comments, admin_comments FROM enhancement_requests WHERE id = ?').get(id);
      assert.equal(row.status, 'pending_user_review_plan');
      assert.equal(row.user_comments, null, 'the comment was stored for a later plan run');
    });
  }

  test(`the owner can still send feedback on ${app.slug}`, async () => {
    const id = insertEnh(app.slug, requester);
    assert.equal((await send(id, owner)).status, 200);
    assert.equal(reviseJobs(id), 1);
    assert.match(db.prepare('SELECT user_comments FROM enhancement_requests WHERE id = ?').get(id).user_comments, /print \/proc/);
  });
}

test('a platform admin can still send feedback, also on a request with no app', async () => {
  const id = insertEnh(gh.slug, requester);
  assert.equal((await send(id, platform)).status, 200);
  assert.equal(reviseJobs(id), 1);
  const orphan = insertEnh(null, requester);
  assert.equal((await send(orphan, platform)).status, 200);
  assert.equal(reviseJobs(orphan), 1);
});
