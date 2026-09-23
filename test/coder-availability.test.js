import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The Coder button used to render only for Crane-hosted apps, so a user on any
// other app never learned the feature existed or what it would take. And the
// real gates report the FIRST failure only — fix the source, meet the
// credential gap next, one refusal at a time.
//
// GET /api/coder/:slug/availability reports every gap at once. What this file
// pins is that it cannot DISAGREE with the gates: availability says
// unavailable exactly when POST /session refuses, for every app shape.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-avail-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.ANTHROPIC_API_KEY;

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');

const KEY_ADMIN = 'avail-admin-key';
const KEY_USER  = 'avail-user-key';
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','a@t.test','platform_admin',?,1,'human')").run(hashApiKey(KEY_ADMIN)).lastInsertRowid;
const userId  = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('User','u@t.test','user',?,1,'human')").run(hashApiKey(KEY_USER)).lastInsertRowid;

let slot = 500;
async function mkApp(slug, fields) {
  const cols = { name: slug, slug, slot: slot++, branch: 'main', ...fields };
  const keys = Object.keys(cols);
  db.prepare(`INSERT INTO apps (${keys.join(',')}) VALUES (${keys.map(() => '?').join(',')})`).run(...keys.map((k) => cols[k]));
  const id = db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug).id;
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(id, userId);
  if (fields.repo_backend === 'local') await lg.createAppRepo(slug, { description: 'avail' });
  return id;
}

// Every source shape the platform has, each with the gap it must report.
const SHAPES = [
  ['hosted',   { source_type: 'managed', repo_backend: 'local' },                                  null],
  // repo_backend NULL is how a GitHub-backed managed app is stored; 'github' is
  // not a value the platform recognises and repoBackendOf refuses to guess.
  ['ghmanaged',{ source_type: 'managed', github_url: 'https://github.com/o/r' },                   'REPO_NOT_MIGRATED'],
  ['plaingh',  { source_type: 'github',  github_url: 'https://github.com/o/r2' },                  'NOT_CRANE_HOSTED'],
  ['uploaded', { source_type: 'upload' },                                                          'NOT_CONVERTED'],
  ['fromimg',  { source_type: 'image', image_ref: 'nginx:alpine' },                                'NO_SOURCE'],
];
for (const [slug, fields] of SHAPES) await mkApp(slug, fields);

const coderRoutes = (await import('../server/routes/coder.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  server.closeAllConnections?.(); server.unref(); server.close();
});

const get = async (key, path) => {
  const r = await fetch(`${BASE}${path}`, { headers: { 'X-API-Key': key } });
  return { status: r.status, body: await r.json() };
};
const startSession = async (key, slug) => {
  const r = await fetch(`${BASE}/api/coder/${slug}/session`, {
    method: 'POST', headers: { 'X-API-Key': key, 'Content-Type': 'application/json' }, body: '{}',
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

test('every source shape reports its own gap, and a Crane-hosted app reports none on source', async () => {
  // A platform key so the credential gap is out of the way for this check.
  process.env.ANTHROPIC_API_KEY = 'sk-ant-avail-test';
  try {
    for (const [slug, , expected] of SHAPES) {
      const { status, body } = await get(KEY_ADMIN, `/api/coder/${slug}/availability`);
      assert.equal(status, 200, `${slug}: availability is not always answerable (${status})`);
      const codes = body.gaps.map((g) => g.code);
      if (expected) {
        assert.deepEqual(codes, [expected], `${slug}: expected ${expected}, got ${JSON.stringify(codes)}`);
        assert.equal(body.available, false);
        for (const g of body.gaps) {
          assert.ok(g.title && g.detail && g.fix, `${slug}: a gap with no explanation or no fix is just a refusal`);
        }
      } else {
        assert.deepEqual(codes, [], `${slug}: a Crane-hosted app with a key reports a gap`);
        assert.equal(body.available, true);
      }
    }
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
  }
});

test('with no credential anywhere, the credential gap is reported TOO, not instead', async () => {
  // Fixing one gap and meeting the next is exactly what this endpoint exists
  // to prevent, so a GitHub app with no credential must name both.
  const { body } = await get(KEY_USER, '/api/coder/plaingh/availability');
  assert.deepEqual(body.gaps.map((g) => g.code), ['NOT_CRANE_HOSTED', 'NO_CREDENTIAL']);
  const cred = body.gaps.find((g) => g.code === 'NO_CREDENTIAL');
  assert.equal(cred.href, '/settings#account', 'the credential gap does not link to where it is fixed');
});

test('availability and the real session gate cannot disagree', async () => {
  // The whole value of the endpoint is that it predicts the gate. For every
  // shape, with and without a credential, "available" must be true exactly
  // when POST /session does NOT refuse on a gap.
  for (const withKey of [false, true]) {
    if (withKey) process.env.ANTHROPIC_API_KEY = 'sk-ant-avail-test';
    else delete process.env.ANTHROPIC_API_KEY;
    for (const [slug] of SHAPES) {
      const { body } = await get(KEY_USER, `/api/coder/${slug}/availability`);
      const start = await startSession(KEY_USER, slug);
      const gateRefused = [400, 503].includes(start.status);
      assert.equal(
        body.available, !gateRefused,
        `${slug} (key=${withKey}): availability says ${body.available} but session start answered ${start.status} ${JSON.stringify(start.body).slice(0, 160)}`,
      );
    }
  }
  delete process.env.ANTHROPIC_API_KEY;
});

test('can_release is reported, so the UI can say it up front instead of a 403 later', async () => {
  const asAdmin = await get(KEY_ADMIN, '/api/coder/hosted/availability');
  const asUser  = await get(KEY_USER,  '/api/coder/hosted/availability');
  assert.equal(asAdmin.body.can_release, true);
  assert.equal(asUser.body.can_release, false, 'a plain member is told they can release, and will then be refused');
});

test('a corrupt repo setting is reported as a gap, never a 500', async () => {
  // repoBackendOf refuses unrecognised values rather than guess — right for a
  // write path, but availability must always answer, or the one place that
  // explains the Coder button goes blank.
  db.prepare(`INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch)
              VALUES ('broken','broken',590,'managed','nonsense','main')`).run();
  const id = db.prepare("SELECT id FROM apps WHERE slug = 'broken'").get().id;
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(id, userId);
  const { status, body } = await get(KEY_USER, '/api/coder/broken/availability');
  assert.equal(status, 200, `availability 500'd on a corrupt row: ${JSON.stringify(body).slice(0, 200)}`);
  assert.ok(body.gaps.some((g) => g.code === 'UNKNOWN_SOURCE'), JSON.stringify(body.gaps.map((g) => g.code)));
  assert.equal(body.available, false);
});
