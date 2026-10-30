import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The 2.125.14 upgrade files one request per app that reads X-AppCrane-*
// identity headers without checking the v2 signature, and e-mails its owners.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-idv2-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { fileIdentityUpgradeRequests, REQUEST_KIND } = await import('../server/services/identityUpgradeRequests.js');

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

let slot = 21000;
function app(slug, files, { env = 'production', source_type = 'github' } = {}) {
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, ?, ?, ?)').run(slug, slug, slot++, source_type, 'main');
  const rel = join(ROOT, 'apps', slug, env, 'releases', 'r1');
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(rel, name, '..'), { recursive: true });
    writeFileSync(join(rel, name), body);
  }
  symlinkSync(rel, join(ROOT, 'apps', slug, env, 'current'));
}

app('reads-plain', { 'server.js': "const a = 1;\nconst email = req.headers['x-appcrane-user-email'];\n" });
app('reads-v1-only', { 'src/auth.ts': "verify(req.headers['x-appcrane-identity-sig']);\nreq.headers['X-AppCrane-Auth-Via'];\n" }, { env: 'sandbox' });
app('checks-v2', { 'a.js': "h['x-appcrane-user']", 'b.js': 'verifyIdentity(req, { requireV2: true })' });
app('python', { 'app.py': "user = environ.get('HTTP_X_APPCRANE_USER')\n" });
app('no-identity', { 'server.js': 'console.log(1)' });
app('only-in-deps', { 'node_modules/x/index.js': "h['x-appcrane-user']", 'server.js': '' });
app('image-app', { 'server.js': "h['x-appcrane-user']" }, { source_type: 'image' });

const notified = [];
const first = await fileIdentityUpgradeRequests({ db, notify: (id) => notified.push(id) });
const rows = db.prepare('SELECT id, app_slug, user_name, message, status FROM enhancement_requests WHERE kind = ? ORDER BY app_slug').all(REQUEST_KIND);

test('asks exactly the apps that read identity headers without the v2 check', () => {
  assert.deepEqual(rows.map((r) => r.app_slug), ['python', 'reads-plain', 'reads-v1-only']);
  assert.ok(rows.every((r) => r.status === 'new' && r.user_name === 'AppCrane upgrade'));
});

test('each new request e-mails its owners (notify gets every id, once)', () => {
  assert.deepEqual([...notified].sort(), rows.map((r) => r.id).sort());
  assert.deepEqual([...first].sort(), [...notified].sort());
});

test('the message names the file and line', () => {
  const m = rows.find((r) => r.app_slug === 'reads-plain').message;
  assert.match(m, /\(server\.js:2\)/);
  assert.match(m, /^Security: verify AppCrane's v2 identity signature/);
  assert.match(rows.find((r) => r.app_slug === 'reads-v1-only').message, /\(src\/auth\.ts:2\)/);
});

test('a second run, and a request the owner closed, file nothing', async () => {
  db.prepare("UPDATE enhancement_requests SET status = 'done' WHERE kind = ? AND app_slug = 'python'").run(REQUEST_KIND);
  const again = [];
  assert.deepEqual(await fileIdentityUpgradeRequests({ db, notify: (id) => again.push(id) }), []);
  assert.deepEqual(again, []);
  assert.throws(() => db.prepare("INSERT INTO enhancement_requests (app_slug, user_name, message, status, kind) VALUES ('reads-plain', 'x', 'x', 'new', ?)").run(REQUEST_KIND), /UNIQUE/);
});
