import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';
import Database from 'better-sqlite3';

// One open access request per person per app, held by the server and the
// database, not only by the Launch picker's disabled button.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-accessdedup-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Roadmap','dedup-app',1,'managed','forward_auth','private')").run();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Other','dedup-other',2,'managed','forward_auth','private')").run();
const mkUser = (name) => {
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,'user',1,?)")
    .run(name, `${name}@acme.test`, hashApiKey(`key-${name}`)).lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
    .run(id, hashApiKey(`tok-${name}`));
  return id;
};
const alice = mkUser('alice');
mkUser('bob');

const enhancementsRouter = (await import('../server/routes/enhancements.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/enhancements', enhancementsRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const post = (who, body) => fetch(`${BASE}/api/enhancements`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer tok-${who}` },
  body: JSON.stringify(body),
});
const access = (slug = 'dedup-app') => ({ message: 'Access request for app “Roadmap”', app_slug: slug });
const openCount = (userId, slug) => db.prepare(
  "SELECT COUNT(*) AS n FROM enhancement_requests WHERE user_id = ? AND app_slug = ? AND message LIKE 'Access request for app%' AND status != 'done'"
).get(userId, slug).n;

test('a second open access request is refused with 409 and the existing id', async () => {
  const first = await post('alice', access());
  assert.equal(first.status, 200);
  const { enhancement_id: id } = await first.json();
  const second = await post('alice', access());
  assert.equal(second.status, 409);
  const body = await second.json();
  assert.equal(body.error.code, 'DUPLICATE_ACCESS_REQUEST');
  assert.equal(body.enhancement_id, id);
  assert.equal(openCount(alice, 'dedup-app'), 1);
  assert.equal(db.prepare('SELECT kind FROM enhancement_requests WHERE id = ?').get(id).kind, 'access');
});

test('another user, another app, and a feature request are not affected', async () => {
  assert.equal((await post('bob', access())).status, 200);
  assert.equal((await post('alice', access('dedup-other'))).status, 200);
  assert.equal((await post('alice', { message: 'Please add dark mode', app_slug: 'dedup-app' })).status, 200);
  assert.equal((await post('alice', { message: 'Please add dark mode', app_slug: 'dedup-app' })).status, 200);
});

test('racing requests file exactly one', async () => {
  const results = await Promise.all(Array.from({ length: 8 }, () => post('alice', access('race-app'))));
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 409, 409, 409, 409, 409, 409, 409]);
  assert.equal(openCount(alice, 'race-app'), 1);
});

test('the database itself refuses a second open access row (two writers)', () => {
  // A second connection, as a second process would have: no route pre-check.
  const other = new Database(join(process.env.DATA_DIR, 'deployhub.db'));
  try {
    const ins = "INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, kind) VALUES ('two-writers', ?, 'alice', 'Access request for app x', 'new', 'access')";
    db.prepare(ins).run(alice);
    assert.throws(() => other.prepare(ins).run(alice), /UNIQUE constraint failed/);
  } finally {
    other.close();
  }
  assert.equal(openCount(alice, 'two-writers'), 1);
});

test('a closed request (approved or denied) allows a new one', async () => {
  const id = db.prepare("SELECT id FROM enhancement_requests WHERE user_id = ? AND app_slug = 'dedup-app' AND kind = 'access'").get(alice).id;
  db.prepare("UPDATE enhancement_requests SET status = 'done' WHERE id = ?").run(id);
  const again = await post('alice', access());
  assert.equal(again.status, 200);
  assert.notEqual((await again.json()).enhancement_id, id);
});

test('migration 135 builds the index on a database that already holds duplicates, closing nothing', async () => {
  const { readdirSync, readFileSync } = await import('fs');
  const { fileURLToPath } = await import('url');
  const DIR = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'server', 'migrations');
  const files = readdirSync(DIR).filter((f) => f.endsWith('.sql')).sort();
  const old = new Database(':memory:');
  for (const f of files) {
    if (f >= '135-') break;
    old.exec(readFileSync(join(DIR, f), 'utf8'));
  }
  const ins = old.prepare('INSERT INTO enhancement_requests (id, app_slug, user_id, user_name, message, status) VALUES (?,?,?,?,?,?)');
  ins.run(1, 'a', 7, 'u', 'Access request for app "A"', 'new');
  ins.run(2, 'a', 7, 'u', 'Access request for app "A"', 'new');
  ins.run(3, 'a', 7, 'u', 'Access request for app "A"', 'done');
  ins.run(4, 'a', 7, 'u', 'Add dark mode', 'new');
  ins.run(5, 'b', 7, 'u', 'access request for app "B"', 'in_progress');
  old.exec(readFileSync(join(DIR, files.find((f) => f.startsWith('135-'))), 'utf8'));
  const rows = Object.fromEntries(old.prepare('SELECT id, kind, status FROM enhancement_requests').all().map((r) => [r.id, [r.kind, r.status]]));
  assert.deepEqual(rows, {
    1: ['access', 'new'], 2: [null, 'new'], 3: ['access', 'done'], 4: [null, 'new'], 5: ['access', 'in_progress'],
  });
  assert.throws(() => ins.run(6, 'a', 7, 'u', 'x', 'new') && old.prepare("UPDATE enhancement_requests SET kind = 'access' WHERE id = 6").run(), /UNIQUE/);
  old.close();
});
