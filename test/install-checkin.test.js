import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The anonymous daily check-in (v2.93.0). What matters most is what it does
// NOT send: the document is a fixed set of counts and versions, and nothing
// that names the host, its apps or its people can be added by accident.
const DIR = mkdtempSync(join(tmpdir(), 'crane-checkin-'));
process.env.DATA_DIR = DIR;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const ck = await import('../server/services/installCheckin.js');
after(() => rmSync(DIR, { recursive: true, force: true }));

// Something identifying in every table the counts read: none of it may leave.
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Secret Person','secret@example.com','platform_admin','h1',1,'human')").run();
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('gone','gone@example.com','user','h2',0,'human')").run();
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('bot','bot@example.com','user','h3',1,'agent')").run();
const appId = db.prepare("INSERT INTO apps (name, slug, slot, github_url) VALUES ('Secret App','secret-app',901,'https://github.com/secret/repo')").run().lastInsertRowid;
db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Other','other-app',902)").run();
db.prepare("INSERT INTO deployments (app_id, env, version, status) VALUES (?, 'production', '1.0.0', 'live')").run(appId);

test('the payload is exactly counts and versions, and names nothing', () => {
  const p = ck.checkinPayload({ version: '9.9.9' });
  assert.deepEqual(Object.keys(p).sort(),
    ['apps', 'apps_deployed', 'arch', 'install_id', 'node', 'os', 'users', 'version'],
    'a field was added to what every install sends home');
  assert.equal(p.apps, 2);
  assert.equal(p.apps_deployed, 1);
  assert.equal(p.users, 1, 'inactive users or agent identities were counted as users');
  assert.equal(p.version, '9.9.9');
  const text = JSON.stringify(p);
  for (const s of ['Secret', 'secret', 'example.com', 'github.com', DIR]) {
    assert.ok(!text.includes(s), `the payload contains ${s}`);
  }
});

test('the install id is random, stable across calls, and stored readable only by AppCrane', () => {
  const a = ck.installId(DIR);
  assert.match(a, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(ck.installId(DIR), a, 'the id changed between calls, so one install would count as many');
  assert.equal(statSync(join(DIR, 'install-id')).mode & 0o777, 0o600);
  assert.notEqual(ck.installId(mkdtempSync(join(tmpdir(), 'crane-checkin2-'))), a);
});

test('every opt-out turns it off, and test runs never send', () => {
  assert.equal(ck.checkinDisabledReason({}), null);
  for (const v of ['off', 'OFF', '0', 'false', 'no', 'disabled']) {
    assert.match(ck.checkinDisabledReason({ APPCRANE_CHECKIN: v }), /APPCRANE_CHECKIN/, v);
  }
  assert.match(ck.checkinDisabledReason({ DO_NOT_TRACK: '1' }), /DO_NOT_TRACK/);
  assert.match(ck.checkinDisabledReason({ NODE_TEST_CONTEXT: 'child-v8' }), /test/);
  assert.ok(ck.checkinDisabledReason(process.env), 'this very test run would have checked in');
});

test('it posts the payload as JSON to the configured URL', async () => {
  let got = null;
  const server = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => { b += c; });
    req.on('end', () => { got = { method: req.method, url: req.url, type: req.headers['content-type'], body: JSON.parse(b) }; res.end('{}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const ok = await ck.sendCheckin({ version: '1.2.3', url: `http://127.0.0.1:${server.address().port}/v1/checkin` });
    assert.equal(ok, true);
    assert.equal(got.method, 'POST');
    assert.equal(got.url, '/v1/checkin');
    assert.equal(got.type, 'application/json');
    assert.equal(got.body.version, '1.2.3');
    assert.equal(got.body.install_id, ck.installId(DIR));
  } finally { server.close(); }
});

test('an unreachable or failing receiver never throws into the platform', async () => {
  assert.equal(await ck.sendCheckin({ version: '1', url: 'http://127.0.0.1:1/v1/checkin' }), false);
  assert.equal(await ck.sendCheckin({ version: '1', fetchImpl: async () => ({ ok: false, status: 500 }) }), false);
  assert.equal(await ck.sendCheckin({ version: '1', fetchImpl: async () => { throw new Error('boom'); } }), false);
});

test('the default destination is ping.appcrane.dev, and the server starts it at boot', () => {
  assert.equal(ck.DEFAULT_CHECKIN_URL, 'https://ping.appcrane.dev/v1/checkin');
  const idx = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  assert.match(idx, /startInstallCheckin\(\{ version: VERSION \}\)/);
});
