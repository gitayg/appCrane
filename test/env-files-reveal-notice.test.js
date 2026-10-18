import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import express from 'express';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The stored .env card shows each file masked with an eye. Listing the files
// must read no content, write no audit row and mail nobody; pressing the eye
// (GET .../env-files/content) must write one env_file.reveal row and send one
// SECRET REVEAL notice to the owners naming that file. Read off a real SMTP
// conversation, the same seam env-single-key-reveal.test.js uses.

const inbox = [];
const smtp = net.createServer((sock) => {
  let buf = ''; let inData = false; let data = ''; let to = [];
  sock.write('220 fake.appcrane.test ESMTP\r\n');
  sock.on('error', () => {});
  sock.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    for (;;) {
      const i = buf.indexOf('\r\n');
      if (i < 0) break;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (inData) {
        if (line === '.') { inData = false; inbox.push({ raw: data, to }); data = ''; to = []; sock.write('250 Ok\r\n'); }
        else data += (line.startsWith('..') ? line.slice(1) : line) + '\r\n';
        continue;
      }
      const cmd = line.split(/[ :]/)[0].toUpperCase();
      if (cmd === 'EHLO' || cmd === 'HELO') sock.write('250-fake.appcrane.test\r\n250 8BITMIME\r\n');
      else if (cmd === 'RCPT') { to.push(line.match(/<([^>]*)>/)?.[1]); sock.write('250 Ok\r\n'); }
      else if (cmd === 'DATA') { inData = true; sock.write('354 go\r\n'); }
      else if (cmd === 'QUIT') { sock.write('221 Bye\r\n'); sock.end(); }
      else sock.write('250 Ok\r\n');
    }
  });
});
await new Promise((res) => smtp.listen(0, '127.0.0.1', res));
process.env.SMTP_HOST = '127.0.0.1';
process.env.SMTP_PORT = String(smtp.address().port);
for (const k of ['SMTP_USER', 'SMTP_PASS', 'GRAPH_TENANT_ID', 'GRAPH_CLIENT_ID', 'GRAPH_CLIENT_SECRET']) delete process.env[k];
const ROOT = mkdtempSync(join(tmpdir(), 'crane-envfile-notice-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '6'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');
const store = await import('../server/services/envFileStore.js');
const routes = (await import('../server/routes/envFiles.js')).default;
initDb();
const db = getDb();

async function craneApp(slug) {
  await lg.createAppRepo(slug);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?, ?, ?, 'managed', 'local', 'main')").run(slug, slug, getNextSlot(db));
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}
const APP = await craneApp('efn-app');
const OTHER = await craneApp('efn-other');

const mk = (name, role, grants = []) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@example.test`, role, hashApiKey(key)).lastInsertRowid;
  for (const [app, appRole] of grants) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, id, appRole);
  return { id, key, name };
};
const OWNER = mk('efn-owner', 'user', [[APP, 'owner']]);
const READER = mk('efn-reader', 'user', [[APP, 'owner']]);
const PLATFORM = mk('efn-platform', 'platform_admin', [[APP, 'user']]);
const APPADMIN = mk('efn-appadmin', 'user', [[APP, 'admin']]);
const MEMBER = mk('efn-member', 'user', [[APP, 'user']]);
const OTHER_OWNER = mk('efn-other-owner', 'user', [[OTHER, 'owner']]);

const CANARY = 'canary-envfile-7c41e2';
store.putStoredEnvFile(db, APP.id, 'sandbox', '.env.local', `TOKEN=${CANARY}\n`);
store.putStoredEnvFile(db, APP.id, 'production', '.env', `DB_PASSWORD=${CANARY}-prod\n`);

const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/apps', routes); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); smtp.close(); rmSync(ROOT, { recursive: true, force: true }); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(who, path) {
  const r = await fetch(`${BASE}${path}`, { headers: { 'x-api-key': who.key } });
  const body = await r.text();
  let json = null; try { json = JSON.parse(body); } catch (_) {}
  return { status: r.status, body, json };
}
const content = (who, env, path, slug = 'efn-app') => call(who, `/api/apps/${slug}/env-files/content?env=${env}&path=${encodeURIComponent(path)}`);
const settle = (ms = 700) => new Promise(r => setTimeout(r, ms));
const decoded = (raw) => raw + '\n' + raw.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
const notices = (from, to) => inbox.slice(from).filter(m => /SECRET REVEAL/.test(m.raw) && (!to || m.to.includes(`${to.name}@example.test`)));
const revealRows = (userId) => db.prepare("SELECT detail FROM audit_log WHERE user_id = ? AND action = 'env_file.reveal' ORDER BY id").all(userId).map(r => JSON.parse(r.detail));
const allRevealRows = () => db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action IN ('env_file.reveal', 'env-reveal', 'secret-reveal')").get().n;

test('listing stored .env files carries no content, writes no reveal row and sends no notice', async () => {
  const before = inbox.length;
  const rowsBefore = allRevealRows();
  for (const who of [OWNER, PLATFORM]) {
    const r = await call(who, '/api/apps/efn-app/env-files');
    assert.equal(r.status, 200, r.body);
    assert.equal(r.json.files.length, 2);
    assert.equal(r.body.includes(CANARY), false, 'the list carried file content');
    for (const f of r.json.files) assert.equal(f.content, undefined);
  }
  await settle();
  assert.equal(allRevealRows(), rowsBefore, 'listing wrote a reveal row');
  assert.equal(notices(before).length, 0, 'listing sent a SECRET REVEAL notice');
});

test('pressing the eye returns that file, writes ONE reveal row and sends ONE notice naming it', async () => {
  await settle();
  const before = inbox.length;
  const r = await content(READER, 'sandbox', '.env.local');
  assert.equal(r.status, 200, r.json?.error?.message);
  assert.ok(r.json.content === `TOKEN=${CANARY}\n`, 'the reveal did not return the stored content');
  assert.equal(r.body.includes(`${CANARY}-prod`), false, 'the reveal carried another file');
  assert.deepEqual(revealRows(READER.id), [{ env: 'sandbox', path: '.env.local' }]);

  const deadline = Date.now() + 15_000;
  while (!notices(before, OWNER).length && Date.now() < deadline) await settle(50);
  await settle();
  const mails = notices(before, OWNER);
  assert.equal(mails.length, 1, `expected one SECRET REVEAL notice to the owner, got ${mails.length}`);
  const text = decoded(mails[0].raw);
  assert.ok(text.includes('stored .env file .env.local'), 'the notice does not name the revealed file');
  assert.equal(text.includes(CANARY), false, 'the notice carried the file content');
});

test('reveal authz: owner and assigned platform admin allowed; app admin, member and another app\'s owner refused', async () => {
  for (const who of [OWNER, PLATFORM]) {
    const r = await content(who, 'production', '.env');
    assert.equal(r.status, 200, `${who.name}: ${r.json?.error?.message}`);
  }
  for (const who of [APPADMIN, MEMBER, OTHER_OWNER]) {
    const rowsBefore = revealRows(who.id).length;
    const r = await content(who, 'production', '.env');
    assert.equal(r.status, 403, `${who.name} got ${r.status}`);
    assert.equal(r.body.includes(CANARY), false, `${who.name}'s refusal carried content`);
    assert.equal(revealRows(who.id).length, rowsBefore, `${who.name}'s refusal was logged as a reveal`);
  }
  const viaOther = await content(OTHER_OWNER, 'sandbox', '.env.local', 'efn-other');
  assert.equal(viaOther.status, 404, 'a file of another app resolved through the caller\'s own app');
  assert.equal(viaOther.body.includes(CANARY), false);
});
