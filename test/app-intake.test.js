import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// App intake with security approval, and data classification: who may set the
// level, that production waits for approval while sandbox does not, the
// approve/reject flow with its e-mail, audit and event, the creation paths
// that submit intake, and the upgrade backfill.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-intake-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
writeFileSync(join(SHIM_DIR, 'caddy'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { submitIntake, intakeGate, reviewIntake } = await import('../server/services/appIntake.js');
const { setClassification } = await import('../server/services/dataClassification.js');
const { callTool } = await import('../server/services/mcpTools.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
const OWNER_KEY = generateApiKey('dhk_user');
const MEMBER_KEY = generateApiKey('dhk_user');
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Ada','ada@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
const ownerId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owen','owen@t.test','user',?,1,'human')").run(hashApiKey(OWNER_KEY)).lastInsertRowid;
const memberId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Mia','mia@t.test','user',?,1,'human')").run(hashApiKey(MEMBER_KEY)).lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(ownerId);
const member = db.prepare('SELECT * FROM users WHERE id = ?').get(memberId);

const { getNextSlot } = await import('../server/services/portAllocator.js');
function makeApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES (?, ?, ?, 'github', NULL)").run(slug, slug, getNextSlot(db)).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(id, ownerId);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(id, memberId);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

let server;
let BASE;
before(async () => {
  const api = express();
  api.use(express.json());
  api.use('/api', (await import('../server/routes/intake.js')).default);
  api.use('/api/apps', (await import('../server/routes/deploy.js')).default);
  api.use('/api/apps', (await import('../server/routes/apps.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  server?.closeAllConnections?.();
  server?.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function call(method, path, key, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: r.status, body: await r.json() };
}

test('owner sets classification on a pending app; a member cannot; lowering an approved app needs a platform admin', async () => {
  const app = makeApp('cls-a');
  submitIntake(app, { data_classification: 'internal', owner: ownerId, db });

  const m = await call('PUT', '/api/apps/cls-a/classification', MEMBER_KEY, { data_classification: 'public' });
  assert.equal(m.status, 403);

  const up = await call('PUT', '/api/apps/cls-a/classification', OWNER_KEY, { data_classification: 'confidential' });
  assert.equal(up.status, 200);
  assert.equal(up.body.classification.level, 'confidential');
  assert.equal(up.body.classification.intake_status, 'pending', 'raising into an approval-required level sends it back for review');

  reviewIntake(db, app, { decision: 'approve' }, admin);
  const down = await call('PUT', '/api/apps/cls-a/classification', OWNER_KEY, { data_classification: 'internal' });
  assert.equal(down.status, 403);
  assert.equal(down.body.error.code, 'CLASSIFICATION_LOWER_NEEDS_ADMIN');

  const bad = await call('PUT', '/api/apps/cls-a/classification', OWNER_KEY, { data_classification: 'secret' });
  assert.equal(bad.status, 400);
});

test('a platform admin override locks the classification against the owner', async () => {
  const app = makeApp('cls-b');
  submitIntake(app, { data_classification: 'internal', owner: ownerId, db });
  const o = await call('PUT', '/api/apps/cls-b/classification', ADMIN_KEY, { data_classification: 'restricted' });
  assert.equal(o.status, 200);
  assert.equal(o.body.classification.locked, true);
  const again = await call('PUT', '/api/apps/cls-b/classification', OWNER_KEY, { data_classification: 'restricted' });
  assert.equal(again.status, 403);
  assert.equal(again.body.error.code, 'CLASSIFICATION_LOCKED');
  const audit = db.prepare("SELECT detail FROM audit_log WHERE app_id = ? AND action = 'app-classification-change'").all(app.id);
  assert.equal(audit.length, 1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM events WHERE app_id = ? AND kind = 'classification.changed'").get(app.id).n, 1);
});

test('a confidential app waits for approval: production refused, sandbox allowed', async () => {
  const app = makeApp('int-a');
  const out = submitIntake(app, { data_classification: 'confidential', purpose: 'Customer list', intake_answers: { personal_data: true }, owner: ownerId, db });
  assert.deepEqual(out, { app_id: app.id, status: 'pending', data_classification: 'confidential', approval_required: true });

  const prod = await call('POST', '/api/apps/int-a/deploy/production', ADMIN_KEY, {});
  assert.equal(prod.status, 403);
  assert.equal(prod.body.error.code, 'INTAKE_NOT_APPROVED');
  assert.match(prod.body.error.message, /waiting for security approval/);
  assert.equal(prod.body.release_check.checks[0].id, 'intake');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(app.id).n, 0);

  const sb = await call('POST', '/api/apps/int-a/deploy/sandbox', ADMIN_KEY, {});
  assert.equal(sb.status, 200, JSON.stringify(sb.body));
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'sandbox'").get(app.id).n, 1);

  const mcp = await callTool(admin, 'appcrane_deploy', { slug: 'int-a', env: 'production' }).then(() => null, (e) => e);
  assert.ok(mcp, 'MCP production deploy must be refused');
  assert.equal(mcp.code, 'INTAKE_NOT_APPROVED');
});

test('public and internal apps are approved on submission by default', () => {
  const app = makeApp('int-b');
  assert.equal(submitIntake(app, { data_classification: 'internal', owner: ownerId, db }).status, 'approved');
  assert.equal(intakeGate(db, app).ok, true);
});

test('reject needs a comment, mails the owner, audits and records an event; approve opens production', async () => {
  const app = makeApp('int-c');
  submitIntake(app, { data_classification: 'restricted', purpose: 'Payroll', owner: ownerId, db });

  const byOwner = await call('POST', '/api/apps/int-c/intake/review', OWNER_KEY, { decision: 'approve' });
  assert.equal(byOwner.status, 403);

  const noComment = await call('POST', '/api/apps/int-c/intake/review', ADMIN_KEY, { decision: 'reject' });
  assert.equal(noComment.status, 400);

  const rej = await call('POST', '/api/apps/int-c/intake/review', ADMIN_KEY, { decision: 'reject', comment: 'List the integrations' });
  assert.equal(rej.status, 200);
  assert.equal(rej.body.intake.status, 'rejected');
  assert.equal(rej.body.gate.ok, false);

  const rejMail = db.prepare("SELECT to_email, subject, body_html, body_text FROM email_queue WHERE app_id = ? AND source = 'intake' AND subject LIKE '%not approved%'").all(app.id);
  assert.equal(rejMail.length, 1);
  assert.equal(rejMail[0].to_email, 'owen@t.test');
  assert.match(rejMail[0].body_text, /List the integrations/);
  assert.match(rejMail[0].body_html, /App<\/span>/);

  const resub = await call('PUT', '/api/apps/int-c/intake', OWNER_KEY, { data_classification: 'restricted', purpose: 'Payroll', external_integrations: 'none' });
  assert.equal(resub.status, 200);
  assert.equal(resub.body.status, 'pending');

  const q = await call('GET', '/api/intake/queue', ADMIN_KEY);
  assert.ok(q.body.items.some((i) => i.slug === 'int-c'));
  assert.equal((await call('GET', '/api/intake/queue', OWNER_KEY)).status, 403);

  const ok = await call('POST', '/api/apps/int-c/intake/review', ADMIN_KEY, { decision: 'approve', comment: 'Fine' });
  assert.equal(ok.body.intake.status, 'approved');
  assert.equal(ok.body.gate.ok, true);
  const okMail = db.prepare("SELECT COUNT(*) n FROM email_queue WHERE app_id = ? AND source = 'intake' AND subject LIKE '%approved for production%'").get(app.id).n;
  assert.equal(okMail, 1);
  const actions = db.prepare("SELECT action FROM audit_log WHERE app_id = ? AND action LIKE 'app-intake-%' ORDER BY id").all(app.id).map((r) => r.action);
  assert.deepEqual(actions, ['app-intake-submit', 'app-intake-reject', 'app-intake-submit', 'app-intake-approve']);
  const kinds = db.prepare("SELECT kind FROM events WHERE app_id = ? AND kind LIKE 'intake.%' ORDER BY id").all(app.id).map((r) => r.kind);
  assert.deepEqual(kinds, ['intake.submitted', 'intake.rejected', 'intake.submitted', 'intake.approved']);
});

test('dashboard creation submits intake from the request body', async () => {
  const r = await call('POST', '/api/apps', ADMIN_KEY, {
    name: 'Made', slug: 'made-dash', source_type: 'github', github_url: 'https://github.com/acme-co/made',
    intake: { data_classification: 'confidential', purpose: 'HR tool', personal_data: true },
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.intake.status, 'pending');
  const row = db.prepare("SELECT i.* FROM app_intake i JOIN apps a ON a.id = i.app_id WHERE a.slug = 'made-dash'").get();
  assert.equal(row.data_classification, 'confidential');
  assert.equal(row.personal_data, 1);

  const bad = await call('POST', '/api/apps', ADMIN_KEY, { name: 'Bad', slug: 'made-bad', github_url: 'https://github.com/acme-co/bad', intake: { data_classification: 'top' } });
  assert.equal(bad.status, 400);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'made-bad'").get().n, 0, 'invalid intake creates nothing');
});

test('MCP appcrane_create_app submits intake', async () => {
  const parse = (r) => JSON.parse(r.content[0].text);
  const out = parse(await callTool(admin, 'appcrane_create_app', {
    name: 'Via MCP', slug: 'made-mcp', github_url: 'https://github.com/acme-co/mcp',
    intake: { data_classification: 'restricted', purpose: 'Finance' },
  }));
  assert.equal(out.intake.status, 'pending');
  assert.equal(out.intake.data_classification, 'restricted');
  const def = parse(await callTool(admin, 'appcrane_create_app', { name: 'Plain', slug: 'made-mcp2', github_url: 'https://github.com/acme-co/mcp2' }));
  assert.equal(def.intake.data_classification, 'internal');
  assert.equal(def.intake.status, 'approved');
});

test('upgrade backfill grandfathers existing apps as approved and internal', () => {
  const app = makeApp('legacy');
  db.prepare('DELETE FROM app_intake WHERE app_id = ?').run(app.id);
  const sql = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations', '139-app-intake-release-check.sql'), 'utf8');
  db.exec(sql);
  const row = db.prepare('SELECT status, data_classification, grandfathered FROM app_intake WHERE app_id = ?').get(app.id);
  assert.deepEqual({ ...row }, { status: 'approved', data_classification: 'internal', grandfathered: 1 });
  assert.equal(intakeGate(db, app).ok, true);
  assert.match(intakeGate(db, app).message, /grandfathered/);
});

test('owner may not escape a lock through setClassification directly', () => {
  const app = makeApp('cls-c');
  setClassification(db, app, 'restricted', admin);
  assert.throws(() => setClassification(db, app, 'public', owner), /platform admin set this classification/);
  assert.throws(() => setClassification(db, app, 'public', member), /Only the app owner/);
});

test('Launch badges: levels for the apps the caller can see', async () => {
  const mine = await call('GET', '/api/data-classification/apps', OWNER_KEY);
  assert.equal(mine.status, 200);
  assert.equal(mine.body.levels['int-c'], 'restricted');
  assert.equal(mine.body.levels['made-dash'], undefined, 'not an app the owner was given');
  const all = await call('GET', '/api/data-classification/apps', ADMIN_KEY);
  assert.equal(all.body.levels['made-dash'], 'confidential');
});
