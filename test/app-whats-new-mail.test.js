import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// When an app ships a new version to production, its owners and app admins get
// one "What's new in <App> vX" mail. Driven through the real deployApp and
// rollbackApp, with the docker shim from test/image-deploy.test.js and a real
// health server, so the trigger is measured where it fires.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-app-wn-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

// ---------------------------------------------------------------------------
// A `docker` that records its argv and answers from a scriptable rule table
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });

// CommonJS on purpose: the file is named `docker` with no extension, so Node
// parses it as CJS and an `import` here would be a syntax error at spawn time —
// surfacing as an unexplained docker failure rather than as a test error.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || "");\n' +
  '    process.stderr.write(r.stderr || "");\n' +
  '    process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

let digest = `sha256:${'a1'.repeat(32)}`;
let failRun = false;
function setRules() {
  writeFileSync(RULES, JSON.stringify([
    ...(failRun ? [{ match: ['run'], stderr: 'boom', code: 1 }] : []),
    ...['a1', 'b2', 'c3', 'd4', 'e5'].map((c) => `odoo@sha256:${c.repeat(32)}`)
      .map((ref) => ({ match: ['image', 'inspect', ref], stdout: `${ref}\n` })),
    { match: ['image', 'inspect'], stdout: `odoo@${digest}\n` },
    { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
    { match: ['images', '--filter'], stdout: '' },
  ]));
}
setRules();

process.env.BASE_URL = 'https://dashboard.example.test';
delete process.env.CRANE_DOMAIN;
const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { deployApp, rollbackApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { queueAppUpgradeMail, renderAppWhatsNew, setAppWhatsNewEmail, APP_WHATS_NEW_SOURCE } = await import('../server/services/appWhatsNewMail.js');

const HEALTH_PATH = '/web/health';
const healthServers = [];
function startHealthServer(port) {
  return new Promise((res) => {
    const s = http.createServer((req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: 'x' }));
    });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
}
let PORTS = null, SLOT = null;
for (let slot = 12545; slot < 12645 && SLOT === null; slot++) {
  const ports = getPortsForSlot(slot);
  const sand = await startHealthServer(ports.sand_be);
  if (!sand) continue;
  const prod = await startHealthServer(ports.prod_be);
  if (!prod) { sand.close(); continue; }
  SLOT = slot; PORTS = ports;
  healthServers.push(sand, prod);
}
assert.ok(SLOT !== null, 'could not find a slot whose sandbox and production ports are both free');

let seq = 0;
function mkUser(name, email, role = 'user', extra = {}) {
  const id = db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?,?,?,?)')
    .run(name, email, role, `hash-awn-${++seq}`).lastInsertRowid;
  if (extra.active === 0) db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(id);
  if (extra.kind) db.prepare('UPDATE users SET kind = ? WHERE id = ?').run(extra.kind, id);
  return id;
}
let app, deployer;
const OWNERS_AND_ADMINS = ['ada@example.com', 'olga@example.com'];

before(() => {
  deployer = mkUser('Deployer', 'deployer@example.com', 'platform_admin');
  const owner = mkUser('Olga', 'olga@example.com');
  const appAdmin = mkUser('Ada', 'ada@example.com');
  const member = mkUser('Mel', 'mel@example.com');
  const agentAdmin = mkUser('Bot', 'bot@example.com', 'user', { kind: 'agent' });
  const goneAdmin = mkUser('Gone', 'gone@example.com', 'user', { active: 0 });
  const noMail = mkUser('NoMail', null);
  db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path) ' +
    "VALUES ('Odoo <&> CRM','odoo-wn',?,'image','odoo:19',8069,?)"
  ).run(SLOT, HEALTH_PATH);
  app = db.prepare("SELECT * FROM apps WHERE slug = 'odoo-wn'").get();
  const grant = db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)');
  grant.run(app.id, owner, 'owner');
  grant.run(app.id, appAdmin, 'admin');
  grant.run(app.id, member, 'user');
  grant.run(app.id, agentAdmin, 'admin');
  grant.run(app.id, goneAdmin, 'admin');
  grant.run(app.id, noMail, 'owner');
});

after(() => {
  for (const s of healthServers) { s.closeAllConnections?.(); s.unref(); s.close(); }
});

const mails = () => db.prepare('SELECT * FROM email_queue WHERE source = ? ORDER BY id').all(APP_WHATS_NEW_SOURCE);
const rowFor = (id) => db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);

async function deploy(env, tag, d) {
  if (tag) {
    db.prepare('UPDATE apps SET image_ref = ? WHERE id = ?').run(`odoo:${tag}`, app.id);
    app = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  }
  if (d) { digest = d; setRules(); }
  const id = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)")
    .run(app.id, env, deployer).lastInsertRowid;
  try { await deployApp(id, app, env, PORTS); } catch (_) {}
  return id;
}
const dig = (c) => `sha256:${c.repeat(32)}`;

test('the first production deploy is not an upgrade: no mail', async () => {
  const id = await deploy('production', '19', dig('a1'));
  assert.equal(rowFor(id).status, 'live', rowFor(id).log);
  assert.equal(rowFor(id).version, '19');
  assert.equal(mails().length, 0);
});

test('a sandbox deploy of a new version sends nothing', async () => {
  const id = await deploy('sandbox', '20', dig('b2'));
  assert.equal(rowFor(id).status, 'live', rowFor(id).log);
  assert.equal(mails().length, 0);
});

test('a production deploy of a new version mails owners and app admins once, not members, agents or deactivated users', async () => {
  const id = await deploy('production', '20', dig('b2'));
  assert.equal(rowFor(id).status, 'live', rowFor(id).log);
  const q = mails();
  assert.deepEqual(q.map((m) => m.to_email).sort(), OWNERS_AND_ADMINS);
  for (const m of q) {
    assert.equal(m.app_id, app.id);
    assert.equal(m.env, 'production');
    assert.equal(m.idempotency_key, `app-whats-new:20:${m.to_email}`);
    assert.equal(m.subject, "[AppCrane] What's new in Odoo <&> CRM v20");
    assert.match(m.body_text, /Odoo <&> CRM was updated to v20\./);
    assert.match(m.body_text, /No release notes were written for this version\./);
    assert.match(m.body_text, /Open Odoo <&> CRM: https:\/\/dashboard\.example\.test\/launch\/odoo-wn/);
    assert.match(m.body_html, /Odoo &lt;&amp;&gt; CRM was updated/);
    assert.doesNotMatch(m.body_html, /Odoo <&>/);
    assert.match(m.body_html, /href="https:\/\/dashboard\.example\.test\/launch\/odoo-wn"/);
  }
});

test('the same version deployed again sends nothing more', async () => {
  const before = mails().length;
  const id = await deploy('production', '20', dig('b2'));
  assert.equal(rowFor(id).status, 'live', rowFor(id).log);
  assert.equal(mails().length, before);
});

test('a failed production deploy of a new version sends nothing', async () => {
  const before = mails().length;
  failRun = true;
  const id = await deploy('production', '21', dig('c3'));
  failRun = false; setRules();
  assert.equal(rowFor(id).status, 'failed');
  assert.equal(mails().length, before);
});

test('running the hook again for a mailed deployment is idempotent', async () => {
  const live = db.prepare("SELECT id FROM deployments WHERE app_id = ? AND env = 'production' AND version = '20' AND status = 'live' ORDER BY id LIMIT 1").get(app.id);
  db.prepare("UPDATE deployments SET status = 'failed' WHERE app_id = ? AND env = 'production' AND version = '20' AND id != ?").run(app.id, live.id);
  const before = mails().length;
  const r = queueAppUpgradeMail({ db, app, deployId: live.id });
  assert.equal(r.status, 'sent');
  assert.equal(r.sent, 0);
  assert.equal(r.skipped, OWNERS_AND_ADMINS.length);
  assert.equal(mails().length, before);
});

test('a rollback sends nothing, and neither does rolling forward to a version already announced', async () => {
  const before = mails().length;
  const target = db.prepare("SELECT id FROM deployments WHERE app_id = ? AND env = 'production' AND version = '19'").get(app.id);
  const r = await rollbackApp(app, 'production', target.id, deployer);
  assert.equal(rowFor(r.deployment_id).status, 'live', rowFor(r.deployment_id).log);
  assert.equal(rowFor(r.deployment_id).commit_hash, dig('a1'), 'fixture: the rollback restored v19\'s digest');
  assert.equal(mails().length, before, 'rollback mailed');
  const id = await deploy('production', '20', dig('b2'));
  assert.equal(rowFor(id).status, 'live');
  assert.equal(mails().length, before, 'roll-forward mailed');
});

test('the per-app switch turns it off', async () => {
  setAppWhatsNewEmail(db, app.id, false);
  const before = mails().length;
  const id = await deploy('production', '22', dig('d4'));
  assert.equal(rowFor(id).status, 'live');
  assert.equal(mails().length, before);
  setAppWhatsNewEmail(db, app.id, true);
});

test('the deploy still succeeds when queueing the mail throws', async () => {
  // With app_settings gone, reading the per-app switch throws inside the hook.
  db.exec('ALTER TABLE app_settings RENAME TO app_settings_parked');
  let id;
  try {
    id = await deploy('production', '23', dig('e5'));
  } finally {
    db.exec('ALTER TABLE app_settings_parked RENAME TO app_settings');
  }
  assert.equal(rowFor(id).status, 'live', rowFor(id).log);
  assert.equal(mails().filter((m) => m.idempotency_key.startsWith('app-whats-new:23:')).length, 0);
});

test("the mail carries the app's What's New text, escaped, in AppCrane's colours", () => {
  const { subject, text, html } = renderAppWhatsNew({
    app: { name: 'Billing', slug: 'billing' }, version: '1.4.0', name: 'Olga',
    notes: 'Invoices export to CSV\n<script>alert(1)</script> & faster search',
  });
  assert.equal(subject, "[AppCrane] What's new in Billing v1.4.0");
  assert.match(text, /What's new in v1\.4\.0:\nInvoices export to CSV\n<script>alert\(1\)<\/script> & faster search\n/);
  assert.match(html, /Invoices export to CSV<br>&lt;script&gt;alert\(1\)&lt;\/script&gt; &amp; faster search/);
  assert.doesNotMatch(html, /<script/);
  for (const colour of ['#1a1d27', '#3b82f6', '#2563eb']) assert.ok(html.includes(colour), `brand colour ${colour} missing`);
  assert.match(html, />App<\/span><span[^>]*>Crane<\/span>/);
  assert.match(html, /You get this because you own or administer Billing on AppCrane\./);
});
