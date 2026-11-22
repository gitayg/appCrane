import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// EU AI Act deployer records: the intake AI-use answer (stored, audited,
// owner-editable, Annex III gating production like confidential), the
// AI-literacy acknowledgement, the AI-system inventory from LLM gateway rows,
// the log-retention floor, the transparency notice, and the evidence pack.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-aiact-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

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
const { submitIntake, intakeGate } = await import('../server/services/appIntake.js');
const rc = await import('../server/services/releaseCheck.js');
const { pruneLlmUsage, AI_LOG_FLOOR_DAYS } = await import('../server/services/aiAct/retention.js');
const { aiNoticeEnv } = await import('../server/services/aiAct/transparency.js');
const { STATEMENT_VERSION } = await import('../server/services/aiAct/literacy.js');
const { extractTar } = await import('../server/services/backupFiles.js');
const ep = await import('../server/services/evidencePack/index.js');
const { _setOptionalModulesForTests } = await import('../server/services/evidencePack/optional.js');

rc._setReleaseCheckDepsForTests({ scanApp: async () => ({ status: 'ok', findings_json: null }), scanTree: async () => ({ status: 'ok', findings_json: null }) });

function mkUser(name, role) {
  const key = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,username,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,?,1,'human')")
    .run(name, name.toLowerCase(), `${name.toLowerCase()}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
}
const ADMIN = mkUser('Ada', 'platform_admin');
const OWNER = mkUser('Owen', 'user');
const MEMBER = mkUser('Mia', 'user');
const OUTSIDER = mkUser('Otto', 'user');

const { getNextSlot } = await import('../server/services/portAllocator.js');
function makeApp(slug, { level = 'internal' } = {}) {
  const id = Number(db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES (?, ?, ?, 'github', NULL)").run(slug, slug, getNextSlot(db)).lastInsertRowid);
  for (const env of ['production', 'sandbox']) db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(id, OWNER.id);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(id, MEMBER.id);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  submitIntake(app, { data_classification: level, owner: OWNER.id, db });
  return app;
}

let server;
let BASE;
before(async () => {
  const api = express();
  api.use(express.json());
  api.use('/api/identity', (await import('../server/routes/identity.js')).default);
  api.use('/api', (await import('../server/routes/intake.js')).default);
  api.use('/api', (await import('../server/routes/releaseCheck.js')).default);
  api.use('/api', (await import('../server/routes/aiAct.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  _setOptionalModulesForTests(null);
  server?.closeAllConnections?.();
  server?.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function call(method, path, key, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, body: json, text, headers: r.headers };
}

const audits = (appId, action) => db.prepare('SELECT detail FROM audit_log WHERE app_id IS ? AND action = ? ORDER BY id').all(appId, action).map((r) => JSON.parse(r.detail));

test('AI use: stored and audited, owners edit, members and outsiders cannot, the literacy statement is acknowledged once', async () => {
  const app = makeApp('ai-cls');

  assert.equal((await call('GET', '/api/apps/ai-cls/ai-act', OUTSIDER.key)).status, 403);
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', OUTSIDER.key, { ai_use: 'none' })).status, 403);
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', MEMBER.key, { ai_use: 'none' })).status, 403);
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-notice', MEMBER.key, { enabled: true })).status, 403);

  const view = await call('GET', '/api/apps/ai-cls/ai-act', MEMBER.key);
  assert.equal(view.status, 200);
  assert.equal(view.body.ai.ai_use, null);
  assert.equal(view.body.can_edit, false);
  assert.equal(view.body.options.annex_iii_categories.length, 8);

  const none = await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'none' });
  assert.equal(none.status, 200, 'answering none needs no acknowledgement');
  assert.equal(none.body.ai.ai_use, 'none');

  const blocked = await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'assistive' });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.body.error.code, 'AI_LITERACY_ACK_REQUIRED');
  assert.equal(blocked.body.error.statement.version, STATEMENT_VERSION);
  assert.equal(db.prepare('SELECT ai_use FROM app_ai_profile WHERE app_id = ?').get(app.id).ai_use, 'none', 'a refused change stores nothing');

  assert.equal((await call('POST', '/api/ai-act/literacy/acknowledge', OWNER.key, { version: 'old' })).status, 409);
  const ack = await call('POST', '/api/ai-act/literacy/acknowledge', OWNER.key, { version: STATEMENT_VERSION });
  assert.equal(ack.status, 201);
  assert.equal(ack.body.acknowledged, true);
  const again = await call('POST', '/api/ai-act/literacy/acknowledge', OWNER.key, { version: STATEMENT_VERSION });
  assert.equal(again.status, 200);
  assert.equal(again.body.created, false);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM ai_literacy_acks WHERE user_id = ?').get(OWNER.id).n, 1);
  assert.equal(audits(null, 'ai-literacy-acknowledge').length, 1);

  const set = await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'assistive' });
  assert.equal(set.status, 200);
  const people = await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'decisions_about_people' });
  assert.equal(people.status, 200, 'a second AI classification does not ask again');
  assert.match(people.body.ai.guidance, /Annex III/);
  assert.equal(db.prepare('SELECT ai_use FROM app_ai_profile WHERE app_id = ?').get(app.id).ai_use, 'decisions_about_people');

  const changes = audits(app.id, 'app-ai-use-change');
  assert.deepEqual(changes.map((c) => [c.from, c.to]), [['none', 'assistive'], ['assistive', 'decisions_about_people']]);
  assert.equal(audits(app.id, 'app-ai-use-set').length, 1);

  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'annex_iii' })).status, 400, 'annex_iii needs a category');
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'annex_iii', annex_iii_category: 'astrology' })).status, 400);
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'assistive', annex_iii_category: 'employment' })).status, 400);
  assert.equal((await call('PUT', '/api/apps/ai-cls/ai-use', OWNER.key, { ai_use: 'maybe' })).status, 400);

  const intake = await call('PUT', '/api/apps/ai-cls/intake', OWNER.key, { purpose: 'screening', ai_use: 'assistive' });
  assert.equal(intake.status, 200, 'the intake form carries the AI-use answer');
  assert.equal(intake.body.ai.ai_use, 'assistive');
  assert.equal((await call('GET', '/api/apps/ai-cls/intake', MEMBER.key)).body.ai.ai_use, 'assistive');
});

test('Annex III: an owner\'s answer closes production until a platform admin approves; the release check runs at the confidential policy', async () => {
  const app = makeApp('ai-annex');
  const plain = makeApp('ai-plain');
  assert.equal(intakeGate(db, app).ok, true);

  const rcBefore = await call('GET', '/api/apps/ai-annex/release-check', OWNER.key);
  assert.equal(rcBefore.body.mode, 'warn');

  const set = await call('PUT', '/api/apps/ai-annex/ai-use', OWNER.key, { ai_use: 'annex_iii', annex_iii_category: 'employment' });
  assert.equal(set.status, 200);
  assert.equal(set.body.intake_back_to_review, true);
  assert.equal(set.body.gate.ok, false);
  assert.match(set.body.gate.message, /Annex III/);

  const rcView = await call('GET', '/api/apps/ai-annex/release-check', OWNER.key);
  assert.equal(rcView.body.data_classification, 'internal');
  assert.equal(rcView.body.policy_level, 'confidential');
  assert.equal(rcView.body.mode, 'enforce');

  const run = await call('POST', '/api/apps/ai-annex/release-check/run', OWNER.key, {});
  assert.equal(run.status, 200);
  assert.equal(run.body.release_check.blocked, true);
  assert.equal(run.body.release_check.mode, 'enforce');
  assert.equal(run.body.release_check.checks[0].id, 'intake');
  assert.equal(run.body.release_check.checks[0].status, 'fail');

  const resubmit = await call('PUT', '/api/apps/ai-annex/intake', OWNER.key, { purpose: 'hiring helper' });
  assert.equal(resubmit.status, 200);
  assert.equal(resubmit.body.status, 'pending', 'resubmitting an internal intake does not self-approve an Annex III app');
  const plainResubmit = await call('PUT', '/api/apps/ai-plain/intake', OWNER.key, { purpose: 'notes' });
  assert.equal(plainResubmit.body.status, 'approved', 'the same resubmission approves an app without Annex III');

  assert.equal((await call('POST', '/api/apps/ai-annex/intake/review', OWNER.key, { decision: 'approve' })).status, 403);
  const approve = await call('POST', '/api/apps/ai-annex/intake/review', ADMIN.key, { decision: 'approve' });
  assert.equal(approve.status, 200);
  assert.equal(approve.body.gate.ok, true);
  const run2 = await call('POST', '/api/apps/ai-annex/release-check/run', OWNER.key, {});
  assert.equal(run2.body.release_check.checks[0].status, 'pass');
  assert.equal(plain.id > 0, true);
});

test('lock: a platform admin\'s AI-use answer is locked against the owner, through ai-use and the intake form; the admin can still change it', async () => {
  const app = makeApp('ai-lock');
  await call('POST', '/api/ai-act/literacy/acknowledge', ADMIN.key, { version: STATEMENT_VERSION });
  const set = await call('PUT', '/api/apps/ai-lock/ai-use', ADMIN.key, { ai_use: 'annex_iii', annex_iii_category: 'employment' });
  assert.equal(set.status, 200);
  assert.equal(set.body.ai.locked, true);

  const owner = await call('PUT', '/api/apps/ai-lock/ai-use', OWNER.key, { ai_use: 'none' });
  assert.equal(owner.status, 403);
  assert.equal(owner.body.error.code, 'AI_USE_LOCKED');
  assert.equal(owner.body.error.message, 'A platform admin set the AI use; ask a platform admin to change it');
  const viaIntake = await call('PUT', '/api/apps/ai-lock/intake', OWNER.key, { purpose: 'x', ai_use: 'assistive' });
  assert.equal(viaIntake.status, 403);
  assert.equal(viaIntake.body.error.code, 'AI_USE_LOCKED');
  assert.equal(db.prepare('SELECT ai_use FROM app_ai_profile WHERE app_id = ?').get(app.id).ai_use, 'annex_iii');
  assert.equal(audits(app.id, 'app-ai-use-change-refused').length, 2);

  const same = await call('PUT', '/api/apps/ai-lock/ai-use', OWNER.key, { ai_use: 'annex_iii', annex_iii_category: 'employment' });
  assert.equal(same.status, 200, 'restating the locked answer is not a change');

  const admin = await call('PUT', '/api/apps/ai-lock/ai-use', ADMIN.key, { ai_use: 'assistive' });
  assert.equal(admin.status, 200);
  assert.equal(admin.body.ai.ai_use, 'assistive');
  assert.equal(admin.body.ai.review_required, false, 'a platform admin lowering it needs no further review');
  assert.equal(audits(app.id, 'app-ai-use-change').at(-1).locked, true);
});

test('downgrade: an owner lowering the AI use sends the intake back for review and production stays refused until a platform admin approves', async () => {
  const app = makeApp('ai-down');
  await call('POST', '/api/ai-act/literacy/acknowledge', OWNER.key, { version: STATEMENT_VERSION });
  await call('PUT', '/api/apps/ai-down/ai-use', OWNER.key, { ai_use: 'annex_iii', annex_iii_category: 'education' });
  assert.equal((await call('POST', '/api/apps/ai-down/intake/review', ADMIN.key, { decision: 'approve' })).body.gate.ok, true);

  const down = await call('PUT', '/api/apps/ai-down/ai-use', OWNER.key, { ai_use: 'assistive' });
  assert.equal(down.status, 200);
  assert.equal(down.body.intake_back_to_review, true);
  assert.equal(down.body.ai.review_required, true);
  assert.equal(down.body.gate.ok, false);
  assert.match(down.body.gate.message, /lowered/);
  const last = audits(app.id, 'app-ai-use-change').at(-1);
  assert.deepEqual([last.from, last.to, last.downgrade, last.intake_back_to_review], ['annex_iii', 'assistive', true, true]);
  const run = await call('POST', '/api/apps/ai-down/release-check/run', OWNER.key, {});
  assert.equal(run.body.release_check.blocked, true);
  assert.equal(run.body.release_check.checks[0].status, 'fail');
  const resubmit = await call('PUT', '/api/apps/ai-down/intake', OWNER.key, { purpose: 'still assistive' });
  assert.equal(resubmit.body.status, 'pending', 'resubmitting does not clear the review');

  await call('POST', '/api/apps/ai-down/intake/review', ADMIN.key, { decision: 'approve' });
  assert.equal(intakeGate(db, app).ok, true);
  assert.equal((await call('GET', '/api/apps/ai-down/ai-act', OWNER.key)).body.ai.review_required, false, 'the approval clears the review');
  assert.equal((await call('PUT', '/api/apps/ai-down/intake', OWNER.key, { purpose: 'after approval' })).body.status, 'approved', 'a later resubmission is not held');
  assert.equal((await call('POST', '/api/apps/ai-down/release-check/run', OWNER.key, {})).body.release_check.checks[0].status, 'pass');

  const none = await call('PUT', '/api/apps/ai-down/ai-use', OWNER.key, { ai_use: 'none' });
  assert.equal(none.body.gate.ok, false, 'assistive to none is a downgrade too');

  const up = makeApp('ai-up');
  await call('PUT', '/api/apps/ai-up/ai-use', OWNER.key, { ai_use: 'none' });
  const upgrade = await call('PUT', '/api/apps/ai-up/ai-use', OWNER.key, { ai_use: 'decisions_about_people' });
  assert.equal(upgrade.body.gate.ok, true, 'an upgrade below Annex III keeps production open');
  assert.equal(up.id > 0, true);
});

test('downgrade through the intake form behaves the same', async () => {
  const app = makeApp('ai-down-intake');
  await call('PUT', '/api/apps/ai-down-intake/ai-use', OWNER.key, { ai_use: 'decisions_about_people' });
  assert.equal(intakeGate(db, app).ok, true);
  const r = await call('PUT', '/api/apps/ai-down-intake/intake', OWNER.key, { purpose: 'notes', ai_use: 'none' });
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'pending');
  assert.equal(r.body.gate.ok, false);
  assert.equal(r.body.ai.review_required, true);
  assert.equal((await call('POST', '/api/apps/ai-down-intake/release-check/run', OWNER.key, {})).body.release_check.blocked, true);
  assert.equal(audits(app.id, 'app-ai-use-change').at(-1).downgrade, true);
  await call('POST', '/api/apps/ai-down-intake/intake/review', ADMIN.key, { decision: 'approve' });
  assert.equal(intakeGate(db, app).ok, true);
});

test('literacy gate: an AI app none of whose owners acknowledged the current statement cannot reach production', async () => {
  const app = makeApp('ai-noack');
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use, ai_use_set_by, ai_use_set_at) VALUES (?, 'assistive', ?, datetime('now'))").run(app.id, MEMBER.id);
  db.prepare('DELETE FROM ai_literacy_acks WHERE user_id = ?').run(OWNER.id);
  const g = intakeGate(db, app);
  assert.equal(g.ok, false);
  assert.equal(g.ai_literacy_ack, false);
  const run = await call('POST', '/api/apps/ai-noack/release-check/run', OWNER.key, {});
  assert.equal(run.body.release_check.blocked, true);

  await call('POST', '/api/ai-act/literacy/acknowledge', OWNER.key, { version: STATEMENT_VERSION });
  assert.equal(intakeGate(db, app).ok, true);
});

test('inventory: derived from gateway rows, joined with the intake, mismatch flagged; platform admin only; CSV export', async () => {
  const declaredNone = makeApp('inv-none');
  const unanswered = makeApp('inv-unanswered');
  const assistive = makeApp('inv-ai');
  const quiet = makeApp('inv-quiet');
  makeApp('inv-absent');
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use) VALUES (?, 'none')").run(declaredNone.id);
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use, ai_use_set_by) VALUES (?, 'assistive', ?)").run(assistive.id, OWNER.id);
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use, annex_iii_category, ai_use_set_by) VALUES (?, 'annex_iii', 'education', ?)").run(quiet.id, OWNER.id);
  const row = db.prepare(`INSERT INTO llm_gateway_usage (app_id, env, provider, endpoint, model, status, outcome, input_tokens, output_tokens, cost_usd, created_at)
    VALUES (?, 'production', ?, '/v1/messages', ?, 200, ?, 10, 5, 0.01, ?)`);
  row.run(declaredNone.id, 'anthropic', 'claude-x', 'ok', '2026-10-01 10:00:00');
  row.run(declaredNone.id, 'openai', 'gpt-y', 'ok', '2026-10-05 10:00:00');
  row.run(declaredNone.id, 'anthropic', 'claude-x', 'refused', '2026-10-03 10:00:00');
  row.run(unanswered.id, 'openai', 'gpt-y', 'ok', '2026-10-02 09:00:00');
  row.run(assistive.id, 'anthropic', 'claude-z', 'ok', '2026-10-04 09:00:00');

  assert.equal((await call('GET', '/api/ai-act/inventory', OWNER.key)).status, 403);
  assert.equal((await call('GET', '/api/ai-act/inventory?format=csv', MEMBER.key)).status, 403);
  const inv = await call('GET', '/api/ai-act/inventory', ADMIN.key);
  assert.equal(inv.status, 200);
  const by = Object.fromEntries(inv.body.apps.map((a) => [a.app, a]));
  assert.equal(by['inv-absent'], undefined, 'no traffic and no AI answer: not an AI system');
  assert.deepEqual(by['inv-none'].providers, ['anthropic', 'openai']);
  assert.deepEqual(by['inv-none'].models, ['claude-x', 'gpt-y']);
  assert.equal(by['inv-none'].calls, 3);
  assert.equal(by['inv-none'].refused_calls, 1);
  assert.equal(by['inv-none'].first_seen, '2026-10-01 10:00:00');
  assert.equal(by['inv-none'].last_seen, '2026-10-05 10:00:00');
  assert.equal(by['inv-none'].mismatch, true);
  assert.equal(by['inv-none'].mismatch_reason, 'gateway_traffic_but_intake_says_none');
  assert.equal(by['inv-unanswered'].mismatch_reason, 'gateway_traffic_but_ai_use_not_answered');
  assert.equal(by['inv-ai'].mismatch, false);
  assert.equal(by['inv-ai'].llm_log_retention_days, AI_LOG_FLOOR_DAYS);
  assert.equal(by['inv-quiet'].calls, 0);
  assert.equal(by['inv-quiet'].annex_iii_category, 'education');
  assert.equal(by['inv-quiet'].mismatch, false);

  const csv = await call('GET', '/api/ai-act/inventory?format=csv', ADMIN.key);
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-type'), /text\/csv/);
  const lines = csv.text.trim().split('\r\n');
  assert.match(lines[0], /^app,name,ai_use,/);
  assert.ok(lines.some((l) => l.startsWith('inv-none,') && l.includes('anthropic openai') && l.includes('gateway_traffic_but_intake_says_none')));
});

test('retention: AI apps keep gateway logs at least 184 days whatever the setting; other apps follow the setting (injected clock)', async () => {
  const ai = makeApp('ret-ai');
  const plain = makeApp('ret-plain');
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use, ai_use_set_by) VALUES (?, 'decisions_about_people', ?)").run(ai.id, OWNER.id);

  assert.equal((await call('PUT', '/api/ai-act/retention', OWNER.key, { days: 30 })).status, 403);
  assert.equal((await call('PUT', '/api/ai-act/retention', ADMIN.key, { days: 0 })).status, 400);
  const put = await call('PUT', '/api/ai-act/retention', ADMIN.key, { days: 30 });
  assert.equal(put.status, 200);
  assert.equal(put.body.configured_days, 30);
  assert.equal(put.body.ai_effective_days, 184);
  assert.equal(audits(null, 'llm-gateway-retention-change').at(-1).to, 30);

  assert.equal((await call('GET', '/api/apps/ret-ai/ai-act', MEMBER.key)).body.retention.llm_gateway_logs_days, 184);
  const plainView = (await call('GET', '/api/apps/ret-plain/ai-act', MEMBER.key)).body.retention;
  assert.equal(plainView.llm_gateway_logs_days, 30);
  assert.equal(plainView.floor_applied, false);

  const NOW = Date.parse('2027-06-01T00:00:00Z');
  const at = (days) => new Date(NOW - days * 86_400_000).toISOString().replace('T', ' ').slice(0, 19);
  const ins = db.prepare("INSERT INTO llm_gateway_usage (app_id, env, provider, endpoint, model, outcome, created_at) VALUES (?, 'production', 'anthropic', '/v1/messages', 'm', 'ok', ?)");
  for (const d of [10, 60, 170, 200]) { ins.run(ai.id, at(d)); ins.run(plain.id, at(d)); }

  const r = pruneLlmUsage({ now: NOW, db });
  assert.equal(r.ai_days, 184);
  const left = (id) => db.prepare('SELECT created_at FROM llm_gateway_usage WHERE app_id = ? ORDER BY created_at DESC').all(id).map((x) => x.created_at);
  assert.deepEqual(left(ai.id), [at(10), at(60), at(170)], 'AI app: rows under six months stay, the 200-day row goes');
  assert.deepEqual(left(plain.id), [at(10)], 'other app: the 30-day setting applies');

  await call('PUT', '/api/ai-act/retention', ADMIN.key, { days: 400 });
  ins.run(ai.id, at(300));
  pruneLlmUsage({ now: NOW, db });
  assert.ok(left(ai.id).includes(at(300)), 'a longer setting than the floor applies to AI apps too');
});

test('retention: the gateway prune that runs every 500 recorded calls applies the floor', async () => {
  const { recordUsage } = await import('../server/services/llmGateway/usage.js');
  const ai = makeApp('ret-gw-ai');
  const plain = makeApp('ret-gw-plain');
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use, ai_use_set_by) VALUES (?, 'assistive', ?)").run(ai.id, OWNER.id);
  await call('PUT', '/api/ai-act/retention', ADMIN.key, { days: 90 });
  const old = new Date(Date.now() - 150 * 86_400_000).toISOString().replace('T', ' ').slice(0, 19);
  const ins = db.prepare("INSERT INTO llm_gateway_usage (app_id, env, provider, endpoint, model, outcome, created_at) VALUES (?, 'production', 'anthropic', '/v1/messages', 'm', 'ok', ?)");
  ins.run(ai.id, old);
  ins.run(plain.id, old);
  for (let i = 0; i < 500; i++) recordUsage({ appId: plain.id, env: 'sandbox', provider: 'anthropic', endpoint: '/v1/messages', model: 'm', outcome: 'ok' }, db);
  const has = (id) => db.prepare('SELECT 1 FROM llm_gateway_usage WHERE app_id = ? AND created_at = ?').get(id, old) != null;
  assert.equal(has(ai.id), true, 'a 150-day row of an AI app survives a 90-day setting');
  assert.equal(has(plain.id), false, 'the same row of another app is pruned');
});

test('transparency notice: the toggle changes the identity verify response and the deploy env', async () => {
  const app = makeApp('ai-notice');
  const verify = () => call('GET', '/api/identity/verify?app=ai-notice', MEMBER.key);

  const off = await verify();
  assert.equal(off.status, 200);
  assert.equal(off.body.ai_notice, null);
  assert.deepEqual(aiNoticeEnv(db, app), {});

  assert.equal((await call('PUT', '/api/apps/ai-notice/ai-notice', OWNER.key, { enabled: 'yes' })).status, 400);
  assert.equal((await call('PUT', '/api/apps/ai-notice/ai-notice', OWNER.key, { enabled: true, text: 'x'.repeat(301) })).status, 400);
  const on = await call('PUT', '/api/apps/ai-notice/ai-notice', OWNER.key, { enabled: true });
  assert.equal(on.status, 200);
  assert.deepEqual((await verify()).body.ai_notice, { enabled: true, text: 'You are interacting with an AI system.' });

  await call('PUT', '/api/apps/ai-notice/ai-notice', OWNER.key, { enabled: true, text: 'Answers here are written by an AI model.' });
  assert.deepEqual((await verify()).body.ai_notice, { enabled: true, text: 'Answers here are written by an AI model.' });
  assert.deepEqual(aiNoticeEnv(db, app), { APPCRANE_AI_NOTICE: '1', APPCRANE_AI_NOTICE_TEXT: 'Answers here are written by an AI model.' });
  assert.equal(audits(app.id, 'app-ai-notice-change').length, 2);

  assert.equal((await call('GET', '/api/identity/verify?app=ai-notice', OUTSIDER.key)).status, 403, 'no notice for someone without access');

  await call('PUT', '/api/apps/ai-notice/ai-notice', OWNER.key, { enabled: false });
  assert.equal((await verify()).body.ai_notice, null);
});

test('evidence pack carries the AI inventory, AI-use changes, literacy acknowledgements and retention', async () => {
  _setOptionalModulesForTests({ accessReviews: null, auditChain: null, releaseCheck: null, siem: null });
  const epApp = makeApp('ep-none');
  db.prepare("INSERT INTO app_ai_profile (app_id, ai_use) VALUES (?, 'none')").run(epApp.id);
  db.prepare("INSERT INTO llm_gateway_usage (app_id, env, provider, endpoint, model, outcome) VALUES (?, 'production', 'openai', '/v1/chat/completions', 'gpt-y', 'ok')").run(epApp.id);
  const today = new Date().toISOString().slice(0, 10);
  const { pack, done } = ep.startEvidencePack({ from: today, to: today, user: ADMIN.row });
  await done;
  const p = ep.getPack(pack.id);
  assert.equal(p.status, 'ready', p.error);
  const dir = mkdtempSync(join(tmpdir(), 'crane-aiact-ep-'));
  await extractTar(ep.packFilePath(p.id), dir, { gzip: true });
  const read = (f) => readFileSync(join(dir, f), 'utf8');
  assert.deepEqual(readdirSync(join(dir, 'AI')).sort(), ['ai-inventory.csv', 'ai-literacy-acknowledgements.csv', 'ai-use-changes.csv', 'llm-log-retention.json']);
  assert.match(read('AI/ai-inventory.csv'), /ep-none,.*gateway_traffic_but_intake_says_none/);
  assert.match(read('AI/ai-literacy-acknowledgements.csv'), new RegExp(`${OWNER.id},owen,human,${STATEMENT_VERSION},`));
  assert.match(read('AI/ai-use-changes.csv'), /app-ai-use-change/);
  assert.equal(JSON.parse(read('AI/llm-log-retention.json')).ai_floor_days, 184);
  const manifest = JSON.parse(read('manifest.json'));
  assert.ok(manifest.controls.some((c) => c.id === 'AI.1'));
  assert.ok(read('README.md').includes('AI.1'));
});
