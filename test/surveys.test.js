import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// In-app surveys (migration 127): admin-only config, when a survey is due, one
// answer per round, answer validation, the mail to owners + platform admins,
// the NPS math and who may read results. Driven through the real router,
// requireAuth and a real database; the e-mail queue is the real one too.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-surveys-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'https://dashboard.example.test';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
initDb();
const db = getDb();
const surveysRouter = (await import('../server/routes/surveys.js')).default;
const { mailer } = await import('../server/routes/surveys.js');
const { queueSurveyResponseMail, surveyMailRecipients } = await import('../server/services/surveyMail.js');
const { npsOf } = await import('../server/services/surveyResults.js');
const { pendingSurvey, sqlTs } = await import('../server/services/surveys.js');

const keys = {};
const ids = {};
function mkUser(tag, { email = `${tag}@example.com`, role = 'user', kind = 'human', active = 1 } = {}) {
  const key = generateApiKey('dhk_admin');
  ids[tag] = Number(db.prepare('INSERT INTO users (name, email, role, api_key_hash, active, kind) VALUES (?,?,?,?,?,?)')
    .run(tag[0].toUpperCase() + tag.slice(1), email, role, hashApiKey(key), active, kind).lastInsertRowid);
  keys[tag] = key;
  return ids[tag];
}
let slot = 0;
function mkApp(slug) {
  return Number(db.prepare('INSERT INTO apps (name, slug, slot, source_type) VALUES (?,?,?,?)')
    .run(slug.toUpperCase(), slug, ++slot, 'managed').lastInsertRowid);
}
const grant = (appId, userId, role) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?,?,?)').run(appId, userId, role);

let server, base, alpha, beta;
before(async () => {
  mkUser('root', { role: 'platform_admin' });
  mkUser('root2', { role: 'platform_admin', email: 'ROOT@example.com' }); // same address, other case
  mkUser('owner');
  mkUser('owner2');
  mkUser('member');
  mkUser('stranger');
  mkUser('bot', { kind: 'agent' });
  mkUser('gone', { role: 'platform_admin', active: 0 });
  alpha = mkApp('alpha');
  beta = mkApp('beta');
  grant(alpha, ids.owner, 'owner');
  grant(alpha, ids.member, 'user');
  grant(alpha, ids.bot, 'user');
  grant(beta, ids.owner2, 'owner');
  grant(beta, ids.member, 'user');

  const app = express();
  app.use(express.json());
  app.use('/api/surveys', surveysRouter);
  app.use(errorHandler);
  await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server?.close());

async function call(who, method, path, body) {
  const r = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json', ...(who ? { 'x-api-key': keys[who] } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* csv */ }
  return { status: r.status, json, text };
}

const NPS_SURVEY = {
  name: 'Quarterly NPS',
  enabled: true,
  all_apps: true,
  frequency_days: 90,
  min_visits: 0,
  min_days: 0,
  snooze_days: 7,
  questions: [
    { kind: 'nps' },
    { kind: 'scale', prompt: 'How easy was it?', scale_min: 1, scale_max: 5, required: false },
    { kind: 'choice', prompt: 'Role?', options: ['Dev', 'Ops'], required: false },
    { kind: 'text', prompt: 'Anything else?', max_length: 50, required: false },
  ],
};

let survey;
const resetState = () => {
  db.prepare('DELETE FROM survey_responses').run();
  db.prepare('DELETE FROM survey_snoozes').run();
  db.prepare('DELETE FROM survey_app_visits').run();
  db.prepare('DELETE FROM email_queue').run();
};
const answersFor = (s, nps, extra = {}) => ({ [s.questions[0].id]: nps, ...extra });

test('survey config is platform-admin only', async () => {
  for (const who of ['owner', 'member', 'stranger']) {
    assert.equal((await call(who, 'GET', '/api/surveys/admin')).status, 403, `${who} listed surveys`);
    assert.equal((await call(who, 'POST', '/api/surveys/admin', NPS_SURVEY)).status, 403, `${who} created a survey`);
  }
  assert.equal((await call(null, 'GET', '/api/surveys/admin')).status, 401);
  const bad = await call('root', 'POST', '/api/surveys/admin', { ...NPS_SURVEY, questions: [{ kind: 'nps' }, { kind: 'nps' }] });
  assert.equal(bad.status, 400, 'two NPS questions accepted');
  const created = await call('root', 'POST', '/api/surveys/admin', NPS_SURVEY);
  assert.equal(created.status, 201, created.text);
  survey = created.json.survey;
  assert.equal(survey.questions.length, 4);
  assert.equal(survey.questions[0].scale_max, 10);
  assert.equal((await call('owner', 'PUT', `/api/surveys/admin/${survey.id}`, NPS_SURVEY)).status, 403);
  assert.equal((await call('owner', 'DELETE', `/api/surveys/admin/${survey.id}`)).status, 403);
  assert.equal((await call('root', 'GET', '/api/surveys/admin')).json.surveys.length, 1);
});

test('pending returns a survey only when it is due', async () => {
  resetState();
  const pend = async (who = 'member', app = 'alpha') => (await call(who, 'GET', `/api/surveys/pending?app=${app}`));

  const due = await pend();
  assert.equal(due.status, 200);
  assert.equal(due.json.survey?.id, survey.id, 'not due on a targeted, enabled survey with no visit rule');
  assert.match(due.json.survey.questions[0].prompt, /recommend ALPHA/, 'the {app} placeholder is not filled');

  assert.equal((await pend('stranger')).status, 403, 'someone without the app got its survey');
  assert.equal((await pend('bot')).json.survey, null, 'an agent was surveyed');

  // Snooze hides it; the snooze running out shows it again.
  assert.equal((await call('member', 'POST', `/api/surveys/${survey.id}/snooze`, { app: 'alpha' })).status, 200);
  assert.equal((await pend()).json.survey, null, 'shown while snoozed');
  db.prepare('UPDATE survey_snoozes SET snoozed_until = ?').run(sqlTs(Date.now() - 1000));
  assert.equal((await pend()).json.survey?.id, survey.id, 'still hidden after the snooze ran out');

  // Answered: hidden for the round, back after frequency_days.
  const r = await call('member', 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers: answersFor(survey, 8) });
  assert.equal(r.status, 201, r.text);
  assert.equal((await pend()).json.survey, null, 'shown again right after an answer');
  assert.equal((await pend('member', 'beta')).json.survey?.id, survey.id, 'an answer on one app hid it on another');
  db.prepare('UPDATE survey_responses SET submitted_at = ?').run(sqlTs(Date.now() - 91 * 86_400_000));
  assert.equal((await pend()).json.survey?.id, survey.id, 'not asked again after the round ended');

  // Turned off, and not targeted.
  const off = { ...NPS_SURVEY, enabled: false };
  await call('root', 'PUT', `/api/surveys/admin/${survey.id}`, off);
  survey = (await call('root', 'GET', '/api/surveys/admin')).json.surveys[0];
  assert.equal((await pend()).json.survey, null, 'an off survey was shown');
  await call('root', 'PUT', `/api/surveys/admin/${survey.id}`, { ...NPS_SURVEY, all_apps: false, apps: ['beta'] });
  survey = (await call('root', 'GET', '/api/surveys/admin')).json.surveys[0];
  assert.equal((await pend('member', 'alpha')).json.survey, null, 'shown on an app the survey does not target');
  assert.equal((await pend('member', 'beta')).json.survey?.id, survey.id);
  await call('root', 'PUT', `/api/surveys/admin/${survey.id}`, NPS_SURVEY);
  survey = (await call('root', 'GET', '/api/surveys/admin')).json.surveys[0];
});

test('visit and first-use rules gate the survey', () => {
  const member = db.prepare('SELECT * FROM users WHERE id = ?').get(ids.member);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(alpha);
  const t0 = Date.now();
  const at = (min) => new Date(t0 + min * 60_000);

  resetState();
  db.prepare('UPDATE surveys SET min_visits = 3, min_days = 0 WHERE id = ?').run(survey.id);
  assert.equal(pendingSurvey(db, member, app, at(0)), null, 'due on the first visit');
  assert.equal(pendingSurvey(db, member, app, at(10)), null);
  assert.equal(db.prepare('SELECT visit_count FROM survey_app_visits').get().visit_count, 1, 'two opens inside 30 minutes counted twice');
  assert.equal(pendingSurvey(db, member, app, at(31)), null, 'due on the second visit');
  assert.equal(pendingSurvey(db, member, app, at(62))?.id, survey.id, 'not due on the third visit');

  resetState();
  db.prepare('UPDATE surveys SET min_visits = 0, min_days = 2 WHERE id = ?').run(survey.id);
  assert.equal(pendingSurvey(db, member, app, at(0)), null, 'due on first use with min_days = 2');
  assert.equal(pendingSurvey(db, member, app, at(47 * 60)), null, 'due before 2 days passed');
  assert.equal(pendingSurvey(db, member, app, at(48 * 60 + 1))?.id, survey.id, 'not due after 2 days');
  db.prepare('UPDATE surveys SET min_visits = 0, min_days = 0 WHERE id = ?').run(survey.id);
});

test('an answer to a survey that is off, or not on this app, is refused', async () => {
  resetState();
  const body = { app: 'alpha', answers: answersFor(survey, 9) };
  db.prepare('UPDATE surveys SET enabled = 0 WHERE id = ?').run(survey.id);
  assert.equal((await call('member', 'POST', `/api/surveys/${survey.id}/responses`, body)).status, 404, 'answered an off survey');
  db.prepare('UPDATE surveys SET enabled = 1, all_apps = 0 WHERE id = ?').run(survey.id);
  assert.equal((await call('member', 'POST', `/api/surveys/${survey.id}/responses`, body)).status, 404, 'answered on an untargeted app');
  db.prepare('UPDATE surveys SET all_apps = 1 WHERE id = ?').run(survey.id);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM survey_responses').get().n, 0);
});

test('answers are validated against the questions', async () => {
  resetState();
  const q = survey.questions;
  const send = (answers, who = 'member') => call(who, 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers });
  const refused = [
    [{}, 'missing required NPS'],
    [{ [q[0].id]: 11 }, 'NPS out of range'],
    [{ [q[0].id]: -1 }, 'NPS below range'],
    [{ [q[0].id]: '9' }, 'NPS as a string'],
    [{ [q[0].id]: 7.5 }, 'NPS not whole'],
    [{ [q[0].id]: 9, [q[1].id]: 6 }, 'scale above its max'],
    [{ [q[0].id]: 9, [q[1].id]: 0 }, 'scale below its min'],
    [{ [q[0].id]: 9, [q[2].id]: 'CEO' }, 'choice not listed'],
    [{ [q[0].id]: 9, [q[3].id]: 'x'.repeat(51) }, 'text over its cap'],
    [{ [q[0].id]: 9, [q[3].id]: 42 }, 'text as a number'],
    [{ [q[0].id]: 9, 99999: 1 }, 'unknown question'],
    [[9], 'answers as a list'],
  ];
  for (const [answers, why] of refused) {
    const r = await send(answers);
    assert.equal(r.status, 400, `${why}: ${r.text}`);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM survey_responses').get().n, 0, 'a refused answer was stored');
  const ok = await send({ [q[0].id]: 10, [q[1].id]: 5, [q[2].id]: 'Ops', [q[3].id]: '  fine  ' });
  assert.equal(ok.status, 201, ok.text);
  const row = db.prepare('SELECT * FROM survey_responses').get();
  assert.equal(row.nps_score, 10);
  assert.equal(JSON.parse(row.answers)[3].value, 'fine');
});

test('one answer per round', async () => {
  resetState();
  const send = () => call('member', 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers: answersFor(survey, 9) });
  assert.equal((await send()).status, 201);
  const again = await send();
  assert.equal(again.status, 409, again.text);
  assert.equal(again.json.error.code, 'ALREADY_ANSWERED');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM survey_responses').get().n, 1);
});

test('answering needs access to the app', async () => {
  resetState();
  const r = await call('stranger', 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers: answersFor(survey, 9) });
  assert.equal(r.status, 403);
  const bot = await call('bot', 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers: answersFor(survey, 9) });
  assert.equal(bot.status, 403, 'an agent answered');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM survey_responses').get().n, 0);
});

test('mail goes to the app owners and platform admins, deduped, every answer escaped', async () => {
  resetState();
  const q = survey.questions;
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run('<b>Mem</b>', ids.member);
  const r = await call('member', 'POST', `/api/surveys/${survey.id}/responses`, {
    app: 'alpha', answers: { [q[0].id]: 3, [q[2].id]: 'Dev', [q[3].id]: '<script>x()</script> & "q"' },
  });
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run('Member', ids.member);
  assert.equal(r.status, 201, r.text);
  const rows = db.prepare('SELECT * FROM email_queue ORDER BY to_email').all();
  assert.deepEqual(rows.map((m) => m.to_email.toLowerCase()).sort(), ['owner@example.com', 'root@example.com'],
    'wrong recipients: want alpha\'s owner + one platform admin address; not members, other apps\' owners, agents or inactive admins');
  for (const m of rows) {
    assert.equal(m.source, 'survey-response');
    assert.equal(m.app_id, alpha);
    assert.equal(m.idempotency_key, `survey-response:${r.json.id}:${m.to_email.toLowerCase()}`);
    assert.doesNotMatch(m.body_html, /<script>|<b>Mem/, 'unescaped answer or name in the html');
    assert.match(m.body_html, /&lt;script&gt;x\(\)&lt;\/script&gt; &amp; &quot;q&quot;/);
    assert.match(m.body_html, /&lt;b&gt;Mem&lt;\/b&gt;/);
    assert.match(m.body_html, /Dev/);
    assert.match(m.body_html, /3 \/ 10/);
    assert.match(m.body_html, /recommend ALPHA/);
    assert.match(m.body_text, /member@example\.com/);
    assert.match(m.body_text, /Anything else\?\n  <script>x\(\)<\/script> & "q"/);
    assert.match(m.subject, /ALPHA survey: NPS 3 from/);
  }
  assert.equal(r.json.mail_queued, 2);
  assert.deepEqual(surveyMailRecipients(db, alpha).map((u) => u.email.toLowerCase()).sort(), ['owner@example.com', 'root@example.com'],
    'two admins sharing an address are one recipient');
});

test('a mail failure does not fail the answer', async () => {
  resetState();
  const real = mailer.queue;
  mailer.queue = () => { throw new Error('queue down'); };
  try {
    const r = await call('member', 'POST', `/api/surveys/${survey.id}/responses`, { app: 'alpha', answers: answersFor(survey, 9) });
    assert.equal(r.status, 201, r.text);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM survey_responses').get().n, 1);
  } finally { mailer.queue = real; }

  // And a recipient whose enqueue throws does not stop the others.
  const app = db.prepare('SELECT id, slug, name FROM apps WHERE id = ?').get(alpha);
  let n = 0;
  const res = queueSurveyResponseMail({
    db, app, survey: { name: 'S' }, respondent: { name: 'M' }, responseId: 1, nps: 9,
    answers: [{ prompt: 'p', kind: 'nps', value: 9 }],
    enqueue: () => { if (n++ === 0) throw new Error('relay down'); return { id: 1 }; },
  });
  assert.deepEqual(res, { sent: 1, skipped: 1 });
});

test('NPS math', () => {
  assert.deepEqual(npsOf([]), { responses: 0, promoters: 0, passives: 0, detractors: 0, nps: null });
  assert.equal(npsOf([10, 10, 9]).nps, 100);
  assert.equal(npsOf([0, 6, 3]).nps, -100);
  assert.equal(npsOf([7, 8]).nps, 0);
  const mixed = npsOf([10, 9, 8, 7, 6, 0]);
  assert.deepEqual(mixed, { responses: 6, promoters: 2, passives: 2, detractors: 2, nps: 0 });
  assert.equal(npsOf([10, 9, 9, 7, 2]).nps, 40);
  assert.equal(npsOf([9, 6, 6]).nps, -33);
  assert.equal(npsOf([6]).nps, -100, '6 is a detractor');
  assert.equal(npsOf([9]).nps, 100, '9 is a promoter');
});

test('results: platform admins see all apps, owners only their own, others are refused', async () => {
  resetState();
  const ins = db.prepare('INSERT INTO survey_responses (survey_id, app_id, user_id, answers, nps_score, submitted_at) VALUES (?,?,?,?,?,?)');
  ins.run(survey.id, alpha, ids.member, '[]', 10, '2026-09-01 10:00:00');
  ins.run(survey.id, alpha, ids.root, '[]', 3, '2026-10-05 10:00:00');
  ins.run(survey.id, beta, ids.member, '[]', 9, '2026-10-06 10:00:00');

  const all = await call('root', 'GET', '/api/surveys/results');
  assert.equal(all.status, 200);
  assert.equal(all.json.overall.total, 3);
  assert.equal(all.json.overall.nps, 33);
  assert.deepEqual(all.json.apps.map((a) => a.slug).sort(), ['alpha', 'beta']);
  assert.deepEqual(all.json.trend.map((t) => t.period), ['2026-09', '2026-10']);
  assert.equal(all.json.distribution[10].count, 1);

  const own = await call('owner', 'GET', '/api/surveys/results');
  assert.deepEqual(own.json.apps.map((a) => a.slug), ['alpha'], 'an owner saw another app');
  assert.equal(own.json.overall.nps, 0);
  assert.equal((await call('owner', 'GET', '/api/surveys/results?app=beta')).status, 403, 'an owner read another app by name');
  assert.equal((await call('owner', 'GET', '/api/surveys/responses?app=beta')).status, 403);
  const list = await call('owner', 'GET', '/api/surveys/responses');
  assert.deepEqual([...new Set(list.json.responses.map((r) => r.app_slug))], ['alpha']);
  const csv = await call('owner', 'GET', '/api/surveys/responses.csv');
  assert.equal(csv.status, 200);
  assert.doesNotMatch(csv.text, /beta/i);

  for (const who of ['member', 'stranger']) {
    assert.equal((await call(who, 'GET', '/api/surveys/results')).status, 403, `${who} read results`);
    assert.equal((await call(who, 'GET', '/api/surveys/responses.csv')).status, 403, `${who} exported answers`);
  }
  const week = await call('root', 'GET', '/api/surveys/results?bucket=week&from=2026-10-01');
  assert.deepEqual(week.json.trend.map((t) => t.period), ['2026-10-05'], 'weeks start on Monday');
  const empty = await call('root', 'GET', '/api/surveys/results?from=2030-01-01');
  assert.equal(empty.json.overall.nps, null);
  assert.equal(empty.json.overall.total, 0);
});
