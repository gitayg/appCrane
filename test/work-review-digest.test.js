import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createServer } from 'http';

// The Work Review hub's weekly digest (examples/work-review-hub/digest.mjs).
//
// One email a week, to each person about themselves only, through AppCrane's
// email service for hosted apps: Monday only, once per person per week, never
// to someone who switched it off, and the switch survives their next upload.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'wr-digest-'));
const { handler, runDigests } = await import('../examples/work-review-hub/server.mjs');
const { digestFor, sendViaAppCrane, isoWeek } = await import('../examples/work-review-hub/digest.mjs');
const { buildPayload, SCHEMA } = await import('../plugins/work-review/skills/work-review/scripts/upload.mjs');

const MONDAY = new Date('2026-10-26T09:00:00Z'), TUESDAY = new Date('2026-10-27T09:00:00Z');
const report = (usd, findings) => ({
  totals: { sessions: 4, usd, tokens: {}, wastedTokensEstimate: {} },
  instructionQuality: { vague: {}, anchored: {}, withCriteria: {}, withoutCriteria: {}, costliestBadPrompts: [] },
  overcomplication: { flags: {}, returnsCurve: [] },
  findings: { shown: findings },
  outcomes: { commits: 6, usdPerCommit: usd / 6 },
});

let hub, base;
before(async () => { hub = createServer(handler); await new Promise(r => hub.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${hub.address().port}`; });
after(() => hub.close());
const as = email => ({ 'X-AppCrane-User-Email': email, 'X-AppCrane-User-Name': 'Kim Lee', 'X-AppCrane-App-Role': 'user' });
const upload = (email, day, r) => fetch(`${base}/api/reports`, { method: 'POST', headers: { ...as(email), 'Content-Type': 'application/json', 'X-Work-Review-Client': SCHEMA }, body: JSON.stringify({ ...buildPayload(r), day }) });

test('the digest says the week\'s cost, the change, and the top fixes', () => {
  const history = [
    { day: '2026-10-18', totals: { usd: 60 } },
    { day: '2026-10-25', totals: { usd: 38 }, outcomes: { commits: 6, usdPerCommit: 6.33 },
      findings: [{ id: 'rework', usd: 9, share: 0.24 }, { id: 'not-a-known-id', usd: 1, share: 0.1 }], setup: { findings: { 'agent-unused': 1 } } },
  ];
  const m = digestFor('Kim Lee', history, { now: MONDAY, hubUrl: 'https://work-review.app.opswat.com' });
  assert.match(m.subject, /\$38\.00, 2 things to try/);
  assert.match(m.text, /^Hi Kim,/);
  assert.match(m.text, /the week before: \$60\.00/);
  assert.match(m.text, /Prompts that ended in a correction \(\$9\.00, 24% of spend\)/);
  assert.match(m.text, /A subagent you never use: delete it/);
  assert.doesNotMatch(m.text, /not-a-known-id/, 'unknown ids are not shown');
  assert.match(m.html, /<a href="https:\/\/work-review\.app\.opswat\.com">/);
  assert.equal(digestFor('Kim', [{ day: '2026-09-01', totals: { usd: 5 } }], { now: MONDAY }), null, 'nothing recent: no email');
  assert.equal(digestFor('<b>x</b>', history, { now: MONDAY }).html.includes('<b>x'), false, 'names are escaped');
  assert.equal(isoWeek(MONDAY), '2026-W44');
});

test('sent on Monday only, once a week, and never to someone who switched it off', async () => {
  const f = [{ id: 'rework', usd: 3, share: 0.2 }];
  assert.equal((await upload('kim@opswat.com', '2026-10-25', report(20, f))).status, 201);
  assert.equal((await upload('ali@opswat.com', '2026-10-25', report(30, f))).status, 201);
  const sent = [];
  const sender = async m => { sent.push(m); };

  assert.equal((await runDigests({ now: TUESDAY, sender })).sent, 0, 'not on a Tuesday');
  assert.equal((await runDigests({ now: new Date('2026-10-26T05:00:00Z'), sender, hour: 7 })).sent, 0, 'not before the hour');

  // Ali switches it off; the switch must survive Ali's next upload.
  const off = await fetch(`${base}/api/me/digest`, { method: 'PUT', headers: { ...as('ali@opswat.com'), 'Content-Type': 'application/json', 'X-Work-Review-Client': SCHEMA }, body: JSON.stringify({ enabled: false }) });
  assert.equal(off.status, 200);
  assert.equal((await upload('ali@opswat.com', '2026-10-26', report(31, f))).status, 201);
  assert.equal((await (await fetch(`${base}/api/me`, { headers: as('ali@opswat.com') })).json()).digest, false);

  const r = await runDigests({ now: MONDAY, sender });
  assert.equal(r.sent, 1);
  assert.deepEqual(sent.map(m => m.to), ['kim@opswat.com'], 'only Kim, about Kim');
  assert.match(sent[0].idempotencyKey, /^work-review-digest-2026-W44-/);
  assert.equal((await runDigests({ now: new Date('2026-10-26T15:00:00Z'), sender })).sent, 0, 'once per week');
  const csrf = await fetch(`${base}/api/me/digest`, { method: 'PUT', headers: { ...as('kim@opswat.com'), 'Content-Type': 'application/json' }, body: '{"enabled":false}' });
  assert.equal(csrf.status, 400, 'the switch needs the client header, so a cross-site form cannot flip it');
});

test('the digest goes through AppCrane\'s email service with the app\'s token', async () => {
  let got;
  const svc = createServer((req, res) => { let b = ''; req.on('data', c => b += c).on('end', () => { got = { path: req.url, token: req.headers['x-appcrane-service-token'], body: JSON.parse(b) }; res.writeHead(202); res.end('{}'); }); });
  await new Promise(r => svc.listen(0, '127.0.0.1', r));
  await sendViaAppCrane({ to: 'kim@opswat.com', subject: 's', text: 't', html: 'h', idempotencyKey: 'k1' },
    { CRANE_INTERNAL_URL: `http://127.0.0.1:${svc.address().port}`, APPCRANE_SERVICE_TOKEN: 'tok' });
  svc.close();
  assert.equal(got.path, '/api/service/email');
  assert.equal(got.token, 'tok');
  assert.deepEqual([got.body.to, got.body.idempotencyKey, got.body.fromName, got.body.env], ['kim@opswat.com', 'k1', 'Work Review', 'production']);
  await assert.rejects(sendViaAppCrane({ to: 'x' }, {}), /no AppCrane email service/);
});

test('erasing your data keeps your digest opt-out, and nothing else', async () => {
  const { readdirSync, readFileSync } = await import('fs');
  const f = [{ id: 'rework', usd: 3, share: 0.2 }];
  assert.equal((await upload('sam@opswat.com', '2026-10-25', report(20, f))).status, 201);
  const put = await fetch(`${base}/api/me/digest`, { method: 'PUT', headers: { ...as('sam@opswat.com'), 'Content-Type': 'application/json', 'X-Work-Review-Client': SCHEMA }, body: '{"enabled":false}' });
  assert.equal(put.status, 200);
  assert.equal((await fetch(`${base}/api/reports/me`, { method: 'DELETE', headers: as('sam@opswat.com') })).status, 200);
  const dirs = readdirSync(join(process.env.DATA_DIR, 'reports'));
  const kept = dirs.map(d => readFileSync(join(process.env.DATA_DIR, 'reports', d, 'meta.json'), 'utf8')).find(m => !m.includes('@'));
  assert.equal(kept, '{"digest":false}', 'only the opt-out survives: no email, name or numbers');
  assert.equal((await upload('sam@opswat.com', '2026-10-26', report(21, f))).status, 201);
  assert.equal((await (await fetch(`${base}/api/me`, { headers: as('sam@opswat.com') })).json()).digest, false, 'still off after the next upload');
  const sent = [];
  await runDigests({ now: MONDAY, sender: async m => { sent.push(m.to); } });
  assert.ok(!sent.includes('sam@opswat.com'));
});
