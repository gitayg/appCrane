import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createServer } from 'http';

// The work-review daily upload (plugins/work-review/skills/work-review/scripts/upload.mjs)
// and the hub that receives it (examples/work-review-hub).
//
// What is pinned here is what the user was promised: only an allow-listed,
// scrubbed summary leaves the machine, only to app.opswat.com over https, and
// the hub trusts nothing but AppCrane's injected identity — so one developer
// can neither read another's excerpts nor write into their history.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'wr-hub-'));
const OK = { allowExcerpt: () => true };   // tests that exercise the excerpt path approve it explicitly
const { buildPayload, scrub, checkUrl, SCHEMA, APP_KEY_RE, accountProblem } = await import('../plugins/work-review/skills/work-review/scripts/upload.mjs');
const { handler, validate } = await import('../examples/work-review-hub/server.mjs');

const report = {
  totals: { sessions: 3, userPrompts: 9, cacheHitRate: 0.9, errorRate: 0.05, tokens: { input: 1, output: 2, cacheRead: 3, cacheWrite: 4 }, wastedTokensEstimate: { redundantReads: 10 } },
  instructionQuality: {
    totalCost: 1000, reworkCost: 400, reworkShare: 0.4,
    vague: { prompts: 2, medianCost: 300, medianExploreBeforeFirstEdit: 6, reworkRate: 0.5 }, anchored: { prompts: 1 }, withCriteria: {}, withoutCriteria: {},
    costliestBadPrompts: [{ cost: 400, sessionId: 'abc-session', why: ['followed by correction', '<script>'], prompt:
      'fix login for jane.doe@opswat.com in /home/jane/repo/src/auth.js, key sk-ant-api03-ABCDEFGHIJKLMNOPQRST, see https://internal.example/x on 10.1.2.3 ' + 'x'.repeat(400) }],
  },
  overcomplication: { flags: { 'heavy-for-output': 1 }, returnsCurve: [{ bin: 1, sessions: 3, avgTokens: 5 }], medianBaselineContextTokens: 70000 },
  cross: { recurringCorrections: [{ sessions: 2, example: "don't mock the db for ACME Corp" }], repeatedPrompts: [{ example: 'deploy to prod-eu-7' }] },
  sessions: [{ sessionId: 'abc-session', project: '-home-jane-secret-project', file: '/home/jane/.claude/projects/x.jsonl' }],
};

test('uploader sends only allow-listed, scrubbed fields', () => {
  const p = buildPayload(report, OK);
  const s = JSON.stringify(p);
  for (const leak of ['jane.doe@opswat.com', '/home/jane', 'sk-ant-api03', 'internal.example', '10.1.2.3', 'abc-session', 'secret-project', 'ACME', 'prod-eu-7', 'x.jsonl'])
    assert.ok(!s.includes(leak), `payload must not contain ${leak}`);
  const ex = p.instructionQuality.costliestBadPrompts[0].excerpt;
  assert.ok(ex.length <= 161, 'excerpt is capped');
  assert.match(ex, /«email»/); assert.match(ex, /«path»/); assert.match(ex, /«secret»/); assert.match(ex, /«url»/); assert.match(ex, /«ip»/);
  assert.deepEqual(p.instructionQuality.costliestBadPrompts[0].why, ['followed by correction', 'script'], 'why-tags are stripped to plain words');
  assert.equal(p.recurring.corrections, 1, 'recurring corrections travel as a count, not text');
  assert.equal(p.schema, SCHEMA);
});

test('scrub removes key material and long tokens', () => {
  assert.equal(scrub('use dhk_admin_abcdef1234567890 now'), 'use «secret» now');
  assert.equal(scrub('password: hunter2 ok'), 'password «secret» ok');
  assert.match(scrub('-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----'), /^«key»$/);
  assert.match(scrub('commit 3f2a9c4e5b6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f'), /«hex»/);
});

test('upload URL is pinned to https on app.opswat.com', () => {
  assert.equal(checkUrl('https://work-review.app.opswat.com').hostname, 'work-review.app.opswat.com');
  assert.equal(checkUrl('https://app.opswat.com/work-review').hostname, 'app.opswat.com');
  for (const bad of ['http://app.opswat.com', 'https://app.opswat.com.evil.io', 'https://evilapp.opswat.com', 'https://u:p@app.opswat.com', 'https://example.com', 'nonsense'])
    assert.throws(() => checkUrl(bad), undefined, bad);
});

test('hub accepts exactly what the uploader builds', () => {
  const v = validate(buildPayload(report, OK));
  assert.equal(v.instructionQuality.costliestBadPrompts.length, 1);
});

test('what was not measured reaches the hub as null, never as 0', () => {
  // No commits, so no cost per commit; one model nobody priced.
  const r = { ...report, totals: { ...report.totals, unpricedModels: { 'mystery-model': 1200 } }, outcomes: { commits: 0, usdPerCommit: null } };
  const p = buildPayload(r, OK);
  assert.equal(p.outcomes.usdPerCommit, null, 'the uploader does not invent a $0 cost per commit');
  assert.equal(p.outcomes.linesAdded, null, 'a field the analyzer did not send is not measured, not zero');
  assert.equal(p.totals.unpricedTokens, 1200, 'the hub is told the dollar total is incomplete');
  const v = validate(p);
  assert.equal(v.outcomes.usdPerCommit, null, 'the hub stores it as not measured');
  assert.equal(v.totals.unpricedTokens, 1200);
  assert.throws(() => validate({ ...p, outcomes: { ...p.outcomes, usdPerCommit: 'free' } }), /not a number/);
});

// ── hub over HTTP ────────────────────────────────────────────────
let server, base;
before(async () => { server = createServer(handler); await new Promise(r => server.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${server.address().port}`; });
after(() => server.close());

const as = (email, role = 'user') => ({ 'X-AppCrane-User-Email': email, 'X-AppCrane-App-Role': role });
const post = (headers, body) => fetch(`${base}/api/reports`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Work-Review-Client': SCHEMA, ...headers }, body: JSON.stringify(body) });

test('hub refuses requests that did not come through AppCrane', async () => {
  assert.equal((await fetch(`${base}/api/health`)).status, 200);
  assert.equal((await fetch(`${base}/`)).status, 401);
  assert.equal((await post({}, buildPayload(report, OK))).status, 401);
});

test('hub stores per user, shows excerpts only to their author, numbers to admins', async () => {
  assert.equal((await post(as('alice@opswat.com'), buildPayload(report, OK))).status, 201);
  const bob = buildPayload(report, OK); bob.instructionQuality.costliestBadPrompts = [];
  assert.equal((await post(as('bob@opswat.com'), bob)).status, 201);

  const mine = await (await fetch(`${base}/api/reports/me`, { headers: as('alice@opswat.com') })).json();
  assert.equal(mine.reports.length, 1);
  assert.equal(mine.reports[0].instructionQuality.costliestBadPrompts.length, 1);
  const bobs = await (await fetch(`${base}/api/reports/me`, { headers: as('bob@opswat.com') })).json();
  assert.equal(bobs.reports[0].instructionQuality.costliestBadPrompts.length, 0, "bob never sees alice's excerpts");

  assert.equal((await fetch(`${base}/api/team`, { headers: as('bob@opswat.com') })).status, 403);
  const team = await (await fetch(`${base}/api/team`, { headers: as('lead@opswat.com', 'owner') })).json();
  assert.equal(team.people, 2);
  assert.equal(team.enough, false, 'two people: no team numbers, only the count');
  assert.equal(team.median, undefined);
  assert.ok(!JSON.stringify(team).includes('«'), 'team view carries no excerpts');

  // Same day again replaces, not appends.
  await post(as('alice@opswat.com'), buildPayload(report, OK));
  assert.equal(readdirSync(process.env.DATA_DIR + '/reports').length, 2);

  assert.equal((await fetch(`${base}/api/reports/me`, { method: 'DELETE', headers: as('alice@opswat.com') })).status, 200);
  assert.equal((await (await fetch(`${base}/api/reports/me`, { headers: as('alice@opswat.com') })).json()).reports.length, 0);
});

test('hub rejects forged, oversized and secret-bearing uploads', async () => {
  const h = as('mallory@opswat.com');
  assert.equal((await fetch(`${base}/api/reports`, { method: 'POST', headers: { ...h, 'Content-Type': 'text/plain' }, body: '{}' })).status, 400, 'no custom header → refused (CSRF)');
  const extra = buildPayload(report, OK); extra.instructionQuality.costliestBadPrompts[0].excerpt = 'x'.repeat(500);
  assert.equal((await post(h, extra)).status, 422);
  const sec = buildPayload(report, OK); sec.instructionQuality.costliestBadPrompts[0].excerpt = 'token ghp_abcdefghijklmnopqrstuvwxyz123456';
  assert.equal((await post(h, sec)).status, 422);
  const injected = buildPayload(report, OK); injected.transcript = 'whole session'; injected.totals.sessions = 'lots';
  assert.equal((await post(h, injected)).status, 422);
  const big = buildPayload(report, OK); big.pad = 'x'.repeat(100_000);
  assert.equal((await post(h, big).catch(() => ({ status: 413 }))).status, 413);
});

test('uploader takes only an app sign-in key; scrub catches keys with dashes', () => {
  assert.ok(APP_KEY_RE.test('dhk_uak_Ab-c_9xYz'), 'base64url keys contain - and _');
  assert.ok(!APP_KEY_RE.test('dhk_user_Abc123'), 'a full user key is refused');
  assert.ok(!APP_KEY_RE.test('dhk_mcp_Abc123'));
  assert.equal(scrub('key dhk_uak_Ab-cdEFgh-1234 here'), 'key «secret» here');
});

test('hub lets an app sign-in key upload and nothing else', async () => {
  const viaKey = { ...as('kim@opswat.com'), 'X-AppCrane-Auth-Via': 'app-key' };
  assert.equal((await post(viaKey, buildPayload(report, OK))).status, 201, 'upload allowed');
  assert.equal((await fetch(`${base}/api/reports/me`, { headers: viaKey })).status, 403, 'cannot read excerpts');
  assert.equal((await fetch(`${base}/api/reports/me`, { method: 'DELETE', headers: viaKey })).status, 403, 'cannot delete');
  assert.equal((await fetch(`${base}/`, { headers: viaKey })).status, 403, 'no dashboard');
  const browser = await (await fetch(`${base}/api/reports/me`, { headers: as('kim@opswat.com') })).json();
  assert.equal(browser.reports.length, 1, 'the same person in a browser sees the upload');
});

test('the setup summary travels as counts and finding kinds, never names or paths', () => {
  const setup = {
    inventory: { alwaysOnTokens: 6000, agents: [{ name: 'secret-billing-agent' }], skills: [{ name: 'acme-deploy' }, { name: 'org', managed: true }], mcpServers: [{ name: 'acme-jira' }], hooks: [], frameworks: { LangGraph: 2 } },
    findings: [{ kind: 'agent-unused', item: 'secret-billing-agent', evidence: { file: '/home/jane/acme/.claude/agents/x.md' } }, { kind: 'agent-unused', item: 'y' }, { kind: 'Bad Kind!', item: 'z' }],
  };
  const p = buildPayload(report, { setup, ...OK });
  const s = JSON.stringify(p.setup);
  for (const leak of ['secret-billing-agent', 'acme', '/home/jane', 'LangGraph', 'Bad Kind']) assert.ok(!s.includes(leak), `setup must not carry ${leak}`);
  assert.deepEqual(p.setup.findings, { 'agent-unused': 2 });
  assert.equal(p.setup.skills, 1, 'org-managed skills are not counted as the person\'s own');
  assert.equal(validate(p).setup.multiAgentFrameworks, 1, 'the hub accepts it');
});

test('no excerpt leaves unless its owner approved that exact text', () => {
  assert.deepEqual(buildPayload(report).instructionQuality.costliestBadPrompts, [], 'default: none');
  const p = buildPayload(report, { allowExcerpt: t => t.startsWith('fix login') });
  assert.equal(p.instructionQuality.costliestBadPrompts.length, 1);
  assert.deepEqual(buildPayload(report, { allowExcerpt: t => t === 'something else' }).instructionQuality.costliestBadPrompts, []);
});

test('with an account domain set, only a work login uploads', () => {
  assert.equal(accountProblem({}, null), null, 'no domain configured: no check');
  assert.equal(accountProblem({ accountDomain: 'opswat.com' }, 'kim@OPSWAT.com'), null);
  assert.match(accountProblem({ accountDomain: 'opswat.com' }, 'kim@gmail.com'), /not a opswat\.com account/);
  assert.match(accountProblem({ accountDomain: 'opswat.com' }, null), /cannot confirm/);
  assert.match(accountProblem({ accountDomain: 'opswat.com' }, 'kim@opswat.com.evil.io'), /not a/);
});

test('the team view is aggregates only, and only once enough people take part', async () => {
  for (let i = 1; i <= 6; i++) assert.equal((await post(as(`dev${i}@opswat.com`), buildPayload(report, { setup: { inventory: {}, findings: [{ kind: 'agent-unused' }] } }))).status, 201);
  const T = await (await fetch(`${base}/api/team`, { headers: as('lead@opswat.com', 'admin') })).json();
  assert.equal(T.enough, true);
  assert.ok(T.people >= 5);
  assert.ok(T.peopleWithSetupFinding['agent-unused'] >= 6, 'counted as people, not named');
  assert.ok(!JSON.stringify(T).includes('@'), 'no email, name or row per person anywhere in the team view');
  assert.equal(T.median.usd >= 0, true);
});
