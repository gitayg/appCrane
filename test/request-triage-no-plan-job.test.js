/**
 * A submitted request is triage work, not an AI job — and the Request panel
 * has to say so.
 *
 * v2.1.1 removed the plan job that POST /api/enhancements used to queue. The
 * React RequestPanel was never told: it kept POSTing, opening an EventSource
 * on /api/plan/:id/stream, and waiting for a `plan` event. With no job row the
 * stream answers "Queued — waiting for worker to pick up the job…" every two
 * seconds forever (server/routes/plan.js), so the spinner never stopped and
 * the Build button — gated on planReady — could never render.
 *
 * The first test is the fact the UI has to match, measured rather than read:
 * submit a request and look at the jobs table. The rest pin the panel to it.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-request-triage-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const USER_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
  .run('Requester', 'req@example.com', 'user', hashApiKey(USER_KEY));

const enhancementsRoutes = (await import('../server/routes/enhancements.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/enhancements', enhancementsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');

// ------------------------------------------------------- the server's answer

test('POST /api/enhancements files a request and queues NO plan job', async () => {
  const res = await fetch(`${BASE}/api/enhancements`, {
    method: 'POST',
    headers: { 'X-API-Key': USER_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'Make the header stickier' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  const id = body.enhancement_id;
  assert.ok(id, 'no enhancement_id returned');

  const row = db.prepare('SELECT status, ai_plan_json FROM enhancement_requests WHERE id = ?').get(id);
  assert.equal(row.status, 'new', 'a filed request lands in triage, not in a planning state');
  assert.equal(row.ai_plan_json, null, 'nothing generates a plan at submit time');

  const jobs = db.prepare('SELECT phase FROM enhancement_jobs WHERE enhancement_id = ?').all(id);
  assert.deepEqual(jobs, [],
    'a job row appeared — if submitting really does queue work again, the Request panel ' +
    'may stream it, but this test and the panel have to change together');
});

// The panel's dead spinner was exactly this: a stream that only ever reports
// "waiting". Asserted on the route source because reproducing it means holding
// an SSE connection open across poll ticks for no new information.
test('/api/plan/:id/stream reports "waiting" indefinitely when no job exists', () => {
  const planRoute = readFileSync(new URL('../server/routes/plan.js', import.meta.url), 'utf8');
  assert.match(planRoute, /if \(!job\) \{[\s\S]{0,200}?sendStatus\('Queued — waiting for worker/,
    'the no-job branch changed — recheck whether the panel could now learn anything from this stream');
});

// ------------------------------------------------------- the panel's answer

const panel = web('components/runtime-topbar/RequestPanel.tsx');

// The panel's header comment explains the machinery that was removed, by name.
// Asserting "the word EventSource is absent" against the raw file would make
// that explanation illegal to write — so the absence tests run against code
// with comments stripped, and the comment itself is checked separately below.
const panelCode = panel.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');

test('the Request panel does not open the plan stream', () => {
  assert.doesNotMatch(panelCode, /EventSource/, 'the panel opened a stream again');
  assert.doesNotMatch(panelCode, /\/api\/plan\//, 'the panel reached for a plan endpoint again');
});

test('the Request panel offers no Build or Refine control', () => {
  assert.doesNotMatch(panelCode, /planReady/);
  assert.doesNotMatch(panelCode, /Build</, 'a Build button gated on a plan that never arrives');
  assert.doesNotMatch(panelCode, /Refine/);
});

test('the panel keeps a record of what was removed and why', () => {
  assert.match(panel, /v2\.1\.1 removed the plan job/,
    'the next reader has to be able to find out why this panel is thinner than the portal chrome around it');
});

test('the Request panel submits through useEnhancementSubmit', () => {
  assert.match(panelCode, /useEnhancementSubmit/,
    'the panel must share the submit path BugPanel uses — one POST, one confirmation');
  assert.match(web('hooks/useEnhancementSubmit.ts'), /post<[^>]*>\(\s*'\/api\/enhancements'/,
    'the hook stopped posting to /api/enhancements');
});

test('the confirmation says the request is queued for people, not for a planner', () => {
  assert.match(panelCode, /filed/i, 'the success state must confirm the request was filed');
  assert.match(panelCode, /Nothing is being generated right now/,
    'the panel used to imply an AI was working; the correction must stay explicit');
  assert.match(panelCode, /"\/requests"/, 'the confirmation must point at where the request is actually tracked');
});

test('usePlanFlow is gone, not left behind as a third dead hook', () => {
  assert.equal(existsSync(new URL('../studio-web/src/hooks/usePlanFlow.ts', import.meta.url)), false,
    'usePlanFlow.ts is back — it documented a plan job POST /api/enhancements has not queued since v2.1.1');
  for (const f of ['components/runtime-topbar/RequestPanel.tsx', 'components/runtime-topbar/RequestModal.tsx', 'topbar-element/CranePanels.tsx']) {
    assert.doesNotMatch(web(f), /usePlanFlow/, `${f} still imports usePlanFlow`);
  }
});

// The portal is where this panel actually renders, and its comment described
// the plan/refine/build flow as current. A wrong comment next to a Custom
// Element is the only documentation the next reader gets.
test('the portal describes the panel it actually mounts', () => {
  const portal = readFileSync(new URL('../docs/login.html', import.meta.url), 'utf8');
  assert.match(portal, /<crane-request-panel id="planPanel"/, 'the portal stopped mounting the panel');
  assert.doesNotMatch(portal, /The React component handles the form, plan SSE, refine,/,
    'the stale comment is back');
});

// Not everything named "plan" in the portal is dead, and the cleanup must not
// take this with it: a request the AppStudio worker parks in
// 'pending_user_review_plan' still opens its plan from the Jobs panel.
test('the portal keeps the plan path that Jobs still reaches', () => {
  const portal = readFileSync(new URL('../docs/login.html', import.meta.url), 'utf8');
  assert.match(portal, /openPlanById\(req\.id, req\.app_slug\)/,
    'the Jobs panel lost its View Plan action — that path is reachable whenever the worker runs');
});
