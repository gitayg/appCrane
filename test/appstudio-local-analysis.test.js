import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// AppStudio for a managed app whose repository is on this host: analyze the
// repo, file the analysis as a NEW request, and stop — no code, no build, no
// PR, nothing pushed. A GitHub-backed (NULL marker) app keeps the full pipeline.
//
// The real worker drives the jobs. Stubbed only at the boundaries it really
// calls: docker (a PATH shim that plays the planner container, emitting
// stream-json and recording which directory was mounted as /workspace) and
// fetch (GitHub's pulls API, for open_pr).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-asla-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPSTUDIO_POLL_MS = '50';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
const CAPTURE = join(ROOT, 'capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(CAPTURE, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  ps) exit 0 ;;
  image) echo 0; exit 0 ;;
  build) exit 0 ;;
  run)
    kind=""; ws=""; prev=""
    for a in "$@"; do
      if [ "$prev" = --label ]; then case "$a" in appcrane.container.type=*) kind="\${a#appcrane.container.type=}" ;; esac; fi
      if [ "$prev" = -v ]; then case "$a" in *:/workspace|*:/workspace:ro) ws="\${a%%:/workspace*}" ;; esac; fi
      prev="$a"
    done
    if [ -f "$CAPTURE/$kind.out" ]; then
      if [ "$kind" = plan ]; then
        echo "$ws" > "$CAPTURE/plan-ws"
        git -C "$ws" rev-parse HEAD > "$CAPTURE/plan-head" 2>/dev/null
        ls -A "$ws" > "$CAPTURE/plan-ls"
      fi
      cat "$CAPTURE/$kind.out"; exit 0
    fi
    echo "no docker" >&2; exit 1 ;;
esac
echo "no docker" >&2; exit 1
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
process.env.CAPTURE = CAPTURE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const { bucketize } = await import('../server/services/requestStatus.js');
const lg = await import('../server/services/localGit.js');
const { startWorker, stopWorker } = await import('../server/services/appstudio/worker.js');

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (args, cwd) => execFileSync('git', args, { env: CLEAN_ENV, cwd }).toString('utf8').trim();
const refsOf = (slug) => git([`--git-dir=${lg.repoPath(slug)}`, 'for-each-ref', '--format=%(refname) %(objectname)']);

const fetchCalls = [];
global.fetch = async (url, init = {}) => {
  const u = String(url);
  const method = (init.method || 'GET').toUpperCase();
  fetchCalls.push(`${method} ${u}`);
  const json = (status, body) => ({ ok: status < 300, status, headers: new Headers(), json: async () => body, text: async () => JSON.stringify(body) });
  if (method === 'POST' && /\/repos\/o\/AMC_asla-gh\/pulls$/.test(u)) return json(201, { html_url: 'https://github.com/o/AMC_asla-gh/pull/7', number: 7 });
  if (method === 'PUT' && /\/repos\/o\/AMC_asla-gh\/pulls\/7\/merge$/.test(u)) return json(200, { sha: 'e'.repeat(40) });
  return json(404, { message: 'stub' });
};

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('asla','asla@x.test','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const requesterId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Rita','rita@x.test','user','h2',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'asla' };
async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const PLAN = {
  summary: 'Add a dark-mode toggle to the header',
  files_to_change: [{ path: 'src/header.js', action: 'modify', rationale: 'render the toggle', estimated_loc: 12 }],
  test_files: [{ path: 'test/header.test.js', action: 'create', what: 'toggle flips the theme' }],
  risks: ['theme flash on load'],
  open_questions: ['persist per user or per device?'],
  test_plan: 'Click the toggle in sandbox.',
};
const streamJson = (text) => [
  JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text }] } }),
  JSON.stringify({ type: 'result', usage: { input_tokens: 1000, output_tokens: 500 } }),
].join('\n') + '\n';
const setPlannerOutput = (text) => writeFileSync(join(CAPTURE, 'plan.out'), text === null ? JSON.stringify({ type: 'result', usage: {} }) + '\n' : streamJson(text));
writeFileSync(join(CAPTURE, 'context.out'), streamJson('# Context\nA tiny app.'));
setPlannerOutput('```json\n' + JSON.stringify(PLAN) + '\n```\nToggle lives in the header.');

startWorker();
after(async () => {
  stopWorker();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function waitJob(id) {
  const deadline = Date.now() + 60000;
  for (;;) {
    const job = db.prepare('SELECT * FROM enhancement_jobs WHERE id = ?').get(id);
    if (job.status === 'done' || job.status === 'failed') return job;
    if (Date.now() > deadline) throw new Error(`job ${id} stuck in ${job.status}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}
const request = (slug, fields = {}) => db.prepare(`
  INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, mode, ai_plan_json, branch_name)
  VALUES (?, ?, 'Rita', 'Please add dark mode', ?, 'auto', ?, ?)
`).run(slug, requesterId, fields.status || 'planning', fields.ai_plan_json ?? null, fields.branch_name ?? null).lastInsertRowid;
const queue = (enhId, phase) => db.prepare('INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, ?)').run(enhId, phase).lastInsertRowid;
const row = (id) => db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(id);
const requestCount = () => db.prepare('SELECT COUNT(*) n FROM enhancement_requests').get().n;

// A local-repo app with some code on main, deploy-on-push off so pushes here start nothing.
await tool('appcrane_create_managed_app', { name: 'Local', slug: 'asla-local' });
const localApp = db.prepare("SELECT * FROM apps WHERE slug = 'asla-local'").get();
assert.equal(localApp.repo_backend, 'local');
await lg.pushFilesToManagedRepo('asla-local', [
  { path: 'package.json', content: '{"name":"asla","version":"1.0.0"}' },
  { path: 'src/header.js', content: 'export const header = () => "<h1>hi</h1>";\n' },
]);
const LOCAL_TIP = git([`--git-dir=${lg.repoPath('asla-local')}`, 'rev-parse', 'refs/heads/main']);

// A GitHub-backed managed app as production has them (repo_backend never written),
// with a deployed release for the planner to read.
db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES ('GH', 'asla-gh', ?, 'managed', 'https://github.com/o/AMC_asla-gh', 'main')").run(getNextSlot(db));
const ghCurrent = join(ROOT, 'apps', 'asla-gh', 'production', 'current');
mkdirSync(ghCurrent, { recursive: true });
writeFileSync(join(ghCurrent, 'package.json'), '{"name":"gh","version":"1.0.0"}');
git(['init', '-q', '-b', 'main'], ghCurrent);
git(['add', '-A'], ghCurrent);
git(['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'release'], ghCurrent);

test('local-repo app: the analysis becomes a new triage request, the original is closed, and nothing is pushed or built', async () => {
  const refsBefore = refsOf('asla-local');
  const enhId = request('asla-local');
  const jobId = queue(enhId, 'plan');
  const job = await waitJob(jobId);
  assert.equal(job.status, 'done', `plan job failed: ${job.error_message}`);

  const all = db.prepare('SELECT * FROM enhancement_requests WHERE app_slug = ? ORDER BY id').all('asla-local');
  assert.equal(all.length, 2, 'expected the original request plus exactly one new request');
  const original = row(enhId);
  const filed = all.find((r) => r.id !== enhId);

  assert.equal(original.status, 'done');
  assert.equal(original.ai_plan_json, null, 'the original must not carry a plan that approve-plan could send to the code phase');
  assert.match(original.ai_log, new RegExp(`filed as request #${filed.id}`));
  assert.equal(original.cost_tokens, 1500);

  assert.equal(filed.status, 'new');
  assert.equal(bucketize(filed.status, filed.validated_at), 'triage');
  assert.equal(filed.user_id, requesterId);
  assert.equal(filed.user_name, 'Rita');
  assert.equal(filed.ai_plan_json, null);
  assert.equal(filed.mode, 'manual');
  assert.match(filed.message, new RegExp(`AppStudio analysis of request #${enhId}`));
  assert.match(filed.message, /Original request:\nPlease add dark mode/);
  assert.match(filed.message, /Add a dark-mode toggle to the header/);
  assert.match(filed.message, /src\/header\.js \(modify\): render the toggle/);
  assert.match(filed.message, /persist per user or per device\?/);
  assert.match(filed.message, new RegExp(LOCAL_TIP.slice(0, 8)));
  assert.match(filed.ai_log, new RegExp(`analysis of request #${enhId}`));

  const listed = await tool('appcrane_list_requests', { bucket: 'triage' });
  assert.ok(JSON.stringify(listed).includes(`"id":${filed.id}`), 'the new request is not in the triage queue agents read');

  const jobs = db.prepare('SELECT phase, status FROM enhancement_jobs WHERE enhancement_id IN (?, ?)').all(enhId, filed.id);
  assert.deepEqual(jobs.map((j) => ({ ...j })), [{ phase: 'plan', status: 'done' }], 'a later phase was queued');

  assert.equal(refsOf('asla-local'), refsBefore, 'a ref was created or moved');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(localApp.id).n, 0, 'something was built');
  assert.equal(fetchCalls.length, 0, 'GitHub was called for a local app');

  assert.equal(readFileSync(join(CAPTURE, 'plan-head'), 'utf8').trim(), LOCAL_TIP, 'the planner did not read the branch tip');
  assert.match(readFileSync(join(CAPTURE, 'plan-ls'), 'utf8'), /src/);
  const ws = readFileSync(join(CAPTURE, 'plan-ws'), 'utf8').trim();
  assert.equal(existsSync(ws), false, 'the analysis checkout was left behind');
});

test('local-repo app: code, build and open_pr refuse, touch no ref, and leave the request failed rather than stuck', async () => {
  for (const phase of ['code', 'build', 'open_pr']) {
    const refsBefore = refsOf('asla-local');
    const enhId = request('asla-local', { status: 'plan_approved', ai_plan_json: JSON.stringify(PLAN), branch_name: 'appstudio/1-asla-local' });
    const job = await waitJob(queue(enhId, phase));
    assert.equal(job.status, 'failed', `${phase} ran for a local app`);
    assert.match(job.error_message, new RegExp(`does not run the '${phase}' phase for 'asla-local'`));
    assert.equal(row(enhId).status, 'auto_failed');
    assert.equal(refsOf('asla-local'), refsBefore);
  }
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(localApp.id).n, 0);
  assert.equal(fetchCalls.length, 0);
});

test('local-repo app: an analysis with nothing in it files no request and fails the job', async () => {
  setPlannerOutput(null);
  try {
    const before = requestCount();
    const enhId = request('asla-local');
    const job = await waitJob(queue(enhId, 'plan'));
    assert.equal(job.status, 'failed');
    assert.match(job.error_message, /no plan and no summary/);
    assert.equal(requestCount(), before + 1, 'a request was filed from an empty analysis');
    assert.equal(row(enhId).status, 'auto_failed');
  } finally {
    setPlannerOutput('```json\n' + JSON.stringify(PLAN) + '\n```\nToggle lives in the header.');
  }
});

test('GitHub-backed (NULL marker) app: plan still waits for plan review, from the deployed release, and files nothing', async () => {
  const before = requestCount();
  const enhId = request('asla-gh');
  const job = await waitJob(queue(enhId, 'plan'));
  assert.equal(job.status, 'done', job.error_message);
  const r = row(enhId);
  assert.equal(r.status, 'pending_user_review_plan');
  assert.deepEqual(JSON.parse(r.ai_plan_json), PLAN);
  assert.equal(requestCount(), before + 1, 'a GitHub-backed app filed a new request');
  assert.equal(readFileSync(join(CAPTURE, 'plan-ws'), 'utf8').trim(), ghCurrent, 'the planner did not read the deployed release');
});

test('GitHub-backed (NULL marker) app: open_pr still opens and merges the PR on GitHub', async () => {
  fetchCalls.length = 0;
  const enhId = request('asla-gh', { status: 'sandbox_ready', ai_plan_json: JSON.stringify(PLAN), branch_name: 'appstudio/9-asla-gh' });
  const job = await waitJob(queue(enhId, 'open_pr'));
  assert.equal(job.status, 'done', job.error_message);
  const r = row(enhId);
  assert.equal(r.status, 'merged');
  assert.equal(r.pr_url, 'https://github.com/o/AMC_asla-gh/pull/7');
  assert.ok(fetchCalls.includes('POST https://api.github.com/repos/o/AMC_asla-gh/pulls'));
  assert.ok(fetchCalls.includes('PUT https://api.github.com/repos/o/AMC_asla-gh/pulls/7/merge'));
});
