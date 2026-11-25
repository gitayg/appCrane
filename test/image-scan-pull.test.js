import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The pinned scanner image is obtained before it is needed: a deploy that
// finds it missing pulls it (bounded wait) instead of skipping, concurrent
// callers share one `docker pull`, the startup warm-up pulls it when absent,
// and a failed pull is recorded on Job Health with the honest reason kept.
// Docker is the module's exec seam: inspect answers from `present`, pull is
// scripted per test, and every argv is recorded.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-scan-pull-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const scan = await import('../server/services/imageScan.js');
const { getJobHealth, jobStarted, _resetJobHealthForTests } = await import('../server/services/jobHealth.js');

const ID = `sha256:${'a'.repeat(64)}`;
let present = false;
let calls = [];
let pull = async () => { present = true; return { stdout: '', stderr: '' }; };
const fake = async (args, opts) => {
  calls.push({ args, timeout: opts?.timeout });
  if (args[0] === 'image' && args[1] === 'inspect') {
    if (!present) throw Object.assign(new Error('No such image'), { stderr: `Error response from daemon: No such image: ${args[2]}` });
    return { stdout: `${ID}\n`, stderr: '' };
  }
  if (args[0] === 'pull') return pull(args);
  throw new Error(`unexpected docker ${args.join(' ')}`);
};
const pulls = () => calls.filter((c) => c.args[0] === 'pull');
const scanJob = () => getJobHealth().find((j) => j.id === scan.SCANNER_JOB);

beforeEach(() => {
  present = false;
  calls = [];
  pull = async () => { present = true; return { stdout: '', stderr: '' }; };
  scan._setScannerDockerForTests(fake);
  _resetJobHealthForTests();
  jobStarted(scan.SCANNER_JOB);
  db.prepare('DELETE FROM job_runs').run();
});
after(() => {
  scan._setScannerDockerForTests(null);
  rmSync(ROOT, { recursive: true, force: true });
});

test('a deploy that finds the scanner missing pulls the pinned image once and proceeds', async () => {
  const r = await scan.ensureScanner({ allowPull: false });
  assert.deepEqual(r, { ok: true });
  assert.equal(pulls().length, 1);
  assert.deepEqual(pulls()[0].args, ['pull', scan.SCANNER_IMAGE]);
  assert.match(scan.SCANNER_IMAGE, /^aquasec\/trivy:\d+\.\d+\.\d+(@sha256:[a-f0-9]{64})?$/);
  assert.ok(!scan.SCANNER_IMAGE.includes(':latest'));
  const again = await scan.ensureScanner({ allowPull: false });
  assert.equal(again.ok, true);
  assert.equal(pulls().length, 1, 'a present scanner is not pulled again');
});

test('concurrent deploys share one docker pull', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  pull = async () => { await gate; present = true; return { stdout: '', stderr: '' }; };
  const waiting = Array.from({ length: 5 }, () => scan.ensureScanner({ allowPull: false }));
  await new Promise((r) => setTimeout(r, 50));
  release();
  const results = await Promise.all(waiting);
  assert.ok(results.every((x) => x.ok), JSON.stringify(results));
  assert.equal(pulls().length, 1, `pulls: ${pulls().length}`);
});

test('a failed pull keeps the honest reason and is recorded on Job Health', async () => {
  pull = async () => { throw Object.assign(new Error('exit 1'), { stderr: 'Error response from daemon: Get "https://registry.example.test/v2/": dial tcp: i/o timeout' }); };
  const r = await scan.ensureScanner({ allowPull: false });
  assert.equal(r.ok, false);
  assert.match(r.reason, /container image scanner unavailable: aquasec\/trivy:[^ ]+ is not present on this host and could not be pulled/);
  assert.match(r.reason, /i\/o timeout/);
  const job = scanJob();
  assert.equal(job.status, 'failing', JSON.stringify(job));
  assert.match(job.last_error, /scanner image aquasec\/trivy:[^ ]+ could not be pulled/);
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM job_runs WHERE job = ? AND ok = 0").get(scan.SCANNER_JOB).n >= 1);

  const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref) VALUES ('pf','pf',901,'image','odoo:19')").run().lastInsertRowid);
  db.prepare("INSERT INTO deployments (app_id,env,version,status,image_ref) VALUES (?,'production','1','live',?)").run(appId, `odoo@sha256:${'b'.repeat(64)}`);
  const viaScan = await scan.scanImage(db, { id: appId, slug: 'pf' }, 'production', { allowPull: false });
  assert.equal(viaScan.status, 'skipped');
  assert.match(viaScan.error, /could not be pulled .*i\/o timeout/);
});

test('no Docker CLI at all is not recorded as a pull failure', async () => {
  pull = async () => { throw Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' }); };
  const r = await scan.ensureScanner({ allowPull: true });
  assert.equal(r.ok, false);
  assert.equal(scanJob().last_run, null);
});

test('a deploy stops waiting after its bound; the shared pull continues and the next caller uses it', async () => {
  scan._setScannerDockerForTests(fake, { deployPullWaitMs: 40 });
  let release;
  const gate = new Promise((r) => { release = r; });
  pull = async () => { await gate; present = true; return { stdout: '', stderr: '' }; };
  const r = await scan.ensureScanner({ allowPull: false });
  assert.equal(r.ok, false);
  assert.match(r.reason, /did not finish within \d+s of starting and continues in the background/);
  release();
  await new Promise((res) => setTimeout(res, 20));
  const next = await scan.ensureScanner({ allowPull: false });
  assert.equal(next.ok, true);
  assert.equal(pulls().length, 1);
});

test('startup warm-up pulls a missing scanner and leaves a present one alone', async () => {
  const w = await scan.warmScannerImage();
  assert.deepEqual(w, { ok: true, pulled: true });
  assert.equal(pulls().length, 1);
  const w2 = await scan.warmScannerImage();
  assert.deepEqual(w2, { ok: true, pulled: false });
  assert.equal(pulls().length, 1);
});

test('one wait budget per pull: a deploy waits at most once, and within 15 minutes of a failed pull a deploy neither pulls nor waits', async () => {
  let now = Date.parse('2026-11-25T10:00:00Z');
  const waits = [];
  const clock = {
    now: () => now,
    sleep: (ms) => { waits.push(ms); now += ms; return { done: new Promise((r) => setImmediate(r)), cancel() {} }; },
  };
  scan._setScannerDockerForTests(fake, { clock });
  let fail;
  pull = () => new Promise((_, reject) => { fail = reject; });

  // Deploy 1: the SBOM step starts the pull and waits out the budget...
  const sbom = await scan.ensureScanner({ allowPull: false });
  assert.equal(sbom.ok, false);
  assert.match(sbom.reason, /continues in the background/);
  // ...and its vulnerability scan finds the budget spent: no second wait.
  const vuln = await scan.ensureScanner({ allowPull: false });
  assert.equal(vuln.ok, false);
  assert.deepEqual(waits.filter((w) => w > 0), [scan.DEPLOY_PULL_WAIT_MS], `waits: ${waits}`);
  assert.equal(pulls().length, 1);

  // The shared pull then fails.
  now += 8 * 60 * 1000;
  fail(Object.assign(new Error('exit 1'), { stderr: 'toomanyrequests: rate limit reached' }));
  await new Promise((r) => setImmediate(r));

  // Deploy 2, five minutes later: skips at once with the remembered reason.
  now += 5 * 60 * 1000;
  const before = waits.length;
  const d2a = await scan.ensureScanner({ allowPull: false });
  const d2b = await scan.ensureScanner({ allowPull: false });
  for (const r of [d2a, d2b]) {
    assert.equal(r.ok, false);
    assert.match(r.reason, /could not be pulled — toomanyrequests: rate limit reached/);
    assert.match(r.reason, /a deploy retries the pull from 2026-11-25T10:25:00\.000Z/);
  }
  assert.equal(waits.length, before, 'a deploy within 15 minutes of the failure did not wait');
  assert.equal(pulls().length, 1, 'and did not start another pull');

  // After 15 minutes a deploy tries again (and gets the full budget once).
  now += 11 * 60 * 1000;
  pull = async () => { present = true; return { stdout: '', stderr: '' }; };
  const d3 = await scan.ensureScanner({ allowPull: false });
  assert.equal(d3.ok, true, d3.reason);
  assert.equal(pulls().length, 2);
});

test('a scheduled scan still retries inside the 15-minute window', async () => {
  let now = Date.parse('2026-11-25T10:00:00Z');
  scan._setScannerDockerForTests(fake, { clock: { now: () => now, sleep: (ms) => { now += ms; return { done: new Promise((r) => setImmediate(r)), cancel() {} }; } } });
  pull = async () => { throw Object.assign(new Error('exit 1'), { stderr: 'dial tcp: i/o timeout' }); };
  assert.equal((await scan.ensureScanner({ allowPull: false })).ok, false);
  now += 60 * 1000;
  pull = async () => { present = true; return { stdout: '', stderr: '' }; };
  assert.equal((await scan.ensureScanner({ allowPull: true })).ok, true);
  assert.equal(pulls().length, 2);
});
