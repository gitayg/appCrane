import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Applying Caddy config can never take every site down (services/caddyApply.js):
// a burst of reload requests is one reload, a config that fails validation is
// never applied, a refused reload is never followed by a restart, a stopped
// Caddy is started (not restarted) at most once a minute, and every failure is
// on Settings > Job Health, in the audit log and in platform admins' mail.

process.env.LOG_LEVEL = 'error';
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-caddy-safety-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
initDb();
const db = getDb();
const jh = await import('../server/services/jobHealth.js');
const caddy = await import('../server/services/caddy.js');
const CA = await import('../server/services/caddyApply.js');
const jobHealthRouter = (await import('../server/routes/jobHealth.js')).default;

const scratch = mkdtempSync(join(tmpdir(), 'crane-caddy-files-'));
const LIVE = join(scratch, 'Caddyfile');
const BACKUPS = join(scratch, 'backups');

let calls, host, audits, clock;
function stubRun(file, args) {
  const cmd = `${file} ${args.join(' ')}`;
  calls.push(cmd);
  const fail = (stderr, stdout = '') => Promise.reject(Object.assign(new Error(`Command failed: ${cmd}`), { stderr, stdout }));
  if (file === 'caddy' && args[0] === 'adapt') return host.adapt === true ? Promise.resolve({ stdout: '{}' }) : fail(host.adapt);
  if (file === 'caddy' && args[0] === 'validate') return host.validate === true ? Promise.resolve({ stdout: '' }) : fail(host.validate);
  if (cmd === 'systemctl is-active caddy') {
    return host.state === 'active' ? Promise.resolve({ stdout: 'active\n' }) : fail('', `${host.state}\n`);
  }
  if (cmd === 'systemctl reload caddy') return host.reload === true ? Promise.resolve({ stdout: '' }) : fail(host.reload);
  if (cmd === 'systemctl reset-failed caddy') { if (host.state === 'failed') host.state = 'inactive'; return Promise.resolve({ stdout: '' }); }
  if (cmd === 'systemctl start caddy') {
    if (host.startOk) { host.state = 'active'; return Promise.resolve({ stdout: '' }); }
    return fail('Job for caddy.service failed');
  }
  return fail(`unexpected command in test: ${cmd}`);
}

function reset(over = {}) {
  CA._resetCaddyApplyForTests();
  jh._resetJobHealthForTests();
  jh.enableJobHealthAlerts();
  db.prepare('DELETE FROM job_runs').run();
  db.prepare("DELETE FROM email_queue WHERE source = 'job-health'").run();
  calls = []; audits = []; clock = 1_000_000;
  host = { adapt: true, validate: true, state: 'active', reload: true, startOk: true, ...over };
  writeFileSync(LIVE, 'previous good config\n');
  rmSync(BACKUPS, { recursive: true, force: true });
  CA._setCaddyApplyDepsForTests({
    run: stubRun,
    fetch: async () => ({ ok: host.state === 'active' }),
    livePath: LIVE, tmpPath: join(scratch, 'validate'), backupDir: BACKUPS,
    windowMs: 40, maxWaitMs: 400,
    now: () => clock,
    sleep: async () => {},
    audit: async (action, detail) => { audits.push({ action, detail }); },
  });
  caddy._setCaddyLinuxCheckForTests(() => true);
}
beforeEach(() => reset());

const ADMIN_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('pa','pa@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));

const app = express();
app.use('/api/settings', jobHealthRouter);
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
after(() => {
  CA._resetCaddyApplyForTests(); jh._resetJobHealthForTests(); caddy._setCaddyLinuxCheckForTests(null);
  server.closeAllConnections?.(); server.close();
  rmSync(scratch, { recursive: true, force: true });
});
const jobRow = async (id) => {
  const r = await fetch(`http://127.0.0.1:${server.address().port}/api/settings/job-health`, { headers: { 'X-API-Key': ADMIN_KEY } });
  assert.equal(r.status, 200);
  return (await r.json()).jobs.find((j) => j.id === id);
};
const count = (re) => calls.filter((c) => re.test(c)).length;
const noRestart = () => assert.equal(count(/\brestart\b/), 0, `a restart was issued: ${calls.join(' | ')}`);

test('twenty reload requests in a burst are one validate and one reload, and every caller gets its result', async () => {
  const results = await Promise.all(Array.from({ length: 20 }, () => caddy.reloadCaddy()));
  assert.equal(count(/^systemctl reload caddy$/), 1, calls.join(' | '));
  assert.equal(count(/^caddy adapt /), 1);
  assert.equal(new Set(results).size, 1, 'callers did not share one result');
  assert.equal(results[0].success, true);
  assert.equal(readFileSync(LIVE, 'utf8'), caddy.generateCaddyfile());
  noRestart();
});

test('calls made while a reload runs share exactly one more, generated after them (last write wins)', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let reloading = false;
  CA._setCaddyApplyDepsForTests({ run: async (f, a) => { if (`${f} ${a.join(' ')}` === 'systemctl reload caddy' && !reloading) { reloading = true; await gate; } return stubRun(f, a); } });
  const first = caddy.reloadCaddy();
  while (!reloading) await new Promise((r) => setTimeout(r, 5));
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('late', 'late', 40, 'managed')").run();
  const id = db.prepare("SELECT id FROM apps WHERE slug = 'late'").get().id;
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(id);
  const during = Array.from({ length: 8 }, () => caddy.reloadCaddy());
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(count(/^systemctl reload caddy$/), 0, 'a second reload started while the first was still running');
  release();
  await first; await Promise.all(during);
  assert.equal(count(/^systemctl reload caddy$/), 2, calls.join(' | '));
  assert.match(readFileSync(LIVE, 'utf8'), /handle \/late\*/, 'the second reload did not carry the change made during the first');
});

test('a config that does not parse is never written, reloaded or restarted; the failure is audited and on Job Health', async () => {
  host.adapt = 'Error: adapting config using caddyfile: unrecognized directive: bogus';
  const r = await caddy.reloadCaddy();
  assert.equal(r.success, false);
  assert.equal(r.stage, 'validate');
  assert.equal(readFileSync(LIVE, 'utf8'), 'previous good config\n', 'the live Caddyfile was overwritten');
  assert.equal(count(/^systemctl (reload|start)/), 0, calls.join(' | '));
  noRestart();
  assert.equal(audits[0].action, 'caddy.apply-failed');
  const row = await jobRow('caddy-reload');
  assert.equal(row.status, 'failing');
  assert.match(row.last_error, /unrecognized directive/);
  const mail = db.prepare("SELECT subject FROM email_queue WHERE source = 'job-health'").all();
  assert.ok(mail.some((m) => /Caddy config apply/.test(m.subject)), `platform admin not alerted: ${JSON.stringify(mail)}`);
});

test('caddy validate refusing the config (a missing certificate) stops it; "permission denied" alone does not', async () => {
  host.validate = 'Error: loading certificates: open /etc/caddy/certs/x.pem: no such file or directory';
  const r = await caddy.reloadCaddy();
  assert.equal(r.success, false);
  assert.equal(count(/^systemctl reload caddy$/), 0);
  noRestart();

  reset({ validate: 'Error: loading certificates: open /etc/caddy/certs/x.key: permission denied' });
  const ok = await caddy.reloadCaddy();
  assert.equal(ok.success, true);
  assert.equal(ok.provisioning_unchecked, true);
  assert.equal(count(/^systemctl reload caddy$/), 1);
});

test('a reload Caddy refuses is never followed by a restart; the previous file goes back on disk', async () => {
  host.reload = 'caddy responded with error: HTTP 400: loading new config: open /x.pem: no such file';
  const r = await caddy.reloadCaddy();
  assert.equal(r.success, false);
  assert.equal(r.stage, 'reload');
  noRestart();
  assert.equal(count(/^systemctl start/), 0, 'a running Caddy was started');
  assert.equal(readFileSync(LIVE, 'utf8'), 'previous good config\n', 'the refused config stayed on disk for the next start');
  assert.equal(readdirSync(BACKUPS).length, 1, 'the previous file was not backed up');
  assert.equal((await jobRow('caddy-reload')).status, 'failing');
});

test("the admin check is accepted by Caddy's origin rule: real fetch, an admin API that refuses requests with no Origin", async () => {
  const { createServer } = await import('node:http');
  const seen = [];
  const caddyLike = createServer((req, res) => {
    seen.push(req.headers.origin || null);
    const origin = req.headers.origin;
    if (req.headers['sec-fetch-mode'] === 'cors' && !origin) { res.statusCode = 403; return res.end("client is not allowed to access from origin ''"); }
    if (origin && origin !== `http://127.0.0.1:${caddyLike.address().port}`) { res.statusCode = 403; return res.end('bad origin'); }
    res.end('{}');
  });
  await new Promise((r) => caddyLike.listen(0, '127.0.0.1', r));
  try {
    CA._setCaddyApplyDepsForTests({ fetch: (...a) => fetch(...a), adminUrl: `http://127.0.0.1:${caddyLike.address().port}` });
    const r = await caddy.reloadCaddy();
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(seen[0], `http://127.0.0.1:${caddyLike.address().port}`);
  } finally {
    caddyLike.close();
  }
});

test('an admin API that answers a moment after the reload is a success, not a failure', async () => {
  let asked = 0;
  CA._setCaddyApplyDepsForTests({ fetch: async () => ({ ok: ++asked > 2 }) });
  const r = await caddy.reloadCaddy();
  assert.equal(r.success, true, JSON.stringify(r));
  assert.equal(asked, 3);
  noRestart();
  assert.notEqual((await jobRow('caddy-reload'))?.status, 'failing');
});

test('an admin API that never answers after a reload is reported, after several tries, and still never restarts Caddy', async () => {
  let asked = 0;
  CA._setCaddyApplyDepsForTests({ fetch: async () => { asked++; throw new Error('ECONNREFUSED'); } });
  const r = await caddy.reloadCaddy();
  assert.equal(r.success, false);
  assert.equal(r.stage, 'verify');
  assert.equal(asked, 10);
  noRestart();
});

test('a stopped Caddy is started (reset-failed first), never restarted, and at most once a minute', async () => {
  host.state = 'failed';
  host.startOk = false;
  const a = await caddy.reloadCaddy({ force: true });
  assert.equal(a.success, false);
  assert.deepEqual(calls.filter((c) => /reset-failed|start caddy/.test(c)), ['systemctl reset-failed caddy', 'systemctl start caddy']);
  assert.equal(readFileSync(LIVE, 'utf8'), 'previous good config\n', 'a config Caddy could not start with stayed on disk');
  clock += 30_000;
  await caddy.reloadCaddy({ force: true });
  await CA.caddyWatchdogTick().catch(() => {});
  assert.equal(count(/^systemctl start caddy$/), 1, `started again inside the cooldown: ${calls.join(' | ')}`);
  clock += 31_000;
  host.startOk = true;
  await CA.caddyWatchdogTick().catch(() => {});
  assert.equal(count(/^systemctl start caddy$/), 2);
  noRestart();
});

test('watchdog: an inactive Caddy is started, reported failing on Job Health, and mailed to platform admins', async () => {
  CA.startCaddyWatchdog();
  host.state = 'inactive';
  await assert.rejects(CA.caddyWatchdogTick(), /Caddy was inactive; AppCrane started it/);
  assert.equal(host.state, 'active');
  const row = await jobRow('caddy-watchdog');
  assert.equal(row.status, 'failing');
  assert.equal(row.started_in_process, true);
  const mail = db.prepare("SELECT subject FROM email_queue WHERE source = 'job-health'").all();
  assert.ok(mail.some((m) => /Caddy watchdog/.test(m.subject)), JSON.stringify(mail));
  await CA.caddyWatchdogTick();
  assert.equal((await jobRow('caddy-watchdog')).status, 'ok');
  noRestart();
});

test('caddy.js has no restart left anywhere', () => {
  for (const f of ['caddy.js', 'caddyApply.js']) {
    const code = readFileSync(new URL(`../server/services/${f}`, import.meta.url), 'utf8')
      .split('\n').filter((l) => !/^\s*(\*|\/\/|\/\*)/.test(l)).join('\n');
    assert.doesNotMatch(code, /'restart'/, `${f} still issues systemctl restart`);
  }
});
