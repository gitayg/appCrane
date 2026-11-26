import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'events';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// Host limits applied automatically after an upgrade: on boot, when the running
// version differs from the last automatic run's, the script Apply runs is run
// once in the background. Root runs the repo copy; any other user runs only the
// root-owned copy through the sudoers rule, and only when its stamp and its
// bytes say it is the checkout's script. The host is faked, as in
// host-hardening-settings.test.js.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-hardening-auto-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_SRC = readFileSync(join(ROOT, 'scripts', 'host-hardening.sh'), 'utf8');

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const H = await import('../server/services/hostHardening.js');
const A = await import('../server/services/hostHardeningAuto.js');
const { createHostHardeningRouter } = await import('../server/routes/hostHardening.js');
const settingsRoutes = (await import('../server/routes/settings.js')).default;
initDb();
const db = getDb();

const REPO = '/opt/appcrane';
const REPO_SCRIPT = `${REPO}/scripts/host-hardening.sh`;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const enoent = (p) => Object.assign(new Error(`ENOENT: ${p}`), { code: 'ENOENT' });
const INSTALLED = H.expectedInstalledCopy(REPO_SRC, REPO);
const STAMP = `version=2.145.0\nsource_sha256=${sha(REPO_SRC)}\ninstalled_sha256=${sha(INSTALLED)}\n`;

function fakeSpawn({ code = 0, out = '==> done\n', hold = null, never = false } = {}) {
  const calls = [];
  const fn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts, at: Date.now() });
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => setImmediate(() => child.emit('close', null));
    const finish = () => { child.stdout.emit('data', Buffer.from(out)); child.emit('close', code); };
    if (never) return child;
    if (hold) hold.then(finish); else setImmediate(finish);
    return child;
  };
  fn.calls = calls;
  return fn;
}

function host({ uid = 0, platform = 'linux', files = {}, systemd = true, iptables = true, sudoRule = true, spawn = fakeSpawn(), lastSync } = {}) {
  const f = { [REPO_SCRIPT]: REPO_SRC, ...files };
  for (const k of Object.keys(f)) if (f[k] === null) delete f[k];
  const order = [];
  const deps = {
    platform,
    getuid: () => uid,
    repoDir: REPO,
    readFile: (p) => { if (f[p] == null) throw enoent(p); return f[p]; },
    stat: (p) => { if (p === '/run/systemd/system' && systemd) return { isDirectory: () => true }; throw enoent(p); },
    exec: async (cmd, args) => {
      const key = [cmd, ...args].join(' ');
      order.push(key);
      if (key === 'iptables --version') return iptables ? { code: 0, stdout: 'iptables v1.8.10 (nf_tables)\n', stderr: '' } : { code: -1, missing: true, stdout: '', stderr: '' };
      if (key === `sudo -n -l ${H.INSTALLED_SCRIPT}`) return sudoRule ? { code: 0, stdout: `${H.INSTALLED_SCRIPT}\n`, stderr: '' } : { code: 1, stdout: '', stderr: '' };
      return { code: -1, missing: true, stdout: '', stderr: '' };
    },
    spawn: (...a) => { order.push('spawn'); return spawn(...a); },
    lastSync: lastSync || (async () => { order.push('sync'); return { status: 'ok' }; }),
  };
  return { deps, spawn, order, files: f };
}
const SUDO_FILES = { [H.INSTALLED_SCRIPT]: INSTALLED, [A.STAMP_FILE]: STAMP };

// A broken wait or lock must fail its test, not hang the file.
const T = (name, fn) => test(name, { timeout: 15_000 }, fn);
const FAST = { syncWaitMs: 200, claimWaitMs: 200, pollMs: 10 };
const boot = (h, version, extra = {}) => A.autoApply({ deps: h.deps, version, db, ...FAST, ...extra });
const jobRows = () => db.prepare("SELECT ok, error FROM job_runs WHERE job = 'host-hardening-auto' ORDER BY id").all();
const audits = (action) => db.prepare('SELECT detail, actor_kind FROM audit_log WHERE action = ? ORDER BY id').all(action);
const mails = () => db.prepare("SELECT to_email, subject, body_text, idempotency_key FROM email_queue WHERE source = 'host-hardening-auto' ORDER BY id").all();

const tag = () => randomBytes(4).toString('hex');
function mkUser(role) {
  const t = tag();
  const id = db.prepare("INSERT INTO users (name, email, username, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${t}`, `u${t}@t.test`, `u${t}`, role, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return { id, token };
}
const ADMIN = mkUser('platform_admin');
const PLAIN = mkUser('user');

beforeEach(() => {
  A.stopHostHardeningAuto();
  db.prepare('DELETE FROM settings WHERE key IN (?, ?, ?)').run(A.STATE_KEY, A.SETTING_KEY, H.LAST_RUN_KEY);
  db.prepare("DELETE FROM email_queue WHERE source = 'host-hardening-auto'").run();
});

// ---- version change ----

T('root: the first boot after an upgrade runs the repo copy once; the next boot of the same version runs nothing; the next upgrade runs again', async () => {
  const h = host({ uid: 0 });
  const r1 = await boot(h, '2.146.0');
  assert.equal(r1.outcome, 'applied', JSON.stringify(r1));
  assert.equal(h.spawn.calls.length, 1);
  assert.deepEqual([h.spawn.calls[0].cmd, h.spawn.calls[0].args], ['bash', [REPO_SCRIPT]]);
  assert.equal(h.spawn.calls[0].opts.shell, undefined);
  const st = A.readState(db);
  assert.equal(st.version, '2.146.0');
  assert.equal(st.ok, true);
  assert.equal(st.mode, 'root');
  assert.equal(audits('host-hardening-auto-applied').at(-1).actor_kind, 'system');

  const r2 = await boot(h, '2.146.0');
  assert.equal(r2.outcome, 'up-to-date');
  assert.equal(h.spawn.calls.length, 1, 'a second boot of the same version runs nothing');

  const r3 = await boot(h, '2.146.1');
  assert.equal(r3.outcome, 'applied');
  assert.equal(h.spawn.calls.length, 2);
  assert.equal(A.readState(db).from_version, '2.146.0');
});

T('a failed run is recorded once (Job Health failing, audit) and is not retried on the next boot of the same version', async () => {
  const h = host({ uid: 0, spawn: fakeSpawn({ code: 1, out: '==> start\nxx  network: iptables-restore failed\n' }) });
  const before = jobRows().length;
  const r = await boot(h, '2.150.0');
  assert.equal(r.outcome, 'failed');
  const st = A.readState(db);
  assert.equal(st.ok, false);
  assert.equal(st.exit_code, 1);
  assert.match(st.reason, /iptables-restore failed/);
  const rows = jobRows().slice(before);
  assert.equal(rows.at(-1).ok, 0);
  assert.match(rows.at(-1).error, /2\.150\.0/);
  assert.ok(audits('host-hardening-auto-failed').length >= 1);
  assert.equal((await boot(h, '2.150.0')).outcome, 'up-to-date');
  assert.equal(h.spawn.calls.length, 1);
});

// ---- root vs non-root ----

T('non-root with a matching stamp runs the root-owned copy through sudo with no arguments, never the repo copy', async () => {
  const h = host({ uid: 1000, files: SUDO_FILES });
  const r = await boot(h, '2.146.0');
  assert.equal(r.outcome, 'applied', JSON.stringify(r));
  assert.deepEqual(h.spawn.calls.map((c) => [c.cmd, c.args]), [['sudo', ['-n', H.INSTALLED_SCRIPT]]]);
  assert.equal(A.readState(db).mode, 'sudo');
});

T('non-root: a stamp for another script, no stamp, a changed installed copy, or no sudo rule never run anything; admins are mailed once per version only where a sudo rule exists', async () => {
  const other = `version=2.144.0\nsource_sha256=${sha('#!/bin/bash\necho old\n')}\ninstalled_sha256=${sha(INSTALLED)}\n`;
  const cases = [
    ['stamp names another script', { ...SUDO_FILES, [A.STAMP_FILE]: other }, true, 'stale', 1],
    ['no stamp', { ...SUDO_FILES, [A.STAMP_FILE]: null }, true, 'no-stamp', 1],
    ['installed copy changed', { ...SUDO_FILES, [H.INSTALLED_SCRIPT]: `${INSTALLED}echo extra\n` }, true, 'stale', 1],
    ['stamp from another install', { ...SUDO_FILES, [A.STAMP_FILE]: `version=2.146.0\nsource_sha256=${sha(REPO_SRC)}\ninstalled_sha256=${sha('other')}\n` }, true, 'stale', 1],
    ['copy baked for another directory, stamped consistently', {
      ...SUDO_FILES, [H.INSTALLED_SCRIPT]: H.expectedInstalledCopy(REPO_SRC, '/srv/elsewhere'),
      [A.STAMP_FILE]: `version=2.146.0\nsource_sha256=${sha(REPO_SRC)}\ninstalled_sha256=${sha(H.expectedInstalledCopy(REPO_SRC, '/srv/elsewhere'))}\n`,
    }, true, 'stale', 1],
    ['no sudo rule', SUDO_FILES, false, 'manual', 0],
    ['no installed copy', { [H.INSTALLED_SCRIPT]: null, [A.STAMP_FILE]: null }, true, 'manual', 0],
  ];
  const adminEmail = db.prepare('SELECT email FROM users WHERE id = ?').get(ADMIN.id).email;
  for (const [name, files, sudoRule, kind, mailCount] of cases) {
    db.prepare("DELETE FROM email_queue WHERE source = 'host-hardening-auto'").run();
    const h = host({ uid: 1000, files, sudoRule });
    const r = await boot(h, '2.146.0');
    assert.equal(r.outcome, 'stale', `${name}: ${JSON.stringify(r)}`);
    assert.equal(h.spawn.calls.length, 0, `${name}: nothing may run`);
    assert.equal(r.message, A.staleMessage('2.146.0', kind), name);
    assert.ok(r.message.includes(A.NOT_ROOT_NOTE), name);
    assert.equal(A.retryDelay(r), A.STALE_RETRY_MS, `${name}: checked again hourly`);
    assert.equal(A.readState(db), null, `${name}: not recorded, so the next check looks again`);
    await boot(h, '2.146.0');
    assert.equal(h.spawn.calls.length, 0);
    const m = mails().filter((x) => x.to_email === adminEmail);
    assert.equal(m.length, mailCount, `${name}: ${mailCount} mail per admin per version, got ${m.length}`);
    if (mailCount) assert.ok(m[0].body_text.startsWith(A.staleMessage('2.146.0', kind)), name);
  }
  const h = host({ uid: 1000, files: { ...SUDO_FILES, [A.STAMP_FILE]: null } });
  await boot(h, '2.146.1');
  assert.equal(mails().filter((x) => /2\.146\.1/.test(x.subject)).length >= 1, true, 'a new version mails again');
  assert.equal(A.NOT_ROOT_NOTE, 'On this server AppCrane is not root, so a release that changes the hardening script needs this one root command; upgrades that do not change it apply automatically.');
  assert.match(A.staleMessage('2.146.0', 'no-stamp'), /has no version stamp yet \(it was installed before automatic apply existed\).*sudo bash scripts\/install-host-hardening\.sh/);
});

T('non-root, stale: after the operator runs the install, the next hourly check applies it without a restart', async () => {
  const h = host({ uid: 1000, files: { ...SUDO_FILES, [A.STAMP_FILE]: null } });
  const first = await A.startHostHardeningAuto({ deps: h.deps, version: '2.160.0', db, ...FAST, staleRetryMs: 60 });
  assert.equal(first.outcome, 'stale');
  assert.equal(A._hasTimer(), true, 'a re-check is scheduled');
  h.files[A.STAMP_FILE] = STAMP;
  for (let i = 0; i < 100 && h.spawn.calls.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal((await A._current()).outcome, 'applied');
  assert.deepEqual(h.spawn.calls.map((c) => [c.cmd, c.args]), [['sudo', ['-n', H.INSTALLED_SCRIPT]]]);
  assert.equal(A._hasTimer(), false, 'no further check once applied');
});

// ---- setting, applicability ----

T('the setting off runs nothing; turning it back on applies on the next boot', async () => {
  const h = host({ uid: 0 });
  A.setEnabled(db, false, ADMIN.id);
  assert.equal(A.isEnabled(db), false);
  assert.equal((await boot(h, '2.146.0')).outcome, 'disabled');
  assert.equal(h.spawn.calls.length, 0);
  A.setEnabled(db, true, ADMIN.id);
  assert.equal((await boot(h, '2.146.0')).outcome, 'applied');
  assert.equal(h.spawn.calls.length, 1);
});

T('not Linux, no systemd, or no iptables: nothing runs', async () => {
  for (const [name, opts] of [['darwin', { platform: 'darwin' }], ['no systemd', { systemd: false }], ['no iptables', { iptables: false }]]) {
    const h = host({ uid: 0, ...opts });
    const r = await boot(h, '2.146.0');
    assert.equal(r.outcome, 'not-applicable', name);
    assert.equal(h.spawn.calls.length, 0, name);
  }
});

// ---- ordering, background, timeout, one run at a time ----

T('waits for AppCrane\'s first APPCRANE-PUBLISH sync before running the script', async () => {
  let n = 0;
  const h = host({ uid: 0, lastSync: async () => { h.order.push('poll'); return ++n < 4 ? null : { status: 'ok' }; } });
  const r = await boot(h, '2.146.0', { syncWaitMs: 5000 });
  assert.equal(r.outcome, 'applied');
  assert.deepEqual(h.order.filter((x) => x === 'poll' || x === 'spawn'), ['poll', 'poll', 'poll', 'poll', 'spawn'], 'the script starts only after a sync has been seen');
  assert.equal(A.readState(db).publish_sync, 'ok');
});

T('no successful sync inside the wait (none, or failed): nothing runs, nothing is recorded, outcome waiting, checked again in 10 minutes', async () => {
  for (const [name, sync, want] of [['none', null, 'none'], ['failed', { status: 'failed' }, 'failed']]) {
    const h = host({ uid: 0, lastSync: async () => sync });
    const t0 = Date.now();
    const r = await boot(h, '2.146.0', { syncWaitMs: 150 });
    assert.ok(Date.now() - t0 >= 150, name);
    assert.equal(r.outcome, 'waiting', `${name}: ${JSON.stringify(r)}`);
    assert.equal(r.publish_sync, want, name);
    assert.equal(h.spawn.calls.length, 0, `${name}: the DROP must not go in before APPCRANE-PUBLISH is filled`);
    assert.equal(A.readState(db), null, name);
    assert.equal(A.retryDelay(r), A.WAITING_RETRY_MS, name);
  }
});

T('waiting is retried on the timer until a sync is ok, then applied once', async () => {
  let ok = false;
  const h = host({ uid: 0, lastSync: async () => (ok ? { status: 'ok' } : { status: 'failed' }) });
  const first = await A.startHostHardeningAuto({ deps: h.deps, version: '2.161.0', db, ...FAST, syncWaitMs: 30, waitingRetryMs: 60 });
  assert.equal(first.outcome, 'waiting');
  assert.equal(A._hasTimer(), true);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(h.spawn.calls.length, 0, 'still waiting while the sync fails');
  ok = true;
  for (let i = 0; i < 100 && h.spawn.calls.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal((await A._current()).outcome, 'applied');
  assert.equal(h.spawn.calls.length, 1);
  assert.equal(A.readState(db).publish_sync, 'ok');
  assert.equal(A._hasTimer(), false);
});

T('the script runs with a minimal environment: .env values such as APPCRANE_INPUT_FORCE do not reach it', async () => {
  const saved = process.env.APPCRANE_INPUT_FORCE;
  process.env.APPCRANE_INPUT_FORCE = '1';
  process.env.APPCRANE_INPUT_ALLOW_TEST_LEAK = 'x';
  try {
    for (const [uid, files] of [[0, {}], [1000, SUDO_FILES]]) {
      db.prepare('DELETE FROM settings WHERE key = ?').run(A.STATE_KEY);
      const h = host({ uid, files });
      assert.equal((await boot(h, '2.146.0')).outcome, 'applied');
      const env = h.spawn.calls[0].opts.env;
      assert.deepEqual(env, A.scriptEnv(), `uid ${uid}`);
      assert.deepEqual(Object.keys(env).sort(), ['HOME', 'LANG', 'LC_ALL', 'PATH']);
      assert.equal(env.PATH, A.SAFE_PATH);
      assert.equal(env.APPCRANE_INPUT_FORCE, undefined);
    }
  } finally {
    if (saved === undefined) delete process.env.APPCRANE_INPUT_FORCE; else process.env.APPCRANE_INPUT_FORCE = saved;
    delete process.env.APPCRANE_INPUT_ALLOW_TEST_LEAK;
  }
});

// ---- warnings ----

const NO_DROP_UNSYNCED = '==> network: start\n!!  network: AppCrane has not synced published ports yet; Apply again after the server is on v2.145.0 (APPCRANE-PUBLISH lacks tcp:5432, which docker-proxy listens on). DOCKER-USER installed WITHOUT the DROP on eth0\n==> done\n';
const NO_DROP_HELPER = '!!  network: DOCKER-USER installed WITHOUT the DROP on eth0: no publish helper. Published ports stay open to the internet until that is fixed and Apply runs again\n';
const OTHER_WARN = '==> journald ok\n!!  gvisor: no gVisor release for riscv64 — skipped\n';

T('a run that left out the DROP, or printed any warning, is a warning, not done: the next check runs it again (10 minutes while unsynced, hourly while the DROP is missing, otherwise at the next boot)', async () => {
  for (const [name, out, delay, noDrop] of [
    ['unsynced', NO_DROP_UNSYNCED, A.WAITING_RETRY_MS, true],
    ['no publish helper', NO_DROP_HELPER, A.STALE_RETRY_MS, true],
    ['other warning', OTHER_WARN, null, false], // a warning that never clears is not re-run on a timer, only at the next boot
  ]) {
    db.prepare('DELETE FROM settings WHERE key = ?').run(A.STATE_KEY);
    const h = host({ uid: 0, spawn: fakeSpawn({ out }) });
    const r = await boot(h, '2.170.0');
    assert.equal(r.outcome, 'applied-with-warnings', `${name}: ${JSON.stringify(r)}`);
    assert.equal(r.severity, 'warning', name);
    const st = A.readState(db);
    assert.equal(st.done, false, name);
    assert.equal(st.ok, true, name);
    assert.equal(st.no_drop, noDrop, name);
    assert.equal(st.warnings.length, 1, name);
    assert.equal(A.retryDelay(r), delay, name);
    const again = await boot(h, '2.170.0');
    assert.equal(h.spawn.calls.length, 2, `${name}: the same version runs again`);
    assert.equal(again.outcome, 'applied-with-warnings');
  }
  const h = host({ uid: 0 });
  assert.equal((await boot(h, '2.170.0')).outcome, 'applied');
  assert.equal(A.readState(db).done, true);
  assert.equal((await boot(h, '2.170.0')).outcome, 'up-to-date', 'a clean run is done');

  await boot(host({ uid: 0 }), '2.169.0');
  const hw = host({ uid: 0, spawn: fakeSpawn({ out: OTHER_WARN }) });
  await boot(hw, '2.172.0');
  await boot(hw, '2.172.0');
  assert.equal(A.readState(db).from_version, '2.169.0', 'a retry of the same version keeps the version it upgraded from');
});

T('an automatic run updates the Host limits card\'s last run, marked automatic', async () => {
  const h = host({ uid: 0, spawn: fakeSpawn({ code: 1, out: 'xx  boom\n' }) });
  await boot(h, '2.171.0');
  const l = H.readLastRun(db);
  assert.equal(l.automatic, true);
  assert.equal(l.ok, false);
  assert.equal(l.exit_code, 1);
  assert.equal(l.version, '2.171.0');
  assert.match(l.by, /automatically after the upgrade to 2\.171\.0/);
});

T('startup returns at once and the run happens in the background, with a timeout', async () => {
  let release;
  const hold = new Promise((r) => { release = r; });
  const h = host({ uid: 0, spawn: fakeSpawn({ hold }) });
  const p = A.startHostHardeningAuto({ deps: h.deps, version: '2.146.0', db, ...FAST });
  assert.ok(p instanceof Promise);
  assert.deepEqual(h.order, [], 'startup returns before it looks at the host at all');
  assert.equal(A.readState(db), null, 'nothing recorded synchronously');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(h.spawn.calls.length, 1, 'running in the background');
  assert.equal(H.isRunning(), true, 'holds the one-run lock, so Apply answers 409 meanwhile');
  release();
  assert.equal((await p).outcome, 'applied');
  assert.equal(H.isRunning(), false);

  const h2 = host({ uid: 0, spawn: fakeSpawn({ never: true }) });
  const r = await boot(h2, '2.147.0', { timeoutMs: 80 });
  assert.equal(r.outcome, 'failed');
  assert.equal(A.readState(db).timed_out, true);
  assert.equal(A.readState(db).reason, 'timed out');
  assert.equal(H.isRunning(), false);
});

T('an Apply in progress is waited for; past the bound nothing runs and nothing is recorded', async () => {
  assert.ok(H.claimRun());
  try {
    const h = host({ uid: 0 });
    const r = await boot(h, '2.146.0', { claimWaitMs: 100 });
    assert.equal(r.outcome, 'busy');
    assert.equal(h.spawn.calls.length, 0);
    assert.equal(A.readState(db), null);
  } finally { H.releaseRun(); }
});

T('the default sync source is the host firewall\'s own last sync', async () => {
  const F = await import('../server/services/hostFirewall/index.js');
  assert.equal(typeof F.getLastSync, 'function');
  const src = readFileSync(join(ROOT, 'server', 'services', 'hostHardeningAuto.js'), 'utf8');
  assert.match(src, /import\('\.\/hostFirewall\/index\.js'\)\)\.getLastSync\(\)/);
});

// ---- routes ----

let deps = host({ uid: 1000, files: { ...SUDO_FILES, [A.STAMP_FILE]: null } }).deps;
const app = express();
app.use(express.json());
app.use('/api/settings', (req, res, next) => createHostHardeningRouter({ ...deps, version: '2.146.0' })(req, res, next));
app.use('/api/settings', settingsRoutes);
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
async function call(method, path, body, token) {
  const res = await fetch(`${BASE}${path}`, {
    method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}

T('GET /host-hardening/auto: platform admin only; shows the warning while the root copy is stale, the last run once applied', async () => {
  assert.equal((await call('GET', '/api/settings/host-hardening/auto')).status, 401);
  assert.equal((await call('GET', '/api/settings/host-hardening/auto', null, PLAIN.token)).status, 403);
  const r = await call('GET', '/api/settings/host-hardening/auto', null, ADMIN.token);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { version: '2.146.0', enabled: true, last: null, pending: null, warning: A.staleMessage('2.146.0', 'no-stamp') });
  deps = host({ uid: 1000, files: SUDO_FILES }).deps;
  assert.equal((await call('GET', '/api/settings/host-hardening/auto', null, ADMIN.token)).body.warning, null);
  await boot(host({ uid: 0 }), '2.146.0');
  const last = (await call('GET', '/api/settings/host-hardening/auto', null, ADMIN.token)).body.last;
  assert.equal(last.version, '2.146.0');
  assert.equal(last.ok, true);
  db.prepare('DELETE FROM settings WHERE key = ?').run(A.STATE_KEY);
  await boot(host({ uid: 0, spawn: fakeSpawn({ out: OTHER_WARN }) }), '2.146.0');
  const w = (await call('GET', '/api/settings/host-hardening/auto', null, ADMIN.token)).body;
  assert.equal(w.last.done, false);
  assert.match(w.warning, /ended with warnings \(gvisor: no gVisor release for riscv64.*every hour/);
});

T('PUT /host-hardening/auto toggles the setting (platform admin, audited); the generic settings PUT cannot write the setting or the last run', async () => {
  assert.equal((await call('PUT', '/api/settings/host-hardening/auto', { enabled: false }, PLAIN.token)).status, 403);
  assert.equal((await call('PUT', '/api/settings/host-hardening/auto', { enabled: 'no' }, ADMIN.token)).status, 400);
  const off = await call('PUT', '/api/settings/host-hardening/auto', { enabled: false }, ADMIN.token);
  assert.equal(off.status, 200);
  assert.equal(off.body.enabled, false);
  assert.equal(A.isEnabled(db), false);
  assert.equal(JSON.parse(audits('host-hardening-auto-set').at(-1).detail).enabled, false);
  for (const key of [A.SETTING_KEY, A.STATE_KEY, 'host%5Fhardening_auto_last']) {
    const r = await call('PUT', `/api/settings/${key}`, { value: key === A.SETTING_KEY ? '1' : '{"version":"9.9.9","ok":true}' }, ADMIN.token);
    assert.equal(r.status, 403, key);
  }
  assert.equal(A.isEnabled(db), false);
  assert.equal(A.readState(db), null);
  assert.equal((await call('PUT', '/api/settings/host-hardening/auto', { enabled: true }, ADMIN.token)).body.enabled, true);
});
