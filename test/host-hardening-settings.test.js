import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'events';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import express from 'express';

// Settings > Job Health > Host limits: per-item status of what
// scripts/host-hardening.sh sets, read without root, and Apply, which runs the
// script as root (directly, or through the sudoers rule install-host-hardening.sh
// writes) behind the caller's two-factor code. The host is faked: files and
// command outputs are injected, as in host-vulns.test.js. `pro config show`
// and `sudo -n -l` behaviour were measured in an ubuntu:24.04 container.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-hardening-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_SRC = readFileSync(join(ROOT, 'scripts', 'host-hardening.sh'), 'utf8');

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const totp = await import('../server/services/totp.js');
const mfa = await import('../server/services/mfa.js');
const H = await import('../server/services/hostHardening.js');
const { createHostHardeningRouter } = await import('../server/routes/hostHardening.js');
const settingsRoutes = (await import('../server/routes/settings.js')).default;
initDb();
const db = getDb();

// ---- fake host ----

const REPO = '/opt/appcrane';
const enoent = (p) => Object.assign(new Error(`ENOENT: ${p}`), { code: 'ENOENT' });
const dirStat = (mode = 0o40750, uid = 998) => ({ isDirectory: () => true, mode, uid, size: 4096 });
const fileStat = (size, uid = 0) => ({ isDirectory: () => false, mode: 0o100600, uid, size });

const PRO_ON = 'http_proxy                     None\nupdate_messaging_timer         21600\napt_news                       True\napt_news_url                   https://motd.example/aptnews.json\nlxd_guest_attach               off\n';
const PRO_OFF = PRO_ON.replace('apt_news                       True', 'apt_news                       False');
const DF = (mount) => `Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/sda1         81106868 20000000  61106868      25% ${mount}\n`;
const PERIODIC_ON = 'APT::Periodic "";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n';

const HARDENED = {
  files: {
    '/etc/systemd/journald.conf': '[Journal]\n#SystemMaxUse=\n',
    '/etc/systemd/journald.conf.d/50-appcrane.conf': '# Written by AppCrane scripts/host-hardening.sh\n[Journal]\nSystemMaxUse=500M\nSystemKeepFree=2G\nMaxRetentionSec=1month\n',
    '/etc/logrotate.conf': 'weekly\ninclude /etc/logrotate.d\n',
    '/etc/logrotate.d/rsyslog': '/var/log/syslog\n{\n\tmaxsize 200M\n\trotate 7\n\tdaily\n}\n',
    '/etc/systemd/system/logrotate.timer.d/50-appcrane.conf': '[Timer]\nOnCalendar=\nOnCalendar=hourly\nAccuracySec=5min\n',
    '/etc/docker/daemon.json': '{"log-opts":{"max-size":"10m","max-file":"3"}}\n',
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ncaddy:x:998:998::/var/lib/caddy:/usr/sbin/nologin\n',
    [`${REPO}/scripts/host-hardening.sh`]: REPO_SRC,
  },
  dirs: {
    '/etc/systemd/journald.conf.d': ['50-appcrane.conf'],
    '/etc/systemd/system/logrotate.timer.d': ['50-appcrane.conf'],
  },
  stats: {
    '/var/lib/dpkg/status': fileStat(100000),
    '/var/log/caddy': dirStat(),
    [`${REPO}/data`]: dirStat(0o40755, 1000),
    '/appcrane-disk-reserve': fileStat(1024 ** 3),
  },
  exec: {
    'journalctl --disk-usage': { code: 0, stdout: 'Archived and active journals take up 312.0M in the file system.\n' },
    'pro config show': { code: 0, stdout: PRO_OFF },
    'dpkg-query -W -f=${Status} unattended-upgrades': { code: 0, stdout: 'install ok installed' },
    'apt-config dump APT::Periodic': { code: 0, stdout: PERIODIC_ON },
    [`df -P ${REPO}/data`]: { code: 0, stdout: DF('/') },
    [`sudo -n -l ${H.INSTALLED_SCRIPT}`]: { code: 0, stdout: `${H.INSTALLED_SCRIPT}\n` },
  },
};

function host(over = {}, { uid = 1000, platform = 'linux', spawn } = {}) {
  const files = { ...HARDENED.files, ...over.files };
  const dirs = { ...HARDENED.dirs, ...over.dirs };
  const stats = { ...HARDENED.stats, ...over.stats };
  const exec = { ...HARDENED.exec, ...over.exec };
  for (const t of [files, dirs, stats, exec]) for (const k of Object.keys(t)) if (t[k] === null) delete t[k];
  const calls = [];
  return {
    calls,
    deps: {
      platform,
      getuid: () => uid,
      repoDir: REPO,
      dataDir: () => `${REPO}/data`,
      readFile: (p) => { if (files[p] == null) throw enoent(p); return files[p]; },
      readdir: (p) => { if (!dirs[p]) throw enoent(p); return dirs[p]; },
      stat: (p) => {
        if (stats[p]) return stats[p];
        if (files[p] != null) return fileStat(files[p].length);
        if (dirs[p]) return dirStat();
        throw enoent(p);
      },
      exec: async (cmd, args) => {
        const key = [cmd, ...args].join(' ');
        calls.push(key);
        return { stdout: '', stderr: '', ...(exec[key] || { code: -1, missing: true }) };
      },
      spawn,
    },
  };
}

const item = (items, id) => items.find((i) => i.id === id);
const installedCopy = H.expectedInstalledCopy(REPO_SRC, REPO);
const SUDO_FILES = { [H.INSTALLED_SCRIPT]: installedCopy };

// ---- status ----

test('a fully hardened host: every item applied, in the contract order', async () => {
  const items = await H.checkItems(host().deps);
  assert.deepEqual(items.map((i) => i.id), ['journal', 'syslog-rotation', 'logrotate-hourly', 'docker-log-defaults', 'apt-news', 'unattended-upgrades', 'caddy-log-dir', 'disk-reserve']);
  for (const i of items) assert.equal(i.state, 'applied', `${i.id}: ${i.detail}`);
  assert.match(item(items, 'journal').detail, /SystemMaxUse=500M in \/etc\/systemd\/journald\.conf\.d\/50-appcrane\.conf; journal uses 312\.0M/);
  assert.match(item(items, 'disk-reserve').detail, /sudo rm \/appcrane-disk-reserve/);
  for (const i of items) assert.equal(typeof i.label, 'string');
});

test('journal: no limit is missing; a limit journald never applied (journal above it) is missing; a later drop-in wins', async () => {
  let items = await H.checkItems(host({ files: { '/etc/systemd/journald.conf.d/50-appcrane.conf': null }, dirs: { '/etc/systemd/journald.conf.d': [] } }).deps);
  assert.equal(item(items, 'journal').state, 'missing');
  assert.match(item(items, 'journal').detail, /no SystemMaxUse set.*journal uses 312\.0M/);

  items = await H.checkItems(host({ exec: { 'journalctl --disk-usage': { code: 0, stdout: 'Archived and active journals take up 4.0G in the file system.\n' } } }).deps);
  assert.equal(item(items, 'journal').state, 'missing');
  assert.match(item(items, 'journal').detail, /has not applied the limit/);

  items = await H.checkItems(host({
    files: { '/etc/systemd/journald.conf.d/60-local.conf': '[Journal]\nSystemMaxUse=\n' },
    dirs: { '/etc/systemd/journald.conf.d': ['60-local.conf', '50-appcrane.conf'] },
  }).deps);
  assert.equal(item(items, 'journal').state, 'missing', 'an empty SystemMaxUse= in a later file resets the limit');

  items = await H.checkItems(host({ files: { '/etc/systemd/journald.conf': null, '/etc/systemd/journald.conf.d/50-appcrane.conf': null }, dirs: { '/etc/systemd/journald.conf.d': null }, exec: { 'journalctl --disk-usage': null } }).deps);
  assert.equal(item(items, 'journal').state, 'not-applicable');
});

test('syslog rotation: maxsize applied, none missing, no rsyslog file not-applicable; a commented maxsize does not count', async () => {
  const s = async (text) => item(await H.checkItems(host({ files: { '/etc/logrotate.d/rsyslog': text } }).deps), 'syslog-rotation');
  assert.equal((await s('/var/log/syslog\n{\n\trotate 7\n\tdaily\n}\n')).state, 'missing');
  assert.equal((await s('/var/log/syslog\n{\n#\tmaxsize 200M\n\tdaily\n}\n')).state, 'missing');
  assert.equal((await s(null)).state, 'not-applicable');
});

test('logrotate hourly: drop-in applied; none missing; an empty OnCalendar= after hourly resets it; no logrotate not-applicable', async () => {
  const s = async (over) => item(await H.checkItems(host(over).deps), 'logrotate-hourly');
  assert.equal((await s({ dirs: { '/etc/systemd/system/logrotate.timer.d': null } })).state, 'missing');
  assert.equal((await s({
    files: { '/etc/systemd/system/logrotate.timer.d/90-x.conf': '[Timer]\nOnCalendar=\nOnCalendar=daily\n' },
    dirs: { '/etc/systemd/system/logrotate.timer.d': ['90-x.conf', '50-appcrane.conf'] },
  })).state, 'missing');
  assert.equal((await s({ dirs: { '/etc/systemd/system/logrotate.timer.d': null }, files: { '/etc/logrotate.conf': null } })).state, 'not-applicable');
});

test('docker log defaults: log-opts or log-driver applied; none or no file missing; invalid JSON unknown', async () => {
  const s = async (text) => item(await H.checkItems(host({ files: { '/etc/docker/daemon.json': text } }).deps), 'docker-log-defaults');
  assert.equal((await s('{"log-driver":"journald"}')).state, 'applied');
  assert.equal((await s('{"storage-driver":"overlay2"}')).state, 'missing');
  assert.equal((await s(null)).state, 'missing');
  assert.equal((await s('{"storage-driver": ')).state, 'unknown');
});

test('apt news: False applied, True missing, no pro not-applicable, pro failing unknown', async () => {
  const s = async (r) => item(await H.checkItems(host({ exec: { 'pro config show': r } }).deps), 'apt-news');
  assert.equal((await s({ code: 0, stdout: PRO_ON })).state, 'missing');
  assert.equal((await s(null)).state, 'not-applicable');
  const failed = await s({ code: 1, stderr: "An unexpected error occurred: [Errno 13] Permission denied: '/nonexistent'\n" });
  assert.equal(failed.state, 'unknown');
  assert.match(failed.detail, /error occurred/);
});

test('unattended upgrades: reuses hostVulns; not installed or periodic 0 missing; no dpkg not-applicable', async () => {
  const s = async (over) => item(await H.checkItems(host(over).deps), 'unattended-upgrades');
  assert.equal((await s({ exec: { 'dpkg-query -W -f=${Status} unattended-upgrades': { code: 1, stderr: 'no packages found' } } })).state, 'missing');
  const off = await s({ exec: { 'apt-config dump APT::Periodic': { code: 0, stdout: PERIODIC_ON.replace('Unattended-Upgrade "1"', 'Unattended-Upgrade "0"') } } });
  assert.equal(off.state, 'missing');
  assert.match(off.detail, /installed but not enabled/);
  assert.equal((await s({ stats: { '/var/lib/dpkg/status': null } })).state, 'not-applicable');
});

test('caddy log dir: missing when absent or owned by another user', async () => {
  const s = async (over) => item(await H.checkItems(host(over).deps), 'caddy-log-dir');
  assert.equal((await s({ stats: { '/var/log/caddy': null } })).state, 'missing');
  const rootOwned = await s({ stats: { '/var/log/caddy': dirStat(0o40755, 0) } });
  assert.equal(rootOwned.state, 'missing');
  assert.match(rootOwned.detail, /owned by uid 0, not caddy/);
});

test('disk reserve: looked for at the DATA_DIR mount; small or absent missing; df failing unknown', async () => {
  const s = async (over) => item(await H.checkItems(host(over).deps), 'disk-reserve');
  const onData = await s({ exec: { [`df -P ${REPO}/data`]: { code: 0, stdout: DF('/srv/data') } }, stats: { '/srv/data/appcrane-disk-reserve': fileStat(1024 ** 3) } });
  assert.equal(onData.state, 'applied');
  assert.match(onData.detail, /\/srv\/data\/appcrane-disk-reserve/);
  assert.equal((await s({ stats: { '/appcrane-disk-reserve': fileStat(1024) } })).state, 'missing');
  assert.equal((await s({ stats: { '/appcrane-disk-reserve': null } })).state, 'missing');
  assert.equal((await s({ exec: { [`df -P ${REPO}/data`]: { code: 1, stderr: 'df: error' } } })).state, 'unknown');
});

// ---- run mode ----

test('mode: root runs the repo copy directly', async () => {
  const r = await H.detectRunMode(host({}, { uid: 0 }).deps);
  assert.equal(r.mode, 'root');
  assert.deepEqual(r.argv, ['bash', [`${REPO}/scripts/host-hardening.sh`]]);
});

test('mode: non-root with the installed copy and the sudo rule runs the installed copy, never the repo copy', async () => {
  const h = host({ files: SUDO_FILES });
  const r = await H.detectRunMode(h.deps);
  assert.equal(r.mode, 'sudo');
  assert.deepEqual(r.argv, ['sudo', ['-n', H.INSTALLED_SCRIPT]]);
  assert.equal(r.command, `sudo -n ${H.INSTALLED_SCRIPT}`);
  assert.equal(r.installed_copy_stale, false);
  assert.ok(h.calls.includes(`sudo -n -l ${H.INSTALLED_SCRIPT}`));
});

test('mode: an installed copy that differs from the repo script is stale, with the refresh command', async () => {
  const r = await H.detectRunMode(host({ files: { [H.INSTALLED_SCRIPT]: installedCopy.replace('500M', '400M') } }).deps);
  assert.equal(r.mode, 'sudo');
  assert.equal(r.installed_copy_stale, true);
  assert.equal(r.setup_command, 'sudo bash /opt/appcrane/scripts/install-host-hardening.sh');
  assert.notEqual(r.setup_command, r.command, 'the refresh command is not the Apply command');
  const moved = await H.detectRunMode({ ...host({ files: { [H.INSTALLED_SCRIPT]: H.expectedInstalledCopy(REPO_SRC, '/old/path') } }).deps });
  assert.equal(moved.installed_copy_stale, true, 'a copy baked for another repo path is stale');
});

test('mode: non-root without the sudo rule (or without the copy) is manual, with the command', async () => {
  const noRule = await H.detectRunMode(host({ files: SUDO_FILES, exec: { [`sudo -n -l ${H.INSTALLED_SCRIPT}`]: { code: 1, stderr: 'sudo: a password is required' } } }).deps);
  assert.equal(noRule.mode, 'manual');
  assert.equal(noRule.command, `sudo bash ${REPO}/scripts/host-hardening.sh`);
  assert.equal(noRule.argv, undefined);
  const noCopy = await H.detectRunMode(host().deps);
  assert.equal(noCopy.mode, 'manual');
  assert.equal(noCopy.setup_command, `sudo bash ${REPO}/scripts/install-host-hardening.sh`);
  assert.equal(noRule.setup_command, `sudo bash ${REPO}/scripts/install-host-hardening.sh`);
  const noSudo = await H.detectRunMode(host({ files: SUDO_FILES, exec: { [`sudo -n -l ${H.INSTALLED_SCRIPT}`]: null } }).deps);
  assert.equal(noSudo.mode, 'manual');
});

test('mode: not Linux is unsupported and runs nothing', async () => {
  const h = host({}, { platform: 'darwin', uid: 0 });
  const r = await H.detectRunMode(h.deps);
  assert.equal(r.mode, 'unsupported');
  assert.equal(r.command, null);
  assert.equal(h.calls.length, 0);
});

test('the installed copy is the repo script with only the REPO_DIR line baked', () => {
  const a = REPO_SRC.split('\n');
  const b = installedCopy.split('\n');
  const diff = a.map((l, i) => (l === b[i] ? null : [l, b[i]])).filter(Boolean);
  assert.deepEqual(diff, [['REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"', "REPO_DIR='/opt/appcrane'"]]);
});

// ---- output ----

test('output is ANSI-stripped and capped to its last 64 KiB', async () => {
  const big = `\x1b[1;36m==>\x1b[0m start\n${'x'.repeat(200 * 1024)}\nthe end\n`;
  const r = await H.runScript(['bash', ['s']], { spawn: fakeSpawn({ out: big, code: 0 }) });
  assert.equal(r.exit_code, 0);
  assert.ok(Buffer.byteLength(r.output) <= H.OUTPUT_CAP + 100, `output is ${Buffer.byteLength(r.output)} bytes`);
  assert.match(r.output, /the end\n$/);
  assert.match(r.output, /^\[output truncated/);
  assert.doesNotMatch(r.output, /\x1b/);
  const small = await H.runScript(['bash', ['s']], { spawn: fakeSpawn({ out: '\x1b[1;33m!!\x1b[0m  warn\n', code: 3 }) });
  assert.equal(small.output, '!!  warn\n');
  assert.equal(small.exit_code, 3);
});

// ---- routes ----

function fakeSpawn({ out = '', code = 0, hold = null, onSpawn } = {}) {
  return (cmd, args, opts) => {
    onSpawn?.(cmd, args, opts);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};
    const finish = () => { child.stdout.emit('data', Buffer.from(out)); child.emit('close', code); };
    if (hold) hold.then(finish); else setImmediate(finish);
    return child;
  };
}

let deps = host({}, { uid: 0 }).deps;
const app = express();
app.use(express.json());
// A router per request, so each test can swap the fake host; the one-run lock
// is process-wide in the service, so it is shared across them.
app.use('/api/settings', (req, res, next) => createHostHardeningRouter(deps)(req, res, next));
app.use('/api/settings', settingsRoutes);
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare("INSERT INTO users (name, email, username, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${tag}`, `u${tag}@t.test`, `u${tag}`, role, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return { user, token };
}
function enroll(user) {
  const { secret } = mfa.startEnrollment(db, user);
  const r = mfa.activateEnrollment(db, user, totp.totp(totp.base32Decode(secret), Date.now() - 30_000));
  assert.ok(r.ok);
  return (offsetMs = 0) => totp.totp(totp.base32Decode(secret), Date.now() + offsetMs);
}
async function call(method, path, body, token) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}
const audits = (action) => db.prepare('SELECT detail FROM audit_log WHERE action = ? ORDER BY id').all(action).map((r) => JSON.parse(r.detail));

const ADMIN = mkUser('platform_admin');
const MFA_ADMIN = mkUser('platform_admin');
const codeFor = enroll(MFA_ADMIN.user);
const PLAIN = mkUser('user');

beforeEach(() => {
  mfa._resetMfaRateLimitsForTests();
  deps = host({}, { uid: 0, spawn: fakeSpawn({ out: '==> Host hardening done\n' }) }).deps;
});

test('GET: platform admin only, contract shape, mfa_required follows enrollment', async () => {
  assert.equal((await call('GET', '/api/settings/host-hardening', null, PLAIN.token)).status, 403);
  assert.equal((await call('GET', '/api/settings/host-hardening')).status, 401);
  const r = await call('GET', '/api/settings/host-hardening', null, ADMIN.token);
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.body).sort(), ['items', 'last_run', 'mfa_required', 'run', 'running', 'supported']);
  assert.equal(r.body.supported, true);
  assert.equal(r.body.items.length, 8);
  assert.deepEqual(r.body.run, { mode: 'root', command: `bash ${REPO}/scripts/host-hardening.sh` });
  assert.equal(r.body.mfa_required, false);
  assert.equal(r.body.running, false);
  assert.equal((await call('GET', '/api/settings/host-hardening', null, MFA_ADMIN.token)).body.mfa_required, true);
});

test('GET: not Linux is supported:false with a reason', async () => {
  deps = host({}, { platform: 'darwin' }).deps;
  const r = await call('GET', '/api/settings/host-hardening', null, ADMIN.token);
  assert.equal(r.body.supported, false);
  assert.match(r.body.reason, /Linux servers/);
  assert.equal(r.body.run.mode, 'unsupported');
});

test('apply without MFA enrolled: runs, records last_run, audits mfa not-enrolled', async () => {
  let spawned;
  deps = host({}, { uid: 0, spawn: fakeSpawn({ out: '\x1b[1;36m==>\x1b[0m Host hardening done\n', onSpawn: (c, a, o) => { spawned = { c, a, o }; } }) }).deps;
  const r = await call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.ok, true);
  assert.equal(r.body.exit_code, 0);
  assert.equal(r.body.output, '==> Host hardening done\n');
  assert.equal(r.body.status.last_run.ok, true);
  assert.equal(r.body.status.last_run.by, ADMIN.user.name);
  assert.deepEqual([spawned.c, spawned.a], ['bash', [`${REPO}/scripts/host-hardening.sh`]]);
  assert.deepEqual(spawned.o.stdio, ['ignore', 'pipe', 'pipe']);
  assert.equal(spawned.o.shell, undefined);
  assert.equal(audits('host-hardening-applied').at(-1).mfa, 'not-enrolled');
});

test('apply through sudo runs the installed copy with no arguments; a failure is recorded and audited as failed', async () => {
  let spawned;
  deps = host({ files: SUDO_FILES }, { uid: 1000, spawn: fakeSpawn({ out: 'xx  boom\n', code: 1, onSpawn: (c, a) => { spawned = [c, a]; } }) }).deps;
  const r = await call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, false);
  assert.equal(r.body.exit_code, 1);
  assert.deepEqual(spawned, ['sudo', ['-n', H.INSTALLED_SCRIPT]]);
  assert.equal(H.readLastRun(db).ok, false);
  assert.equal(audits('host-hardening-failed').at(-1).exit_code, 1);
});

test('apply with MFA enrolled: missing code 403 MFA_REQUIRED, bad code 403 MFA_INVALID, good code runs', async () => {
  let runs = 0;
  deps = host({}, { uid: 0, spawn: fakeSpawn({ onSpawn: () => { runs++; } }) }).deps;
  const none = await call('POST', '/api/settings/host-hardening/apply', {}, MFA_ADMIN.token);
  assert.equal(none.status, 403);
  assert.equal(none.body.error.code, 'MFA_REQUIRED');
  const bad = await call('POST', '/api/settings/host-hardening/apply', { mfa_code: '000000' === codeFor() ? '111111' : '000000' }, MFA_ADMIN.token);
  assert.equal(bad.status, 403);
  assert.equal(bad.body.error.code, 'MFA_INVALID');
  assert.equal(runs, 0, 'nothing runs without a valid code');
  const good = await call('POST', '/api/settings/host-hardening/apply', { mfa_code: codeFor() }, MFA_ADMIN.token);
  assert.equal(good.status, 200, JSON.stringify(good.body));
  assert.equal(runs, 1);
  assert.equal(audits('host-hardening-applied').at(-1).mfa, 'totp');
  const replay = await call('POST', '/api/settings/host-hardening/apply', { mfa_code: codeFor() }, MFA_ADMIN.token);
  assert.equal(replay.body.error.code, 'MFA_INVALID', 'a used code cannot be replayed');
});

test('apply with MFA enrolled: repeated bad codes are rate limited (429)', async () => {
  let last;
  for (let i = 0; i < 12; i++) {
    last = await call('POST', '/api/settings/host-hardening/apply', { mfa_code: '12345' + (i % 10) === codeFor() ? '999999' : '12345' + (i % 10) }, MFA_ADMIN.token);
    if (last.status === 429) break;
  }
  assert.equal(last.status, 429);
  assert.equal(last.body.error.code, 'RATE_LIMITED');
});

test('apply: manual and unsupported answer 400 MANUAL_ONLY with the command, and release the lock', async () => {
  deps = host({}, { uid: 1000 }).deps;
  const r = await call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, 'MANUAL_ONLY');
  assert.equal(r.body.command, `sudo bash ${REPO}/scripts/host-hardening.sh`);
  assert.equal(H.isRunning(), false);
  deps = host({}, { platform: 'darwin' }).deps;
  const u = await call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  assert.equal(u.status, 400);
  assert.equal(u.body.error.code, 'MANUAL_ONLY');
});

test('apply: one run at a time (409 RUNNING while one is in progress; GET shows running)', async () => {
  let release;
  const hold = new Promise((r) => { release = r; });
  deps = host({}, { uid: 0, spawn: fakeSpawn({ hold }) }).deps;
  const first = call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  for (let i = 0; i < 50 && !H.isRunning(); i++) await new Promise((r) => setTimeout(r, 10));
  const second = await call('POST', '/api/settings/host-hardening/apply', {}, ADMIN.token);
  assert.equal(second.status, 409);
  assert.equal(second.body.error.code, 'RUNNING');
  assert.equal((await call('GET', '/api/settings/host-hardening', null, ADMIN.token)).body.running, true);
  release();
  assert.equal((await first).status, 200);
  assert.equal(H.isRunning(), false);
});

test('the generic settings PUT cannot write the last run', async () => {
  const before = db.prepare('SELECT value FROM settings WHERE key = ?').get(H.LAST_RUN_KEY)?.value;
  const forged = JSON.stringify({ at: '2020-01-01T00:00:00Z', ok: true, exit_code: 0, by: 'forged' });
  for (const key of [H.LAST_RUN_KEY, 'host%5Fhardening_last_run']) {
    const r = await call('PUT', `/api/settings/${key}`, { value: forged }, ADMIN.token);
    assert.equal(r.status, 403, key);
  }
  assert.equal(db.prepare('SELECT value FROM settings WHERE key = ?').get(H.LAST_RUN_KEY)?.value, before);
  const other = await call('PUT', '/api/settings/some_unrelated_key', { value: 'x' }, ADMIN.token);
  assert.equal(other.status, 200, 'other keys still reach the generic handler');
});

test('the host security mail points at Host limits when unattended upgrades are off', async () => {
  const N = await import('../server/services/hostVulnsNotify.js');
  const r = {
    supported: true, os: { prettyName: 'Ubuntu 24.04 LTS' }, source: 'apt', unavailable: 0,
    packages: [{ name: 'libc6', installed: '1', candidate: '2', service: 'standard-security' }],
    reboot: { required: false, packages: [] },
    unattended: { installed: false, enabled: false }, cache: { ageHours: 1, stale: false },
  };
  assert.match(N.renderHostVulnMail(r, 'new', []).text, /Unattended security upgrades: OFF .*Settings > Job Health > Host limits/);
});

test('index.js mounts the Host limits router ahead of the generic settings router (its PUT guard depends on it)', () => {
  const index = readFileSync(join(ROOT, 'server', 'index.js'), 'utf8');
  const mine = index.search(/^app\.use\('\/api\/settings', \(await import\('\.\/routes\/hostHardening\.js'\)\)\.default\);/m);
  const generic = index.search(/^app\.use\('\/api\/settings', settingsRoutes\);/m);
  assert.ok(mine > 0 && generic > 0 && mine < generic);
});
