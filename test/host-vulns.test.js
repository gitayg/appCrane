import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The daily host security check: pending Ubuntu/Debian security updates (pro
// first, apt's -security pocket as the fallback), reboot required, and whether
// unattended-upgrades is on, mailed to platform admins only when something is
// pending and changed since the last mail, with one reminder per 7 days.
//
// Every command output below was captured from a real container (ubuntu:20.04,
// 22.04, 24.04 and debian:12, October 2026), with the archive hostname in pro's
// `origin` field replaced by a placeholder.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-vulns-'));
process.env.ENCRYPTION_KEY = 'v'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { detectHostVulns, isActionable } = await import('../server/services/hostVulns.js');
const P = await import('../server/services/hostVulnsParse.js');
const N = await import('../server/services/hostVulnsNotify.js');

// ---- captured outputs ----

// ubuntu:22.04, `pro security-status --format json` (ubuntu-pro-client 38ubuntu0~22.04)
const PRO_2204 = '{"_schema_version": "0.1", "livepatch": {"fixed_cves": []}, "packages": [{"download_size": 99802, "origin": "security.archive.example", "package": "liblzma5", "service_name": "standard-security", "status": "upgrade_available", "version": "5.2.5-2ubuntu1.2"}, {"download_size": 316468, "origin": "security.archive.example", "package": "libsystemd0", "service_name": "standard-security", "status": "upgrade_available", "version": "249.11-0ubuntu3.23"}, {"download_size": 75692, "origin": "security.archive.example", "package": "libudev1", "service_name": "standard-security", "status": "upgrade_available", "version": "249.11-0ubuntu3.23"}], "summary": {"num_esm_apps_packages": 0, "num_esm_apps_updates": 0, "num_esm_infra_packages": 0, "num_esm_infra_updates": 0, "num_installed_packages": 126, "num_main_packages": 126, "num_multiverse_packages": 0, "num_restricted_packages": 0, "num_standard_security_updates": 3, "num_third_party_packages": 0, "num_universe_packages": 0, "num_unknown_packages": 0, "reboot_required": "no", "ua": {"attached": false, "enabled_services": [], "entitled_services": []}}}';
// ubuntu:24.04, same command, nothing pending
const PRO_2404_CLEAN = '{"_schema_version": "0.1", "livepatch": {"fixed_cves": []}, "packages": [], "summary": {"num_esm_apps_packages": 0, "num_esm_apps_updates": 0, "num_esm_infra_packages": 0, "num_esm_infra_updates": 0, "num_installed_packages": 169, "num_main_packages": 169, "num_multiverse_packages": 0, "num_restricted_packages": 0, "num_standard_security_updates": 0, "num_third_party_packages": 0, "num_universe_packages": 0, "num_unknown_packages": 0, "reboot_required": "no", "ua": {"attached": false, "enabled_services": [], "entitled_services": []}}}';
// ubuntu:22.04, `dpkg-query -W -f='${Package} ${Version}\n' liblzma5 libsystemd0 libudev1`
const DPKG_2204 = 'liblzma5 5.2.5-2ubuntu1.1\nlibsystemd0 249.11-0ubuntu3.22\nlibudev1 249.11-0ubuntu3.22\n';
// ubuntu:20.04 as a user whose HOME does not exist (nobody): pro exits non-zero
const PRO_NO_HOME_STDERR = `Unhandled exception, please file a bug
Traceback (most recent call last):
  File "/usr/lib/python3.8/pathlib.py", line 1288, in mkdir
    self._accessor.mkdir(self, mode)
PermissionError: [Errno 13] Permission denied: '/nonexistent'
An unexpected error occurred: [Errno 13] Permission denied: '/nonexistent'
For more details, see the log: /nonexistent/.cache/ubuntu-pro/ubuntu-pro.log
If you think this is a bug, please run: ubuntu-bug ubuntu-advantage-tools
`;
// ubuntu:20.04, `apt-get -s upgrade` (apt and libapt-pkg6.0 come from -updates only)
const APT_SIM_2004 = `Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  apt gpgv libapt-pkg6.0 libc-bin libc6
5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libc6 [2.31-0ubuntu9.17] (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Conf libc6 (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Inst libc-bin [2.31-0ubuntu9.17] (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Conf libc-bin (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Inst libapt-pkg6.0 [2.0.10] (2.0.11 Ubuntu:20.04/focal-updates [amd64])
Conf libapt-pkg6.0 (2.0.11 Ubuntu:20.04/focal-updates [amd64])
Inst gpgv [2.2.19-3ubuntu2.4] (2.2.19-3ubuntu2.5 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Conf gpgv (2.2.19-3ubuntu2.5 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Inst apt [2.0.10] (2.0.11 Ubuntu:20.04/focal-updates [amd64])
Conf apt (2.0.11 Ubuntu:20.04/focal-updates [amd64])
`;
// debian:12, `apt-get -s dist-upgrade`
const APT_SIM_DEB12 = `Calculating upgrade...
The following packages will be upgraded:
  tzdata
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst tzdata [2026e-0+deb12u1] (2026f-0+deb12u1 Debian-Security:12/oldstable-security [all])
Conf tzdata (2026f-0+deb12u1 Debian-Security:12/oldstable-security [all])
`;
// ubuntu:22.04, `apt-get -s install curl`: newly installed packages carry no [installed]
const APT_SIM_NEW = `Inst openssl (3.0.2-0ubuntu1.30 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libpsl5 (0.21.0-1.2build2 Ubuntu:22.04/jammy [amd64])
`;
// ubuntu:20.04 after installing unattended-upgrades, `apt-config dump APT::Periodic`
const PERIODIC_ON = `APT::Periodic "";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "1";
`;
// ubuntu:24.04 image after the same install: Docker's image adds Enable "0"
const PERIODIC_DOCKER_OFF = PERIODIC_ON + 'APT::Periodic::Enable "0";\n';
// ubuntu:22.04 without unattended-upgrades
const PERIODIC_NONE = 'APT::Periodic "";\nAPT::Periodic::Enable "0";\n';
// /var/run/reboot-required(.pkgs) on ubuntu:20.04 after upgrading libc6
const REBOOT_FLAG = '*** System restart required ***\n';
const REBOOT_PKGS = 'libc6\n';
const OS_2204 = 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n';
const OS_DEB12 = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nVERSION_CODENAME=bookworm\nID=debian\n';
const OS_FEDORA = 'NAME="Fedora Linux"\nVERSION_ID=40\nID=fedora\nPRETTY_NAME="Fedora Linux 40 (Server Edition)"\n';

// ---- a fake host ----

const NOW = Date.parse('2026-10-30T10:00:00Z');
const HOUR = 36e5;

function host({
  os = OS_2204, pro = { code: 0, stdout: PRO_2204 }, sim = { code: 0, stdout: APT_SIM_2004 },
  dpkg = DPKG_2204, periodic = PERIODIC_ON, uuInstalled = true, reboot = false, stampAgeH = 5, listsAgeH = null,
} = {}) {
  const calls = [];
  const files = { '/etc/os-release': os };
  if (reboot) { files['/var/run/reboot-required'] = REBOOT_FLAG; files['/var/run/reboot-required.pkgs'] = REBOOT_PKGS; }
  const mtimes = {};
  if (stampAgeH != null) mtimes['/var/lib/apt/periodic/update-success-stamp'] = NOW - stampAgeH * HOUR;
  if (listsAgeH != null) mtimes['/var/lib/apt/lists'] = NOW - listsAgeH * HOUR;
  const ok = (stdout) => ({ code: 0, stdout, stderr: '' });
  return {
    calls,
    deps: {
      platform: 'linux',
      now: () => NOW,
      readFile: (p) => { if (p in files) return files[p]; throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' }); },
      mtimeMs: (p) => { if (p in mtimes) return mtimes[p]; throw new Error(`ENOENT ${p}`); },
      exec: async (cmd, args) => {
        calls.push([cmd, ...args].join(' '));
        if (cmd === 'pro') return { stderr: '', ...pro };
        if (cmd === 'apt-get') return { stderr: '', ...sim };
        if (cmd === 'apt-config') return ok(periodic);
        if (cmd === 'dpkg-query' && args.includes('unattended-upgrades')) {
          return uuInstalled ? ok('install ok installed') : { code: 1, stdout: '', stderr: 'dpkg-query: no packages found matching unattended-upgrades\n' };
        }
        if (cmd === 'dpkg-query') return ok(dpkg);
        throw new Error(`unexpected command ${cmd}`);
      },
    },
  };
}

// ---- detection ----

test('pro: security packages with candidate from pro and installed version from dpkg', async () => {
  const h = host();
  const r = await detectHostVulns(h.deps);
  assert.equal(r.supported, true);
  assert.equal(r.source, 'pro');
  assert.deepEqual(r.packages, [
    { name: 'liblzma5', installed: '5.2.5-2ubuntu1.1', candidate: '5.2.5-2ubuntu1.2', service: 'standard-security' },
    { name: 'libsystemd0', installed: '249.11-0ubuntu3.22', candidate: '249.11-0ubuntu3.23', service: 'standard-security' },
    { name: 'libudev1', installed: '249.11-0ubuntu3.22', candidate: '249.11-0ubuntu3.23', service: 'standard-security' },
  ]);
  assert.ok(!h.calls.some((c) => c.startsWith('apt-get')), 'apt fallback not run when pro answered');
  assert.equal(r.os.prettyName, 'Ubuntu 22.04.5 LTS');
});

test('pro: an update that needs a Pro subscription is counted, not listed as installable', () => {
  const j = JSON.parse(PRO_2204);
  j.packages[0].status = 'pending_attach';
  const r = P.parseProSecurityStatus(JSON.stringify(j));
  assert.deepEqual(r.packages.map((p) => p.name), ['libsystemd0', 'libudev1']);
  assert.equal(r.unavailable, 1);
});

test('apt fallback: only Inst lines from a -security pocket, with installed and candidate versions', () => {
  assert.deepEqual(P.parseAptSimulate(APT_SIM_2004).packages, [
    { name: 'libc6', installed: '2.31-0ubuntu9.17', candidate: '2.31-0ubuntu9.18', service: null },
    { name: 'libc-bin', installed: '2.31-0ubuntu9.17', candidate: '2.31-0ubuntu9.18', service: null },
    { name: 'gpgv', installed: '2.2.19-3ubuntu2.4', candidate: '2.2.19-3ubuntu2.5', service: null },
  ]);
  assert.deepEqual(P.parseAptSimulate(APT_SIM_DEB12).packages, [
    { name: 'tzdata', installed: '2026e-0+deb12u1', candidate: '2026f-0+deb12u1', service: null },
  ]);
  assert.deepEqual(P.parseAptSimulate(APT_SIM_NEW).packages, [
    { name: 'openssl', installed: null, candidate: '3.0.2-0ubuntu1.30', service: null },
  ]);
});

test('non-root without a home: pro fails, apt answers, and the reason is kept', async () => {
  const h = host({ pro: { code: 1, stdout: '', stderr: PRO_NO_HOME_STDERR } });
  const r = await detectHostVulns(h.deps);
  assert.equal(r.source, 'apt');
  assert.deepEqual(r.packages.map((p) => p.name), ['gpgv', 'libc-bin', 'libc6']);
  assert.match(r.notes[0], /Permission denied/);
  assert.ok(h.calls.includes('apt-get -s -q dist-upgrade'));
  assert.equal(r.error, undefined);
});

test('Debian without pro: apt is used silently', async () => {
  const h = host({ os: OS_DEB12, pro: { code: -1, stdout: '', missing: true }, sim: { code: 0, stdout: APT_SIM_DEB12 } });
  const r = await detectHostVulns(h.deps);
  assert.equal(r.source, 'apt');
  assert.deepEqual(r.notes, []);
  assert.equal(r.packages[0].name, 'tzdata');
});

test('both sources failing is an error, not "nothing pending"', async () => {
  const h = host({ pro: { code: -1, stdout: '', missing: true }, sim: { code: 100, stdout: '', stderr: 'E: Could not open lock file\n' } });
  const r = await detectHostVulns(h.deps);
  assert.match(r.error, /apt-get -s dist-upgrade failed: E: Could not open lock file/);
});

test('unsupported platforms return supported:false and run nothing', async () => {
  const mac = host();
  mac.deps.platform = 'darwin';
  assert.deepEqual(await detectHostVulns(mac.deps), { supported: false, reason: 'not Linux (darwin)' });
  assert.equal(mac.calls.length, 0);
  const fedora = host({ os: OS_FEDORA });
  const r = await detectHostVulns(fedora.deps);
  assert.equal(r.supported, false);
  assert.match(r.reason, /not Ubuntu or Debian \(Fedora Linux 40/);
  assert.equal(fedora.calls.length, 0);
});

test('reboot required is read from /var/run/reboot-required(.pkgs)', async () => {
  assert.deepEqual((await detectHostVulns(host({ reboot: true }).deps)).reboot, { required: true, packages: ['libc6'] });
  assert.deepEqual((await detectHostVulns(host().deps)).reboot, { required: false, packages: [] });
});

test('unattended-upgrades: installed and both periodic values on; off when Enable "0" or not installed', async () => {
  assert.equal((await detectHostVulns(host().deps)).unattended.enabled, true);
  const docker = (await detectHostVulns(host({ periodic: PERIODIC_DOCKER_OFF }).deps)).unattended;
  assert.equal(docker.enabled, false);
  assert.equal(docker.periodicEnable, '0');
  const none = (await detectHostVulns(host({ periodic: PERIODIC_NONE, uuInstalled: false }).deps)).unattended;
  assert.deepEqual([none.installed, none.enabled, none.unattendedUpgrade], [false, false, null]);
});

test('cache age: the update stamp first, the lists directory second, stale after 48 h', async () => {
  const fresh = (await detectHostVulns(host({ stampAgeH: 5 }).deps)).cache;
  assert.deepEqual([fresh.source, fresh.ageHours, fresh.stale], ['update-success-stamp', 5, false]);
  const lists = (await detectHostVulns(host({ stampAgeH: null, listsAgeH: 72 }).deps)).cache;
  assert.deepEqual([lists.source, lists.ageHours, lists.stale], ['lists', 72, true]);
});

// ---- change detection ----

const result = (over = {}) => ({
  supported: true, at: new Date(NOW).toISOString(), os: { prettyName: 'Ubuntu 22.04.5 LTS' }, source: 'pro',
  packages: P.parseProSecurityStatus(PRO_2204).packages.map((p) => ({ ...p, installed: '0' })),
  unavailable: 0, reboot: { required: false, packages: [] },
  unattended: { installed: true, enabled: true }, cache: { ageHours: 5, stale: false }, notes: [], ...over,
});
const DAY = 24 * HOUR;

test('decideMail: new, then quiet, then a weekly reminder; new packages or a new reboot mail at once', () => {
  const first = N.decideMail(result(), null, NOW);
  assert.equal(first.kind, 'new');
  assert.equal(first.fresh.length, 3);
  assert.equal(N.decideMail(result(), first.state, NOW + DAY).kind, null);
  assert.equal(N.decideMail(result(), first.state, NOW + 7 * DAY - 1).kind, null);
  assert.equal(N.decideMail(result(), first.state, NOW + 7 * DAY).kind, 'reminder');

  const more = result();
  more.packages.push({ name: 'openssl', installed: '1', candidate: '2', service: null });
  const added = N.decideMail(more, first.state, NOW + DAY);
  assert.deepEqual([added.kind, added.fresh], ['new', ['openssl@2']]);

  const reboot = N.decideMail(result({ reboot: { required: true, packages: ['libc6'] } }), first.state, NOW + DAY);
  assert.equal(reboot.kind, 'new');
});

test('decideMail: nothing pending forgets the state, so a later return is new again', () => {
  const first = N.decideMail(result(), null, NOW);
  const clean = N.decideMail(result({ packages: [] }), first.state, NOW + DAY);
  assert.deepEqual([clean.kind, clean.state], [null, null]);
  assert.equal(N.decideMail(result(), clean.state, NOW + 2 * DAY).kind, 'new');
  assert.equal(isActionable(result({ packages: [], unattended: { installed: false, enabled: false } })), false,
    'unattended-upgrades off alone is reported, not mailed');
});

// ---- runs against the database ----

let nUser = 0;
function user(role) {
  nUser++;
  const key = generateApiKey('dhk_user');
  db.prepare('INSERT INTO users (name, email, role, api_key_hash, active, kind) VALUES (?,?,?,?,1,?)')
    .run(`U${nUser}`, `u${nUser}@example.test`, role, hashApiKey(key), 'human');
  return { email: `u${nUser}@example.test`, key };
}
const ADMIN_A = user('platform_admin');
const ADMIN_B = user('platform_admin');
const PLAIN = user('user');
const mails = () => db.prepare("SELECT to_email, subject, body_text, idempotency_key FROM email_queue WHERE source = 'host-vulns' ORDER BY id").all();

beforeEach(() => {
  db.prepare("DELETE FROM email_queue WHERE source = 'host-vulns'").run();
  db.prepare("DELETE FROM settings WHERE key LIKE 'host_vulns_%'").run();
});

test('first run mails every platform admin and no one else; an unchanged second run mails nobody', async () => {
  const one = await N.runHostVulnCheck({ db, deps: host().deps, now: NOW });
  assert.equal(one.kind, 'new');
  assert.deepEqual(mails().map((m) => m.to_email).sort(), [ADMIN_A.email, ADMIN_B.email]);
  assert.ok(!mails().some((m) => m.to_email === PLAIN.email));
  assert.equal(mails()[0].subject, '[AppCrane] Server 3 security updates pending');
  const two = await N.runHostVulnCheck({ db, deps: host().deps, now: NOW + DAY });
  assert.equal(two.kind, null);
  assert.equal(mails().length, 2);
});

test('a restart that lost the saved state does not send the same mail twice', async () => {
  await N.runHostVulnCheck({ db, deps: host().deps, now: NOW });
  db.prepare("DELETE FROM settings WHERE key = 'host_vulns_mailed'").run();
  const again = await N.runHostVulnCheck({ db, deps: host().deps, now: NOW + HOUR });
  assert.equal(again.kind, 'new');
  assert.deepEqual(again.mailed, []);
  assert.equal(mails().length, 2);
});

test('a reboot newly required mails again; a week later an unchanged state gets one reminder', async () => {
  await N.runHostVulnCheck({ db, deps: host().deps, now: NOW });
  await N.runHostVulnCheck({ db, deps: host({ reboot: true }).deps, now: NOW + DAY });
  assert.equal(mails().length, 4);
  assert.match(mails()[2].subject, /3 security updates pending, reboot required/);
  const rem = await N.runHostVulnCheck({ db, deps: host({ reboot: true }).deps, now: NOW + 8 * DAY });
  assert.equal(rem.kind, 'reminder');
  assert.equal(mails().length, 6);
  assert.match(mails()[4].subject, /^\[AppCrane\] Reminder: /);
});

test('a failed or unsupported detection mails nobody and keeps the last mail state', async () => {
  await N.runHostVulnCheck({ db, deps: host().deps, now: NOW });
  const before = db.prepare("SELECT value FROM settings WHERE key = 'host_vulns_mailed'").get().value;
  const broken = host({ pro: { code: -1, stdout: '', missing: true }, sim: { code: 100, stdout: '', stderr: 'E: lock\n' } });
  const r = await N.runHostVulnCheck({ db, deps: broken.deps, now: NOW + 8 * DAY });
  assert.ok(r.result.error);
  const mac = host();
  mac.deps.platform = 'darwin';
  await N.runHostVulnCheck({ db, deps: mac.deps, now: NOW + 9 * DAY });
  assert.equal(mails().length, 2);
  assert.equal(db.prepare("SELECT value FROM settings WHERE key = 'host_vulns_mailed'").get().value, before);
});

test('a clean host mails nobody', async () => {
  const r = await N.runHostVulnCheck({ db, deps: host({ pro: { code: 0, stdout: PRO_2404_CLEAN } }).deps, now: NOW });
  assert.equal(r.kind, null);
  assert.equal(mails().length, 0);
});

test('the mail lists each package installed -> available, marks new ones, and states reboot and unattended status', async () => {
  await N.runHostVulnCheck({ db, deps: host({ reboot: true, periodic: PERIODIC_DOCKER_OFF }).deps, now: NOW });
  const t = mails()[0].body_text;
  assert.match(t, /^  - liblzma5 5\.2\.5-2ubuntu1\.1 -> 5\.2\.5-2ubuntu1\.2 \(new\)$/m);
  assert.match(t, /^Reboot required \(by libc6\)$/m);
  assert.match(t, /^Unattended security upgrades: OFF \(installed but not enabled in APT::Periodic\)/m);
  assert.match(t, /^Source: pro security-status$/m);
});

// ---- the read-only platform-admin route ----

const monitoring = (await import('../server/routes/monitoring.js')).default;
const app = express();
app.use(express.json());
app.use('/api', monitoring);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

test('GET /api/server/host-vulns returns the stored result to a platform admin only', async () => {
  await N.runHostVulnCheck({ db, deps: host().deps, now: NOW });
  const get = (key) => fetch(`http://127.0.0.1:${server.address().port}/api/server/host-vulns`, { headers: { 'X-API-Key': key } });
  const ok = await get(ADMIN_A.key);
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.result.packages.length, 3);
  assert.equal((await get(PLAIN.key)).status, 403);
});
