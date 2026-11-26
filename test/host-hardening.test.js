import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// A production box filled its disk: a journal whose size limit was written but
// never applied, and syslog that rotated only weekly. scripts/host-hardening.sh
// caps both (and Docker's default logs), applies the caps immediately, and
// install.sh runs it before restarting Docker.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'host-hardening.sh');
const src = readFileSync(SCRIPT, 'utf8');
const install = readFileSync(join(ROOT, 'install.sh'), 'utf8');

test('the script and install.sh parse', () => {
  execFileSync('bash', ['-n', SCRIPT]);
  execFileSync('bash', ['-n', join(ROOT, 'install.sh')]);
});

test('install.sh runs the script before it restarts Docker, without aborting on failure', () => {
  const call = install.search(/^bash "\$REPO_DIR\/scripts\/host-hardening\.sh"/m);
  assert.ok(call > 0, 'install.sh must invoke scripts/host-hardening.sh');
  const ensure = install.indexOf('log "Ensuring Docker daemon is running"');
  const restart = install.indexOf('systemctl restart docker.service');
  assert.ok(ensure > 0 && restart > 0);
  assert.ok(call < ensure && call < restart, 'must run before Docker is (re)started');
  assert.match(install.slice(call, call + 300), /\|\| warn /, 'a hardening failure must only warn');
});

test('the script never restarts or stops Docker', () => {
  assert.doesNotMatch(src, /systemctl\s+(?:re)?start\s+docker|systemctl\s+stop\s+docker|service\s+docker\s/);
});

test('journald limit is written and applied now (restart + vacuum)', () => {
  assert.match(src, /SystemMaxUse=500M\nSystemKeepFree=2G\nMaxRetentionSec=1month/);
  assert.match(src, /systemctl restart systemd-journald/);
  assert.match(src, /journalctl --vacuum-size=500M/);
});

// ---- real runs in an Ubuntu container (no systemd, as in any container) ----

const { images, RELEASES, skipFor, buildTimeLeft, note, section, run } = await import('./host-hardening-harness.js');

for (const rel of RELEASES) {
  test(`ubuntu ${rel}: fresh run writes every limit, logrotate still parses, and a second run changes nothing`, { skip: skipFor(rel) }, () => {
    const r = run(rel, '', { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '0' } });
    const [a, b] = r.runs;
    assert.equal(a.exit, 0, a.log);
    assert.match(a.journald, /^\[Journal\]\nSystemMaxUse=500M\nSystemKeepFree=2G\nMaxRetentionSec=1month$/m);
    assert.match(a.timer, /^OnCalendar=\nOnCalendar=hourly$/m);
    const stanzas = (a.rsyslog.match(/^\s*\{\s*$/gm) || []).length;
    assert.ok(stanzas >= 1);
    assert.equal((a.rsyslog.match(/^\tmaxsize 200M$/gm) || []).length, stanzas, 'every stanza gets maxsize');
    assert.deepEqual(JSON.parse(a.daemon), { 'log-opts': { 'max-size': '10m', 'max-file': '3' } });
    assert.match(a.log, /next Docker restart/);
    assert.equal(a.reserve, String(1024 ** 3), a.log);
    assert.match(a.log, /sudo rm \/appcrane-disk-reserve/);

    assert.equal(r.logrotateExit, 0, r.logrotate);
    assert.doesNotMatch(r.logrotate, /error|duplicate/i, r.logrotate);
    assert.match(r.logrotate, /log needs rotating|log does not need rotating|considering log \/var\/log\/syslog/);

    assert.equal(b.exit, 0, b.log);
    assert.equal(b.sum, a.sum, 'second run must not change any file');
    assert.match(b.log, /already has maxsize/);
    assert.match(b.log, /already present/);
  });
}

const R = '24.04';

test('docker: operator log-opts are left byte-for-byte alone', { skip: skipFor(R) }, () => {
  const orig = '{\n  "log-opts": {"max-size": "50m"},\n  "storage-driver": "overlay2"\n}';
  const r = run(R, `mkdir -p /etc/docker; printf '%s\\n' '${orig}' > /etc/docker/daemon.json`);
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.equal(r.runs[0].daemon, orig + '\n');
});

test('docker: an operator log-driver is left alone', { skip: skipFor(R) }, () => {
  const orig = '{"log-driver": "journald"}';
  const r = run(R, `mkdir -p /etc/docker; printf '%s\\n' '${orig}' > /etc/docker/daemon.json`);
  assert.equal(r.runs[0].daemon, orig + '\n');
});

test('docker: other settings are kept and log-opts merged in', { skip: skipFor(R) }, () => {
  const r = run(R, `mkdir -p /etc/docker; echo '{"storage-driver":"overlay2","dns":["192.0.2.53"]}' > /etc/docker/daemon.json`);
  assert.deepEqual(JSON.parse(r.runs[0].daemon), {
    'storage-driver': 'overlay2', dns: ['192.0.2.53'],
    'log-opts': { 'max-size': '10m', 'max-file': '3' },
  });
});

test('docker: invalid JSON is left untouched with a warning', { skip: skipFor(R) }, () => {
  const r = run(R, `mkdir -p /etc/docker; echo '{"storage-driver": ' > /etc/docker/daemon.json`);
  assert.equal(r.runs[0].exit, 0);
  assert.equal(r.runs[0].daemon, '{"storage-driver": \n');
  assert.match(r.runs[0].log, /not valid JSON/);
});

test('reserve: skipped with a warning when it would leave too little free space', { skip: skipFor(R) }, () => {
  const r = run(R, '', { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].exit, 0);
  assert.equal(r.runs[0].reserve, 'none');
  assert.match(r.runs[0].log, /reserve: only .* skipped/);
});

// The root-owned copy runs as root but reads DATA_DIR from .env, which the run
// user can edit, so the reserve must never be written where that user can plant
// a link.
test('reserve: a mount point others can write to is skipped', { skip: skipFor(R) }, () => {
  const r = run(R, `printf "DATA_DIR=/mnt/data\\n" > /opt/appcrane/.env; echo "@@MOUNT"; stat -c '%u %a' /mnt/data`,
    { env: { APPCRANE_RESERVE_MIN_FREE_GB: '0' }, dockerArgs: ['--tmpfs', '/mnt/data:mode=1777'] });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.match(r.runs[0].log, /reserve: \/mnt\/data is not root-owned or is writable by others/);
  assert.doesNotMatch(r.runs[0].log, /reserve: created/);
});

test('reserve: a planted symlink is left alone and its target untouched', { skip: skipFor(R) }, () => {
  const r = run(R, `echo keep > /etc/victim; chmod 644 /etc/victim; ln -s /etc/victim /appcrane-disk-reserve`,
    { env: { APPCRANE_RESERVE_MIN_FREE_GB: '0' } });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.match(r.runs[0].log, /reserve: \/appcrane-disk-reserve is a symlink or not a regular file/);
  assert.doesNotMatch(r.runs[0].log, /reserve: created/);
});

test('logrotate: an rsyslog file that already has maxsize is not edited again', { skip: skipFor(R) }, () => {
  const r = run(R, `sed -i 's/^\\tweekly$/\\tweekly\\n\\tmaxsize 1G/' /etc/logrotate.d/rsyslog`);
  assert.match(r.runs[0].rsyslog, /maxsize 1G/);
  assert.doesNotMatch(r.runs[0].rsyslog, /maxsize 200M/);
});

// ---- unattended security upgrades ----
// The test image has the package (as a real Ubuntu server does); the purge
// below takes it away again to exercise the install path.

const AUTO_FILE = '/etc/apt/apt.conf.d/20auto-upgrades';
const aptValue = (cfg, key) => (cfg.match(new RegExp(`^${key.replace(/:/g, ':')} "(.*)";$`, 'm')) || [])[1];

for (const rel of RELEASES) {
  test(`ubuntu ${rel}: unattended-upgrades is installed and enabled for security updates, with no automatic reboot`, { skip: skipFor(rel) }, () => {
    const r = run(rel, `DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq unattended-upgrades >/dev/null 2>&1; rm -f ${AUTO_FILE}`,
      { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
    const [a, b] = r.runs;
    assert.equal(a.exit, 0, a.log);
    assert.match(a.log, /unattended-upgrades: installed\n/, a.log);
    assert.match(a.uu, /install ok installed/, a.log);
    assert.equal(aptValue(a.aptcfg, 'APT::Periodic::Unattended-Upgrade'), '1', a.aptcfg);
    assert.equal(aptValue(a.aptcfg, 'APT::Periodic::Update-Package-Lists'), '1', a.aptcfg);
    assert.notEqual(aptValue(a.aptcfg, 'Unattended-Upgrade::Automatic-Reboot'), 'true', a.aptcfg);
    assert.doesNotMatch(a.log, /security updates are not applied automatically/);
    assert.equal(b.exit, 0, b.log);
    assert.match(b.log, /unattended-upgrades: already installed/);
    assert.equal(b.auto, a.auto, 'second run must not change 20auto-upgrades');
  });
}

test('unattended-upgrades: a missing 20auto-upgrades is written with both periodic values', { skip: skipFor(R) }, () => {
  const r = run(R, `rm -f ${AUTO_FILE}`, { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.match(r.runs[0].auto, /^APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";$/m);
  assert.match(r.runs[0].log, /wrote \/etc\/apt\/apt\.conf\.d\/20auto-upgrades/);
});

test('unattended-upgrades: an operator 20auto-upgrades that turns it off is left byte-for-byte, with a warning', { skip: skipFor(R) }, () => {
  const orig = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";';
  const r = run(R, `printf '%s\\n' '${orig}' > ${AUTO_FILE}`, { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.equal(r.runs[0].auto, orig + '\n');
  assert.match(r.runs[0].log, /left as is/);
  assert.match(r.runs[0].log, /security updates are not applied automatically/);
});

// ---- Caddy access-log directory ----

// install-host-hardening.sh installs a root-owned copy with the repo path baked
// in (sudo's env_reset strips the environment) and a sudoers rule for exactly
// that file with no arguments. The repo copy is never sudoable: self-update
// rewrites it as the run user.

const INSTALL = join(ROOT, 'scripts', 'install-host-hardening.sh');
const DEST = '/usr/local/lib/appcrane/host-hardening.sh';
const PUBLISH_HELPER = join(ROOT, 'scripts', 'appcrane-publish-chain.sh');
const DB_HELPER = join(ROOT, 'scripts', 'appcrane-db-chain.sh');

test('install.sh installs the sudo copy after running the script, passing the run user, without aborting on failure', () => {
  execFileSync('bash', ['-n', INSTALL]);
  const harden = install.search(/^bash "\$REPO_DIR\/scripts\/host-hardening\.sh"/m);
  const call = install.search(/^bash "\$REPO_DIR\/scripts\/install-host-hardening\.sh" "\$RUN_USER"/m);
  assert.ok(call > harden && harden > 0, 'install.sh must call install-host-hardening.sh "$RUN_USER" after the script');
  assert.match(install.slice(call, call + 300), /\|\| warn /);
});

const SUDO_TAG = 'appcrane-test-host-hardening-sudo:24.04';
let sudoImage = null;
if (images['24.04'] && buildTimeLeft() >= 1000) {
  const t0 = Date.now();
  try {
    execFileSync('docker', ['build', '-q', '-t', SUDO_TAG, '-'], {
      input: `FROM ${images['24.04']}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null && rm -rf /var/lib/apt/lists/*\nRUN useradd -m app\n`,
      stdio: ['pipe', 'pipe', 'pipe'], timeout: Math.max(1000, buildTimeLeft()),
    });
    sudoImage = SUDO_TAG;
  } catch (_) { /* the tests below skip */ }
  note('sudo image', t0, !!sudoImage);
}
const skipSudo = sudoImage ? false : 'docker (or the package mirror) unavailable';

function installRun(runUser, after = '') {
  const body = [
    'mkdir -p /opt/appcrane/scripts /mnt/data',
    'cp /src/host-hardening.sh /src/install-host-hardening.sh /src/appcrane-publish-chain.sh /src/appcrane-db-chain.sh /opt/appcrane/scripts/',
    'chown -R app:app /opt/appcrane',
    'printf "DATA_DIR=/mnt/data\\n" > /opt/appcrane/.env',
    `echo "@@INSTALL"; bash /opt/appcrane/scripts/install-host-hardening.sh ${runUser} 2>&1; echo "@@EXIT $?"`,
    `echo "@@DIR"; stat -c '%U:%G %a' /usr/local/lib/appcrane`,
    `echo "@@FILE"; stat -c '%U:%G %a' ${DEST} 2>&1`,
    `echo "@@SHA"; sha256sum ${DEST} | cut -d' ' -f1`,
    `echo "@@REPOLINE"; grep '^REPO_DIR=' ${DEST}`,
    'echo "@@SUDOERS"; cat /etc/sudoers.d/appcrane-host-hardening 2>/dev/null || echo "@@MISSING"',
    'echo "@@SUDOERSMODE"; stat -c \'%U:%G %a\' /etc/sudoers.d/appcrane-host-hardening 2>&1',
    'echo "@@VISUDO"; visudo -c >/dev/null 2>&1; echo "rc=$?"',
    'echo "@@PUBHELPER"; stat -c \'%U:%G %a\' /usr/local/lib/appcrane/appcrane-publish-chain.sh 2>&1',
    'echo "@@PUBSUDOERS"; cat /etc/sudoers.d/appcrane-publish-chain 2>/dev/null || echo "@@MISSING"',
    'echo "@@DBHELPER"; stat -c \'%U:%G %a\' /usr/local/lib/appcrane/appcrane-db-chain.sh 2>&1; cmp /src/appcrane-db-chain.sh /usr/local/lib/appcrane/appcrane-db-chain.sh && echo same',
    'echo "@@DBSUDOERS"; cat /etc/sudoers.d/appcrane-db-chain 2>/dev/null || echo "@@MISSING"',
    'echo "@@DBSUDOERSMODE"; stat -c \'%U:%G %a\' /etc/sudoers.d/appcrane-db-chain 2>&1',
    after,
    'echo "@@END"',
  ].join('\n');
  return execFileSync('docker', ['run', '--rm', '--tmpfs', '/mnt/data:size=64m',
    '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, '-v', `${INSTALL}:/src/install-host-hardening.sh:ro`, '-v', `${PUBLISH_HELPER}:/src/appcrane-publish-chain.sh:ro`, '-v', `${DB_HELPER}:/src/appcrane-db-chain.sh:ro`,
    sudoImage, 'bash', '-c', body], { encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] });
}

test('install-host-hardening: root-owned copy with REPO_DIR baked, sudoers rule with "" that permits only the bare copy', { skip: skipSudo }, async () => {
  const H = await import('../server/services/hostHardening.js');
  const out = installRun('app', [
    `echo "@@L"; su app -c "sudo -n -l ${DEST}" 2>&1; echo "rc=$?"`,
    `echo "@@LARG"; su app -c "sudo -n -l ${DEST} x" 2>&1; echo "rc=$?"`,
    `echo "@@RUN"; su app -c "sudo -n ${DEST}" 2>&1; echo "rc=$?"`,
    `echo "@@RUNARG"; su app -c "sudo -n ${DEST} x" 2>&1; echo "rc=$?"`,
    'echo "@@REPOSUDO"; su app -c "sudo -n bash /opt/appcrane/scripts/host-hardening.sh" 2>&1; echo "rc=$?"',
    'echo "@@DBL"; su app -c "sudo -n -l /usr/local/lib/appcrane/appcrane-db-chain.sh close:45432" >/dev/null 2>&1; echo "rc=$?"',
    'echo "@@DBREPO"; su app -c "sudo -n -l /opt/appcrane/scripts/appcrane-db-chain.sh close:45432" >/dev/null 2>&1; echo "rc=$?"',
  ].join('\n'));
  const sec = (n) => section(out, n);
  assert.match(out, /^@@EXIT 0$/m, out);
  assert.equal(sec('DIR').trim(), 'root:root 755');
  assert.equal(sec('FILE').trim(), 'root:root 755');
  assert.equal(sec('REPOLINE').trim(), "REPO_DIR='/opt/appcrane'");
  assert.equal(sec('SHA').trim(), createHash('sha256').update(H.expectedInstalledCopy(src, '/opt/appcrane')).digest('hex'),
    'the server compares against exactly what the install step writes');
  assert.match(sec('SUDOERS'), /^app ALL=\(root\) NOPASSWD: \/usr\/local\/lib\/appcrane\/host-hardening\.sh ""$/m);
  assert.equal(sec('SUDOERSMODE').trim(), 'root:root 440');
  assert.equal(sec('VISUDO').trim(), 'rc=0');
  assert.equal(sec('PUBHELPER').trim(), 'root:root 755');
  assert.match(sec('PUBSUDOERS'), /^app ALL=\(root\) NOPASSWD: \/usr\/local\/lib\/appcrane\/appcrane-publish-chain\.sh$/m);
  assert.equal(sec('DBHELPER').trim(), 'root:root 755\nsame');
  assert.match(sec('DBSUDOERS'), /^app ALL=\(root\) NOPASSWD: \/usr\/local\/lib\/appcrane\/appcrane-db-chain\.sh$/m);
  assert.equal(sec('DBSUDOERSMODE').trim(), 'root:root 440');
  assert.equal(sec('DBL').trim(), 'rc=0', 'the run user may sudo the installed DB helper with arguments');
  assert.equal(sec('DBREPO').trim(), 'rc=1', 'the repo copy of the DB helper is not sudoable');
  assert.match(sec('L'), /rc=0$/m, 'sudo -n -l <copy> exits 0 when permitted');
  assert.match(sec('LARG'), /rc=1$/m, 'with an argument it is not permitted');
  assert.match(sec('RUN'), /rc=0$/m, sec('RUN'));
  assert.match(sec('RUN'), /on \/mnt\/data|\/mnt\/data\/appcrane-disk-reserve|reserve: \/mnt\/data /, 'the copy found DATA_DIR through the baked repo path');
  assert.match(sec('RUNARG'), /rc=1$/m);
  assert.match(sec('REPOSUDO'), /rc=1$/m, 'the repo copy must not be sudoable');
});

test('install-host-hardening: a root run user gets the copy but no sudoers rule', { skip: skipSudo }, () => {
  const out = installRun('root');
  assert.match(out, /^@@EXIT 0$/m, out);
  assert.equal(section(out, 'FILE').trim(), 'root:root 755');
  assert.match(out, /^@@SUDOERS\n@@MISSING$/m, out);
  assert.equal(section(out, 'PUBHELPER').trim(), 'root:root 755', 'the helper is installed for a root server too');
  assert.match(out, /^@@PUBSUDOERS\n@@MISSING$/m, out);
  assert.equal(section(out, 'DBHELPER').trim(), 'root:root 755\nsame', 'the DB helper is installed for a root server too');
  assert.match(out, /^@@DBSUDOERS\n@@MISSING$/m, out);
});
