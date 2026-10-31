import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { execFileSync } from 'child_process';
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

function dockerUp() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch (_) { return false; }
}

// One image per Ubuntu release, with the packages a real box has. Docker's
// layer cache makes every run after the first instant. Built at module load so
// the build is not charged to a test's timeout.
const RELEASES = ['24.04', '20.04'];
const images = {};
if (dockerUp()) {
  for (const rel of RELEASES) {
    const tag = `appcrane-test-host-hardening:${rel}`;
    try {
      execFileSync('docker', ['build', '-q', '-t', tag, '-'], {
        input: `FROM ubuntu:${rel}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog logrotate jq unattended-upgrades >/dev/null && rm -rf /var/lib/apt/lists/*\nRUN useradd --system --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy\n`,
        stdio: ['pipe', 'pipe', 'pipe'], timeout: 600000,
      });
      images[rel] = tag;
    } catch (_) { /* no network or no image: the tests below skip */ }
  }
}
const skipFor = (rel) => images[rel] ? false : 'docker (or the package mirror) unavailable';

const DUMP = `
for f in /etc/systemd/journald.conf.d/50-appcrane.conf /etc/systemd/system/logrotate.timer.d/50-appcrane.conf /etc/logrotate.d/rsyslog /etc/docker/daemon.json; do
  echo "@@FILE $f"; cat "$f" 2>/dev/null || echo "@@MISSING"
done
echo "@@SUM"; cat /etc/systemd/journald.conf.d/50-appcrane.conf /etc/systemd/system/logrotate.timer.d/50-appcrane.conf /etc/logrotate.d/rsyslog /etc/docker/daemon.json 2>/dev/null | md5sum
echo "@@RESERVE"; stat -c %s /appcrane-disk-reserve 2>/dev/null || echo none
echo "@@AUTO"; cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo "@@MISSING"
echo "@@APTCFG"; apt-config dump | grep -E '^(APT::Periodic::(Unattended-Upgrade|Update-Package-Lists)|Unattended-Upgrade::Automatic-Reboot) ' || true
echo "@@UU"; dpkg-query -W -f='\${Status}\n' unattended-upgrades 2>&1 || true
echo "@@CADDYDIR"; stat -c '%U:%G %a' /var/log/caddy 2>/dev/null || echo missing
`;

// Text between `@@<name>` and the next marker, or null for "@@MISSING".
function section(chunk, name) {
  const m = chunk.match(new RegExp(`^@@${name}\\n([\\s\\S]*?)(?=^@@|(?![\\s\\S]))`, 'm'));
  return m && !m[1].startsWith('@@MISSING') ? m[1] : null;
}

// Runs <setup>, then the script <runs> times, dumping state after each run.
function run(rel, setup = '', { runs = 1, env = {} } = {}) {
  const body = [
    'set -e',
    'mkdir -p /opt/appcrane/scripts /opt/appcrane/data',
    'cp /src/host-hardening.sh /opt/appcrane/scripts/',
    'printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env',
    setup,
    ...Array.from({ length: runs }, (_, i) => `echo "@@RUN ${i}"; bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"; ${DUMP}`),
    'echo "@@LOGROTATE"; logrotate -d /etc/logrotate.conf 2>&1; echo "@@LREXIT $?"',
  ].join('\n');
  const envArgs = Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]);
  const out = execFileSync('docker', ['run', '--rm', ...envArgs, '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, images[rel], 'bash', '-c', body],
    { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] });
  const runsOut = out.split(/^@@RUN \d+\n/m).slice(1).map((chunk) => {
    const file = (p) => {
      const m = chunk.match(new RegExp(`^@@FILE ${p.replace(/[.]/g, '\\.')}\\n([\\s\\S]*?)(?=^@@)`, 'm'));
      return m && !m[1].startsWith('@@MISSING') ? m[1] : null;
    };
    return {
      log: chunk.split('@@EXIT')[0],
      exit: Number(chunk.match(/^@@EXIT (\d+)/m)[1]),
      journald: file('/etc/systemd/journald.conf.d/50-appcrane.conf'),
      timer: file('/etc/systemd/system/logrotate.timer.d/50-appcrane.conf'),
      rsyslog: file('/etc/logrotate.d/rsyslog'),
      daemon: file('/etc/docker/daemon.json'),
      sum: chunk.match(/^@@SUM\n(.*)$/m)[1],
      reserve: chunk.match(/^@@RESERVE\n(.*)$/m)[1],
      auto: section(chunk, 'AUTO'),
      aptcfg: section(chunk, 'APTCFG'),
      uu: section(chunk, 'UU'),
      caddyDir: chunk.match(/^@@CADDYDIR\n(.*)$/m)[1],
    };
  });
  const lr = out.split('@@LOGROTATE\n')[1];
  return { runs: runsOut, logrotate: lr, logrotateExit: Number(lr.match(/^@@LREXIT (\d+)/m)[1]) };
}

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

test('caddy log dir: created owned by caddy, mode 0750; a root-owned one is fixed; a second run changes nothing', { skip: skipFor(R) }, () => {
  const fresh = run(R, '', { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(fresh.runs[0].exit, 0, fresh.runs[0].log);
  assert.equal(fresh.runs[0].caddyDir, 'caddy:caddy 750');
  assert.equal(fresh.runs[1].caddyDir, 'caddy:caddy 750');
  assert.match(fresh.runs[1].log, /already caddy:caddy 0750/);

  const rootOwned = run(R, 'mkdir -p /var/log/caddy && chown root:root /var/log/caddy && chmod 755 /var/log/caddy',
    { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(rootOwned.runs[0].caddyDir, 'caddy:caddy 750');
  assert.match(rootOwned.runs[0].log, /was: root:root 755/);
});

test('caddy log dir: skipped with a warning when the caddy user does not exist', { skip: skipFor(R) }, () => {
  const r = run(R, 'userdel caddy', { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.equal(r.runs[0].caddyDir, 'missing');
  assert.match(r.runs[0].log, /user 'caddy' does not exist/);
});
