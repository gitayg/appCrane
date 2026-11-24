// Shared by host-hardening*.test.js: Ubuntu images with the packages a real box
// has, and run(), which runs scripts/host-hardening.sh in one and dumps the state.
// Split from host-hardening.test.js so each file stays inside npm test's
// per-file --test-timeout as the docker tests grow.
import { execFileSync } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'host-hardening.sh');

function dockerUp() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch (_) { return false; }
}

// One image per Ubuntu release, with the packages a real box has. Docker's
// layer cache makes every run after the first instant. Built at module load,
// which node --test still charges to this FILE's timeout (npm test passes
// --test-timeout=240000): on a cold CI runner with a slow package mirror the
// builds once ran past it and failed the file instead of skipping. So all the
// builds share one budget; past that, the docker tests skip. The budget must
// leave room for the docker-run tests too (about a minute on CI): with 120 s
// per file, 75 s of cold builds plus those tests timed out on 19 Nov 2026.
const BUILD_BUDGET_MS = 75000;
// Docker Hub's mirror on Google's registry: anonymous Docker Hub pulls are rate
// limited (a 429 measured from a cloud container on 18 Nov 2026), and a
// throttled pull stalls the build this file's timeout is counting.
const BASE_IMAGE = 'mirror.gcr.io/library/ubuntu';
// One line per build in the CI log, so a slow run shows where its time went.
const note = (what, t0, ok) => process.stderr.write(`host-hardening: ${what} ${ok ? 'built' : 'not built'} in ${Date.now() - t0} ms\n`);
const buildStart = Date.now();
const buildTimeLeft = () => BUILD_BUDGET_MS - (Date.now() - buildStart);
const RELEASES = ['24.04', '20.04'];
const images = {};
if (dockerUp()) {
  for (const rel of RELEASES) {
    const tag = `appcrane-test-host-hardening:${rel}`;
    if (buildTimeLeft() < 1000) break;
    const t0 = Date.now();
    try {
      execFileSync('docker', ['build', '-q', '-t', tag, '-'], {
        input: `FROM ${BASE_IMAGE}:${rel}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog logrotate jq unattended-upgrades >/dev/null && rm -rf /var/lib/apt/lists/*\nRUN useradd --system --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy\n`,
        stdio: ['pipe', 'pipe', 'pipe'], timeout: Math.max(1000, buildTimeLeft()),
      });
      images[rel] = tag;
    } catch (_) { /* no network or no image: the tests below skip */ }
    note(`ubuntu ${rel} image`, t0, !!images[rel]);
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
echo "@@CADDYDROPIN"; cat /etc/systemd/system/caddy.service.d/appcrane.conf 2>/dev/null || echo "@@MISSING"
echo "@@CADDYBAK"; ls /var/backups 2>/dev/null | grep -c '^caddy-dropin\.appcrane-bak\.' || true
`;

// Text between `@@<name>` and the next marker, or null for "@@MISSING".
function section(chunk, name) {
  const m = chunk.match(new RegExp(`^@@${name}\\n([\\s\\S]*?)(?=^@@|(?![\\s\\S]))`, 'm'));
  return m && !m[1].startsWith('@@MISSING') ? m[1] : null;
}

// Runs <setup>, then the script <runs> times, dumping state after each run.
function run(rel, setup = '', { runs = 1, env = {}, dockerArgs = [] } = {}) {
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
  const out = execFileSync('docker', ['run', '--rm', ...envArgs, ...dockerArgs, '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, images[rel], 'bash', '-c', body],
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
      caddyDropin: section(chunk, 'CADDYDROPIN'),
      caddyBackups: Number(chunk.match(/^@@CADDYBAK\n(\d+)$/m)[1]),
    };
  });
  const lr = out.split('@@LOGROTATE\n')[1];
  return { runs: runsOut, logrotate: lr, logrotateExit: Number(lr.match(/^@@LREXIT (\d+)/m)[1]) };
}

export { images, RELEASES, skipFor, buildTimeLeft, note, section, run, DUMP };
