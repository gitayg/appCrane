import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, symlinkSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

// install.sh's Docker install section, run on its own with apt-get, apt-cache,
// curl and dpkg as stubs: which Docker a fresh install gets, and that an
// existing Docker is never switched.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const install = readFileSync(join(REPO, 'install.sh'), 'utf8');
const start = install.indexOf('# ---------- Docker + systemd setup');
const end = install.indexOf('if ! id -nG "$RUN_USER"');
assert.ok(start > 0 && end > start, 'Docker section found in install.sh');
const SECTION = install.slice(start, end);

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dockerinst-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));
const BASH = execFileSync('bash', ['-c', 'command -v bash'], { encoding: 'utf8' }).trim();

function binDir(name, withDocker) {
  const bin = join(ROOT, name);
  mkdirSync(bin);
  for (const tool of ['awk', 'cut', 'tr', 'sort', 'tail', 'grep', 'sed', 'install', 'chmod', 'dirname', 'mkdir', 'cat', 'touch']) {
    const p = execFileSync('bash', ['-c', `command -v ${tool}`], { encoding: 'utf8' }).trim();
    symlinkSync(p, join(bin, tool));
  }
  const stub = (n, body) => { writeFileSync(join(bin, n), `#!${BASH}\n${body}\n`); chmodSync(join(bin, n), 0o755); };
  stub('apt-get', 'echo "apt-get $*" >> "$CALLS"');
  stub('apt-cache', `case "$1" in
  policy) printf 'docker.io:\\n  Installed: (none)\\n  Candidate: %s\\n  Version table:\\n' "$STUB_CANDIDATE" ;;
  madison) printf ' docker-ce | 5:29.10.1-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages\\n docker-ce | 5:29.2.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages\\n' ;;
esac`);
  stub('curl', 'echo "curl $*" >> "$CALLS"; for a in "$@"; do [[ "$a" == */dists/*/Release && "$a" != */dists/"$STUB_GOOD"/Release ]] && exit 22; done; prev=""; for a in "$@"; do [[ "$prev" == -o ]] && : > "$a"; prev="$a"; done; exit 0');
  stub('dpkg', '[[ "$1" == --print-architecture ]] && echo arm64');
  stub('dpkg-query', 'exit 0');
  if (withDocker) stub('docker', 'echo "Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2"');
  return bin;
}
const NO_DOCKER = binDir('bin-nodocker', false);
const HAS_DOCKER = binDir('bin-docker', true);

let n = 0;
function run({ candidate = '29.1.3-0ubuntu3~24.04.2', source, docker = false, good = 'noble' } = {}) {
  const dir = join(ROOT, `run${n++}`);
  mkdirSync(dir);
  const calls = join(dir, 'calls');
  writeFileSync(join(dir, 'os-release'), 'ID=ubuntu\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n');
  const script = `set -euo pipefail
log()  { echo "LOG $*"; }
warn() { echo "WARN $*"; }
die()  { echo "DIE $*"; exit 1; }
REPO_DIR="$1"
${SECTION}
`;
  const env = {
    PATH: docker ? HAS_DOCKER : NO_DOCKER, CALLS: calls, STUB_CANDIDATE: candidate, STUB_GOOD: good,
    DCE_OS_RELEASE: join(dir, 'os-release'), DCE_KEYRING: join(dir, 'keyrings', 'docker.asc'), DCE_SOURCES: join(dir, 'docker.sources'),
    ...(source ? { APPCRANE_DOCKER_SOURCE: source } : {}),
  };
  const r = spawnSync(BASH, ['-c', script, 'install', REPO], { encoding: 'utf8', env });
  return { code: r.status, out: r.stdout + r.stderr, calls: existsSync(calls) ? readFileSync(calls, 'utf8') : '', sources: existsSync(env.DCE_SOURCES) ? readFileSync(env.DCE_SOURCES, 'utf8') : null };
}

test('fresh install, Ubuntu docker.io 29.1.3: Docker CE >= 29.3 from the documented repository instead', () => {
  const r = run();
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /has the dockerd reload bug or is too old; installing Docker CE/);
  assert.match(r.calls, /curl -fsS -o \/dev\/null --max-time 30 https:\/\/download\.docker\.com\/linux\/ubuntu\/dists\/noble\/Release/);
  assert.match(r.calls, /curl -fsSL https:\/\/download\.docker\.com\/linux\/ubuntu\/gpg -o /);
  assert.match(r.sources, /^Types: deb\nURIs: https:\/\/download\.docker\.com\/linux\/ubuntu\nSuites: noble\nComponents: stable\nArchitectures: arm64\nSigned-By: .*docker\.asc\n$/);
  assert.match(r.calls, /apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold docker-ce=5:29\.10\.1-1~ubuntu\.24\.04~noble docker-ce-cli=5:29\.10\.1-1~ubuntu\.24\.04~noble containerd\.io\n/);
  assert.doesNotMatch(r.calls, /install -y docker\.io/);
});

test('fresh install, a docker.io candidate without the bug (27.5.1, 29.4.0) stays on docker.io; below 27 does not', () => {
  for (const c of ['27.5.1-0ubuntu1', '29.4.0-0ubuntu1']) {
    const r = run({ candidate: c });
    assert.equal(r.code, 0, r.out);
    assert.match(r.calls, /^apt-get install -y docker\.io\n$/, c);
  }
  assert.match(run({ candidate: '24.0.7-0ubuntu4' }).calls, /docker-ce=5:29\.10\.1/);
});

test('APPCRANE_DOCKER_SOURCE=distro keeps docker.io with a warning; a bad value stops the install', () => {
  let r = run({ source: 'distro' });
  assert.equal(r.code, 0, r.out);
  assert.match(r.calls, /^apt-get install -y docker\.io\n$/);
  assert.match(r.out, /WARN docker\.io 29\.1\.3-0ubuntu3~24\.04\.2 has the dockerd reload bug/);
  r = run({ source: 'ce;reboot' });
  assert.equal(r.code, 1);
  assert.match(r.out, /DIE APPCRANE_DOCKER_SOURCE must be 'auto' or 'distro'/);
  assert.equal(r.calls, '');
});

test('Docker has no repository for the codename: falls back to docker.io and says so', () => {
  const r = run({ good: 'none' });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /falling back to Ubuntu's docker\.io/);
  assert.match(r.calls, /apt-get install -y docker\.io\n$/);
  assert.doesNotMatch(r.calls, /docker-ce=/);
});

test('an existing Docker is never switched by install.sh', () => {
  const r = run({ docker: true });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /Docker already installed: Docker version 29\.1\.3/);
  assert.equal(r.calls, '');
});
