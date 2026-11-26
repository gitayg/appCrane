import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

// scripts/docker-upgrade.sh: argument validation, preflight refusals and the
// --dry-run plan, with docker/dpkg/apt/curl/df replaced by stubs on PATH. The
// stub outputs are the real formats captured in ubuntu:24.04 (2026-11-25).
// The live upgrade is in docker-upgrade-live.test.js.

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'docker-upgrade.sh');
const ROOT = mkdtempSync(join(tmpdir(), 'crane-dockerup-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));
const BIN = join(ROOT, 'bin');
mkdirSync(BIN);

const stub = (name, body) => { const p = join(BIN, name); writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`); chmodSync(p, 0o755); };
stub('curl', 'for a in "$@"; do [[ "$a" == */dists/"$STUB_GOOD_CODENAME"/Release ]] && exit 0; [[ -n "$STUB_CRANE_URL" && "$a" == "$STUB_CRANE_URL" ]] && exit 0; done; exit 22');
stub('docker', `case "$1" in
  version) [[ -n "$STUB_SERVER" ]] || exit 1; echo "$STUB_SERVER" ;;
  ps) printf '%s' "$STUB_PS" ;;
  info) echo "$STUB_RUNTIMES" ;;
  *) exit 1 ;;
esac`);
stub('dpkg-query', 'printf "%b" "$STUB_DPKGQ"');
stub('dpkg', '[[ "$1" == --print-architecture ]] && echo arm64');
stub('apt-cache', '[[ "$1" == madison ]] && cat "$STUB_MADISON"');
stub('df', 'echo "Filesystem     1048576-blocks   Used Available Capacity Mounted on"; echo "overlay               1871772 149493   $STUB_FREE       9% /"');

const MADISON = join(ROOT, 'madison.txt');
writeFileSync(MADISON, [
  ' docker-ce | 5:29.10.1-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages',
  ' docker-ce | 5:29.9.3-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages',
  ' docker-ce | 5:29.2.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages',
  '',
].join('\n'));
const SOURCES = join(ROOT, 'docker.sources');
writeFileSync(SOURCES, 'Types: deb\n');
const osRelease = (id, codename) => { const p = join(ROOT, `os-${id}-${codename}`); writeFileSync(p, `ID=${id}\nVERSION_CODENAME=${codename}\nUBUNTU_CODENAME=${codename}\n`); return p; };

const DOCKER_IO = 'ii \tcontainerd\t2.2.1-0ubuntu1~24.04.4\\nrc \tcontainerd.io\t2.4.2-4~ubuntu.24.04~noble\\nii \tdocker.io\t29.1.3-0ubuntu3~24.04.2\\nii \trunc\t1.3.4-0ubuntu1~24.04.1\\n';

function run(args, env = {}) {
  const r = spawnSync('bash', [SCRIPT, ...args], {
    encoding: 'utf8',
    env: {
      PATH: `${BIN}:${process.env.PATH}`,
      DCE_OS_RELEASE: osRelease('ubuntu', 'noble'),
      DCE_SOURCES: SOURCES,
      DCE_KEYRING: join(ROOT, 'docker.asc'),
      DOCKER_DAEMON_JSON: join(ROOT, 'no-daemon.json'),
      STUB_GOOD_CODENAME: 'noble',
      STUB_SERVER: '29.1.3',
      STUB_PS: 'appcrane-shop-production\nappcrane-db-mariadb\n',
      STUB_RUNTIMES: 'io.containerd.runc.v2 runc runsc ',
      STUB_DPKGQ: DOCKER_IO,
      STUB_MADISON: MADISON,
      STUB_FREE: '1627126',
      ...env,
    },
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('unknown argument: usage and exit 2', () => {
  const r = run(['--force']);
  assert.equal(r.code, 2);
  assert.match(r.err, /unknown argument: --force/);
  assert.match(r.err, /Usage:/);
});

test('DOCKER_VERSION below 29.3 or not a version is refused before anything else', () => {
  let r = run(['--dry-run'], { DOCKER_VERSION: '29.2.0' });
  assert.equal(r.code, 2);
  assert.match(r.err, /below 29\.3\.0/);
  r = run(['--dry-run'], { DOCKER_VERSION: 'latest; rm -rf /' });
  assert.equal(r.code, 2);
  assert.match(r.err, /is not a version/);
});

test('without --dry-run a non-root caller is refused', { skip: process.getuid?.() === 0 ? 'running as root' : false }, () => {
  const r = run([]);
  assert.equal(r.code, 2);
  assert.match(r.err, /run as root/);
});

test('dry run on the 24.04 host prints the one-transaction plan and changes nothing', () => {
  const r = run(['--dry-run']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /dockerd now: +29\.1\.3/);
  assert.match(r.out, /target: +docker-ce 5:29\.10\.1-1~ubuntu\.24\.04~noble/);
  assert.match(r.out, /apt-get install: -y --no-install-recommends -o Dpkg::Options::=--force-confold docker-ce=5:29\.10\.1-1~ubuntu\.24\.04~noble docker-ce-cli=5:29\.10\.1-1~ubuntu\.24\.04~noble containerd\.io docker\.io- containerd- runc-\n/);
  assert.match(r.out, /runsc runtime: +registered/);
  assert.match(r.out, /running now: +2 container\(s\)\n +appcrane-shop-production\n +appcrane-db-mariadb/);
  assert.match(r.out, /every running container stops and starts again/);
  assert.match(r.out, /Dry run: nothing changed\./);
});

test('dry run with DOCKER_VERSION picks that version; one missing from the repository is refused', () => {
  let r = run(['--dry-run'], { DOCKER_VERSION: '29.9.3' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /target: +docker-ce 5:29\.9\.3-1~ubuntu\.24\.04~noble/);
  r = run(['--dry-run'], { DOCKER_VERSION: '29.99.0' });
  assert.equal(r.code, 1);
  assert.match(r.err, /no docker-ce 29\.99\.0 in Docker's repository for 'noble'/);
});

test('repository not configured yet: the plan says the version is chosen after adding it', () => {
  const r = run(['--dry-run'], { DCE_SOURCES: join(ROOT, 'absent.sources') });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /target: +docker-ce newest at or above 29\.3\.0 \(Docker's repository is not configured yet/);
});

test('preflight refusals: codename Docker does not publish, non-Ubuntu, low disk', () => {
  let r = run(['--dry-run'], { DCE_OS_RELEASE: osRelease('ubuntu', 'zesty') });
  assert.equal(r.code, 1);
  assert.match(r.err, /Docker's repository has no Ubuntu 'zesty'/);
  r = run(['--dry-run'], { DCE_OS_RELEASE: osRelease('debian', 'bookworm') });
  assert.equal(r.code, 1);
  assert.match(r.err, /Ubuntu only/);
  r = run(['--dry-run'], { STUB_FREE: '300' });
  assert.equal(r.code, 1);
  assert.match(r.err, /only 300 MB free on \/var/);
});

test('idempotent: already on Docker CE >= 29.3 without docker.io is a no-op', () => {
  const ce = 'ii \tcontainerd.io\t2.4.2-4~ubuntu.24.04~noble\\nii \tdocker-ce\t5:29.10.1-1~ubuntu.24.04~noble\\nii \tdocker-ce-cli\t5:29.10.1-1~ubuntu.24.04~noble\\nrc \tdocker.io\t29.1.3-0ubuntu3~24.04.2\\n';
  let r = run(['--dry-run'], { STUB_DPKGQ: ce, STUB_SERVER: '29.10.1' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Nothing to do/);
  assert.doesNotMatch(r.out, /Docker upgrade plan/);
  r = run(['--dry-run'], { STUB_DPKGQ: ce, STUB_SERVER: '29.10.1', DOCKER_VERSION: '29.9.3' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /target: +docker-ce 5:29\.9\.3/);
});

test('dry run says what changes: no Recommends, so buildx and compose are added only where they were installed', () => {
  let r = run(['--dry-run']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /adds: +docker-ce docker-ce-cli containerd\.io\n/);
  assert.match(r.out, /removes: +docker\.io containerd runc\n/);
  assert.match(r.out, /BuildKit: +unchanged, off \(buildx was not installed before; Recommends are not installed\)/);
  assert.match(r.out, /compose: +not installed/);
  r = run(['--dry-run'], { STUB_DPKGQ: `${DOCKER_IO}ii \tdocker-buildx\t0.30.1-0ubuntu1~24.04.1\\nii \tdocker-compose-v2\t2.40.3+ds1-0ubuntu1~24.04.1\\n` });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /apt-get install: -y --no-install-recommends -o Dpkg::Options::=--force-confold docker-ce=\S+ docker-ce-cli=\S+ containerd\.io docker-buildx-plugin docker-buildx- docker-compose-plugin docker-compose-v2- docker\.io- containerd- runc-\n/);
  assert.match(r.out, /adds: +docker-ce docker-ce-cli containerd\.io docker-buildx-plugin docker-compose-plugin\n/);
  assert.match(r.out, /removes: +docker-buildx docker-compose-v2 docker\.io containerd runc\n/);
  assert.match(r.out, /BuildKit: +unchanged, on/);
  assert.match(r.out, /compose: +kept/);
});

test('dry run: AppCrane health is read from the PORT in its .env, checked after only when it answers now', () => {
  const env = join(ROOT, 'crane.env');
  writeFileSync(env, 'PORT=5077\nHOST=0.0.0.0\n');
  let r = run(['--dry-run'], { APPCRANE_ENV_FILE: env, STUB_CRANE_URL: 'http://127.0.0.1:5077/api/info' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /AppCrane: +answering on http:\/\/127\.0\.0\.1:5077\/api\/info; must answer again within 180s/);
  r = run(['--dry-run'], { APPCRANE_ENV_FILE: join(ROOT, 'absent.env') });
  assert.match(r.out, /AppCrane: +not answering on http:\/\/127\.0\.0\.1:5001\/api\/info now; not checked after/);
});

test('the host-gateway probe image is the pinned HELPER_IMAGE, never a tag', () => {
  const lib = readFileSync(join(dirname(SCRIPT), 'lib', 'docker-ce.sh'), 'utf8');
  const js = readFileSync(join(dirname(SCRIPT), '..', 'server', 'services', 'volumeHelper.js'), 'utf8');
  const sh = /^DCE_PROBE_IMAGE='([^']+)'$/m.exec(lib)?.[1];
  assert.equal(sh, /export const HELPER_IMAGE = '([^']+)'/.exec(js)?.[1]);
  assert.match(sh, /^busybox@sha256:[0-9a-f]{64}$/);
  assert.doesNotMatch(readFileSync(SCRIPT, 'utf8'), /:latest|DOCKER_UPGRADE_PROBE_IMAGE/);
});
