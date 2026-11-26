import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

// scripts/docker-upgrade.sh past the plan: rollback triggers, the manual
// rollback commands, restarting units stopped with docker.service and the
// AppCrane health wait. The script must run as root, so it runs in an
// ubuntu:24.04 container, with docker, apt-get, dpkg, dpkg-query, systemctl and
// curl replaced by stubs that keep state in /st. The systemctl stub fakes the
// one systemd behaviour that matters here: stopping docker.service also stops
// appcrane.service (Requires=), and starting docker does not start it again.
// The same path on a real systemd is in docker-upgrade-live.test.js.

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');
const IMAGE = 'mirror.gcr.io/library/ubuntu:24.04';
const ROOT = mkdtempSync(join(tmpdir(), 'crane-dockerrb-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));
const BIN = join(ROOT, 'bin');
mkdirSync(BIN);

let skip = false;
const probe = spawnSync('docker', ['image', 'inspect', IMAGE], { encoding: 'utf8' });
if (probe.status !== 0) skip = `${IMAGE} not available locally (docker image inspect exit ${probe.status})`;

const stub = (name, body) => { const p = join(BIN, name); writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`); chmodSync(p, 0o755); };
const OLD_PKGS = 'ii \\tcontainerd\\t2.2.1-0ubuntu1~24.04.4\\nii \\tdocker.io\\t29.1.3-0ubuntu3~24.04.2\\nii \\trunc\\t1.3.4-0ubuntu1~24.04.1\\n';
const NEW_PKGS = 'ii \\tcontainerd.io\\t2.4.2-4~ubuntu.24.04~noble\\nii \\tdocker-ce\\t5:29.10.1-1~ubuntu.24.04~noble\\nii \\tdocker-ce-cli\\t5:29.10.1-1~ubuntu.24.04~noble\\n';
stub('apt-get', `echo "apt-get $*" >> /st/calls
[[ "$1" == update ]] && exit 0
if [[ " $* " == *" docker-ce="* ]]; then
  [[ -n "$STUB_APT_FAIL" ]] && exit 100
  echo new > /st/pkgs
else
  [[ "$STUB_APT_FAIL" == all ]] && exit 100
  echo old > /st/pkgs
fi`);
stub('apt-cache', "echo ' docker-ce | 5:29.10.1-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages'");
stub('dpkg-query', `if [[ "$(cat /st/pkgs)" == new ]]; then printf '%b' '${NEW_PKGS}'; else printf '%b' '${OLD_PKGS}'; fi`);
stub('dpkg', `case "$1" in --print-architecture) echo arm64 ;; *) echo "dpkg $*" >> /st/calls ;; esac`);
stub('df', 'echo "Filesystem 1048576-blocks Used Available Capacity Mounted on"; echo "overlay 1871772 149493 1627126 9% /"');
stub('curl', `for a in "$@"; do
  [[ "$a" == */dists/noble/Release ]] && exit 0
  [[ "$a" == http://127.0.0.1:5077/api/info ]] && { [[ -f /st/crane_up ]] && exit 0; exit 7; }
done; exit 22`);
stub('systemctl', `echo "systemctl $*" >> /st/calls
case "$1" in
  list-dependencies) printf 'docker.service\\n  appcrane.service\\n  multi-user.target\\n  graphical.target\\n' ;;
  is-active) shift; [[ "$1" == --quiet ]] && shift; [[ -f "/st/active.$1" ]]; exit ;;
  show) exit 0 ;;
  stop) rm -f /st/up /st/active.appcrane.service /st/crane_up ;;
  start) shift
    for u in "$@"; do
      case "$u" in
        docker.service) [[ "$(cat /st/pkgs)" == new && -n "$STUB_DOCKERD_DEAD" ]] || touch /st/up ;;
        appcrane.service) touch /st/active.appcrane.service; [[ -n "$STUB_CRANE_DEAD" ]] || touch /st/crane_up ;;
      esac
    done ;;
  restart) touch /st/up ;;
esac
exit 0`);
stub('docker', `echo "docker $*" >> /st/calls
new() { [[ "$(cat /st/pkgs)" == new ]]; }
case "$1" in
  version) [[ -f /st/up ]] || exit 1; if new; then echo "\${STUB_NEW_VER:-29.10.1}"; else echo 29.1.3; fi ;;
  ps) [[ -f /st/up ]] || exit 1; if [[ "$2" == -q ]]; then printf 'a1\\nb2\\n'; else printf 'appcrane-shop-production\\nappcrane-db-mariadb\\n'; fi ;;
  info) if new; then echo "\${STUB_NEW_RUNTIMES:-io.containerd.runc.v2 runc runsc }"; else echo 'io.containerd.runc.v2 runc runsc '; fi ;;
  image) [[ -f /st/image ]] ;;
  pull) touch /st/image ;;
  rmi) rm -f /st/image ;;
  run) printf '127.0.0.1\\tlocalhost\\n%s\\tprobe.test\\n' "\${STUB_HG:-172.17.0.1}" ;;
  *) exit 1 ;;
esac`);

function scenario(env = {}, { image = false } = {}) {
  const r = spawnSync('docker', ['run', '--rm', '-v', `${SCRIPTS}:/appcrane/scripts:ro`, '-v', `${BIN}:/stub:ro`,
    '-e', 'PATH=/stub:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    '-e', 'DCE_SOURCES=/st/docker.sources', '-e', 'DCE_KEYRING=/st/docker.asc', '-e', 'APPCRANE_ENV_FILE=/st/crane.env',
    '-e', 'DOCKER_UPGRADE_WAIT_S=0', '-e', 'DOCKER_UPGRADE_DOCKERD_WAIT_S=3', '-e', 'APPCRANE_HEALTH_WAIT_S=4',
    ...Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]),
    IMAGE, 'bash', '-c', `mkdir -p /st /run/systemd/system /etc/docker
echo old > /st/pkgs; touch /st/up /st/active.appcrane.service /st/crane_up /st/docker.sources /st/docker.asc
${image ? 'touch /st/image' : ''}
echo 'PORT=5077' > /st/crane.env
echo '{"runtimes":{"runsc":{"path":"/usr/local/bin/runsc"}}}' > /etc/docker/daemon.json
bash /appcrane/scripts/docker-upgrade.sh; rc=$?
echo "@@RC $rc"; echo "@@PKGS $(cat /st/pkgs)"; echo "@@IMAGE $([[ -f /st/image ]] && echo present || echo absent)"
echo "@@CRANE $([[ -f /st/active.appcrane.service ]] && echo active || echo inactive)"
echo "@@CALLS"; cat /st/calls`], { encoding: 'utf8', timeout: 120_000 });
  const out = r.stdout + r.stderr;
  const field = (k) => (new RegExp(`^@@${k} ?(.*)$`, 'm').exec(r.stdout) || [])[1]?.trim();
  const calls = r.stdout.split('@@CALLS\n')[1] || '';
  return { out, field, calls };
}

const ROLLBACK_INSTALL = /apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold --allow-downgrades containerd=2\.2\.1-0ubuntu1~24\.04\.4 docker\.io=29\.1\.3-0ubuntu3~24\.04\.2 runc=1\.3\.4-0ubuntu1~24\.04\.1 containerd\.io- docker-ce- docker-ce-cli-\n/;

test('success: appcrane.service, stopped with docker.service, is started again and must answer; the probe image it pulled is removed', { skip, timeout: 120_000 }, () => {
  const { out, field, calls } = scenario();
  assert.equal(field('RC'), '0', out);
  assert.equal(field('CRANE'), 'active', out);
  assert.match(out, /started again: +appcrane\.service/);
  assert.match(out, /units started: +appcrane\.service/);
  assert.match(out, /AppCrane: +ok \(http:\/\/127\.0\.0\.1:5077\/api\/info\)/);
  assert.match(calls, /systemctl stop docker\.socket docker\.service\napt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold docker-ce=/, 'docker is stopped before apt swaps its unit files');
  assert.match(calls, /docker pull -q busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662\n/);
  assert.match(calls, /docker rmi busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662\n/);
  assert.equal(field('IMAGE'), 'absent');
  assert.doesNotMatch(out, /not rolled back/);
});

test('success with the helper image already on the host: no pull, nothing removed', { skip, timeout: 120_000 }, () => {
  const { out, field, calls } = scenario({}, { image: true });
  assert.equal(field('RC'), '0', out);
  assert.doesNotMatch(calls, /docker (pull|rmi)/);
  assert.equal(field('IMAGE'), 'present');
});

test('apt-get install fails: dpkg --configure -a, then the old packages, then appcrane.service started again', { skip, timeout: 120_000 }, () => {
  const { out, field, calls } = scenario({ STUB_APT_FAIL: '1' });
  assert.equal(field('RC'), '1', out);
  assert.match(out, /apt-get install failed\. Rolling back/);
  assert.match(calls, /dpkg --configure -a\napt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold --allow-downgrades containerd=2\.2\.1-0ubuntu1~24\.04\.4 docker\.io=29\.1\.3-0ubuntu3~24\.04\.2 runc=1\.3\.4-0ubuntu1~24\.04\.1\n/);
  assert.equal(field('CRANE'), 'active', out);
  assert.match(out, /AppCrane: ok/);
  assert.match(out, /previous Docker 29\.1\.3 is running again/);
});

for (const [name, env, msg] of [
  ['runsc lost', { STUB_NEW_RUNTIMES: 'io.containerd.runc.v2 runc ' }, /the runsc runtime is no longer registered/],
  ['host-gateway probe fails', { STUB_HG: 'invalid' }, /the host-gateway probe got 'invalid' instead of an IPv4/],
  ['version below 29.3', { STUB_NEW_VER: '29.2.0' }, /the running dockerd is 29\.2\.0, below 29\.3\.0/],
  ['new dockerd does not answer', { STUB_DOCKERD_DEAD: '1' }, /dockerd did not answer within 3s after the install/],
]) {
  test(`${name}: rolled back to the previous packages, appcrane.service started again, exit 1`, { skip, timeout: 120_000 }, () => {
    const { out, field, calls } = scenario(env);
    assert.equal(field('RC'), '1', out);
    assert.match(out, msg);
    assert.match(out, /Rolling back to the previous packages/);
    assert.match(calls, ROLLBACK_INSTALL, calls);
    assert.equal(field('PKGS'), 'old');
    assert.equal(field('CRANE'), 'active', out);
    assert.doesNotMatch(out, /not rolled back/);
  });
}

test('rollback install fails too: the exact manual rollback commands are printed', { skip, timeout: 120_000 }, () => {
  const { out, field } = scenario({ STUB_APT_FAIL: 'all' });
  assert.equal(field('RC'), '1', out);
  assert.match(out, /rollback failed too/);
  assert.match(out, /Docker was not rolled back\. To return to the previous packages by hand:\n +sudo systemctl stop docker\.socket docker\.service\n +sudo dpkg --configure -a\n +sudo apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold --allow-downgrades containerd=2\.2\.1-0ubuntu1~24\.04\.4 docker\.io=29\.1\.3-0ubuntu3~24\.04\.2 runc=1\.3\.4-0ubuntu1~24\.04\.1\n +sudo cp -p \/etc\/docker\/daemon\.json\.appcrane-upgrade-bak\.\d+ \/etc\/docker\/daemon\.json\n +sudo systemctl start docker\.socket docker\.service appcrane\.service\n/);
});

test('AppCrane does not answer after a good upgrade: exit 1, no rollback, the manual rollback commands are printed', { skip, timeout: 120_000 }, () => {
  const { out, field } = scenario({ STUB_CRANE_DEAD: '1' });
  assert.equal(field('RC'), '1', out);
  assert.equal(field('PKGS'), 'new');
  assert.match(out, /AppCrane: +FAILED: no answer on http:\/\/127\.0\.0\.1:5077\/api\/info within 4s/);
  assert.match(out, /Docker was not rolled back\. To return to the previous packages by hand:[\s\S]*--allow-downgrades containerd=2\.2\.1-0ubuntu1~24\.04\.4 docker\.io=29\.1\.3-0ubuntu3~24\.04\.2 runc=1\.3\.4-0ubuntu1~24\.04\.1 containerd\.io- docker-ce- docker-ce-cli-\n/);
});
