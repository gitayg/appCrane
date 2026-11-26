import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// LIVE: scripts/docker-upgrade.sh inside privileged ubuntu:24.04 containers
// running Ubuntu's docker.io 29.1.3, with a daemon.json that registers runsc and
// --restart always containers: once without systemd (the script's no-init
// path), once with systemd as PID 1 and a stand-in appcrane.service that has
// Requires=docker.service like the unit install.sh writes.
// It downloads Docker CE from download.docker.com and takes minutes, so it runs
// only with APPCRANE_LIVE_DOCKER_UPGRADE=1 (not part of npm test).
//   APPCRANE_LIVE_DOCKER_UPGRADE=1 node --test test/docker-upgrade-live.test.js

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');
const IMAGE = 'appcrane-test-docker-upgrade:24.04';
const SD_IMAGE = 'appcrane-test-docker-upgrade-systemd:24.04';
const HELPER = 'busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662';
const PROBE = 'mirror.gcr.io/library/busybox:latest';

let skip = process.env.APPCRANE_LIVE_DOCKER_UPGRADE === '1' ? false : 'set APPCRANE_LIVE_DOCKER_UPGRADE=1 (downloads Docker CE, several minutes)';
if (!skip) {
  try {
    execFileSync('docker', ['build', '-q', '-t', IMAGE, '-'], {
      input: 'FROM mirror.gcr.io/library/ubuntu:24.04\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io curl ca-certificates >/dev/null\n',
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 300_000,
    });
    // The Ubuntu image ships /usr/sbin/policy-rc.d (exit 101), which stops apt
    // from starting services; a real host has none, so the systemd image drops it.
    execFileSync('docker', ['build', '-q', '-t', SD_IMAGE, '-'], {
      input: 'FROM mirror.gcr.io/library/ubuntu:24.04\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv docker.io curl ca-certificates python3-minimal >/dev/null && systemctl mask systemd-logind getty.target console-getty.service systemd-resolved.service && systemctl enable docker.service && rm -f /usr/sbin/policy-rc.d\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n',
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 300_000,
    });
  } catch (e) { skip = `test image not built: ${String(e.stderr || e.message).trim().split('\n').pop()}`; }
}

const SETUP = `
set -e
mkdir -p /etc/docker
printf '{"runtimes":{"runsc":{"path":"/usr/local/bin/runsc"}},"log-opts":{"max-size":"10m"}}\\n' > /etc/docker/daemon.json
printf '#!/bin/sh\\nexit 1\\n' > /usr/local/bin/runsc; chmod +x /usr/local/bin/runsc
md5sum /etc/docker/daemon.json | cut -c1-32 > /tmp/daemon.md5
nohup dockerd >/var/log/dockerd-first.log 2>&1 &
for i in $(seq 1 60); do docker version >/dev/null 2>&1 && break; sleep 1; done
docker pull -q ${PROBE} >/dev/null
docker run -d --restart always --name keep ${PROBE} sleep 1d >/dev/null
docker run -d --restart always --name keep2 ${PROBE} sleep 1d >/dev/null
echo "@@BEFORE $(docker version --format '{{.Server.Version}}')"
set +e
`;

const AFTER = `
echo "@@RC $rc"
echo "@@AFTER $(docker version --format '{{.Server.Version}}')"
echo "@@PKGS $(dpkg-query -W -f '\${db:Status-Abbrev}\${Package}=\${Version} ' docker.io docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras docker-buildx-plugin docker-compose-plugin)"
echo "@@DAEMON $(md5sum /etc/docker/daemon.json | cut -c1-32) $(cat /tmp/daemon.md5)"
echo "@@RUNNING $(docker ps -q | grep -c .)"
echo "@@RUNTIMES $(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}')"
echo "@@HELPER $(docker image inspect ${HELPER} >/dev/null 2>&1 && echo present || echo absent)"
kill -HUP "$(pidof dockerd)"; sleep 3
echo "@@HUP $(docker run --rm --add-host probe.test:host-gateway --entrypoint cat ${PROBE} /etc/hosts | awk '$NF=="probe.test"{print $1}')"
`;

function scenario(env) {
  const r = spawnSync('docker', ['run', '--rm', '--privileged', '-v', '/var/lib/docker', '-v', `${SCRIPTS}:/appcrane/scripts:ro`,
    ...Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]),
    IMAGE, 'bash', '-c', `${SETUP}\nbash /appcrane/scripts/docker-upgrade.sh; rc=$?\n${AFTER}`], { encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
  const out = r.stdout + r.stderr;
  const field = (k) => (new RegExp(`^@@${k} ?(.*)$`, 'm').exec(r.stdout) || [])[1]?.trim();
  return { out, field };
}

test('LIVE: docker.io 29.1.3 -> Docker CE >= 29.3, daemon.json and runsc kept, containers back, reload no longer breaks host-gateway', { skip, timeout: 600_000 }, () => {
  const { out, field } = scenario({ DOCKER_UPGRADE_WAIT_S: '60' });
  assert.equal(field('BEFORE'), '29.1.3', out);
  assert.equal(field('RC'), '0', out);
  const after = field('AFTER');
  const [maj, min] = after.split('.').map(Number);
  assert.ok(maj > 29 || (maj === 29 && min >= 3), `after: ${after}\n${out}`);
  assert.match(field('PKGS'), /ii docker-ce=5:/);
  assert.match(field('PKGS'), /ii containerd\.io=/);
  assert.doesNotMatch(field('PKGS'), /ii docker\.io=/);
  const [now, before] = field('DAEMON').split(' ');
  assert.equal(now, before, 'daemon.json unchanged');
  assert.equal(field('RUNNING'), '2', out);
  assert.match(field('RUNTIMES'), /\brunsc\b/);
  assert.match(out, /host-gateway: +ok \(\d+\.\d+\.\d+\.\d+\)/);
  assert.match(out, /running: +2 of 2 container\(s\) back/);
  assert.match(out, /daemon\.json: +kept \(backup \/etc\/docker\/daemon\.json\.appcrane-upgrade-bak\.\d+\)\n/);
  assert.match(field('HUP'), /^\d+\.\d+\.\d+\.\d+$/, `host-gateway after a SIGHUP on the new dockerd\n${out}`);
  assert.equal(field('HELPER'), 'absent', 'the probe image the script pulled is removed again');
  assert.doesNotMatch(field('PKGS'), /ii (docker-buildx-plugin|docker-compose-plugin|docker-ce-rootless-extras)=/, 'no Recommends installed');
});

test('LIVE: when the new dockerd does not come up, the previous docker.io is reinstalled and the script exits 1', { skip, timeout: 600_000 }, () => {
  const { out, field } = scenario({ DOCKER_UPGRADE_DOCKERD_WAIT_S: '0' });
  assert.equal(field('RC'), '1', out);
  assert.match(out, /dockerd did not answer within 0s after the install\. Rolling back/);
  assert.match(field('PKGS'), /ii docker\.io=29\.1\.3-0ubuntu3~24\.04\.2/);
  assert.doesNotMatch(field('PKGS'), /ii (docker-ce|docker-ce-cli|containerd\.io|docker-ce-rootless-extras|docker-buildx-plugin|docker-compose-plugin)=/, 'every package the upgrade added is gone');
  assert.equal(field('AFTER'), '29.1.3', out);
  const [now, before] = field('DAEMON').split(' ');
  assert.equal(now, before, 'daemon.json restored');
  assert.match(out, /previous Docker 29\.1\.3 is running again/);
  assert.equal(field('HUP'), 'invalid', `the same SIGHUP probe on docker.io 29.1.3 shows the bug (this is what the first test's probe would see without the upgrade)\n${out}`);
});

const SD_SETUP = `
set -e
for i in $(seq 1 60); do docker version >/dev/null 2>&1 && break; sleep 1; done
mkdir -p /etc/docker /srv/crane/api
printf '{"runtimes":{"runsc":{"path":"/usr/local/bin/runsc"}}}\\n' > /etc/docker/daemon.json
printf '#!/bin/sh\\nexit 1\\n' > /usr/local/bin/runsc; chmod +x /usr/local/bin/runsc
systemctl restart docker.service
echo '{"version":"test"}' > /srv/crane/api/info
printf 'PORT=5077\\nHOST=0.0.0.0\\n' > /srv/crane/.env
printf '[Unit]\\nAfter=network.target docker.service\\nRequires=docker.service\\n[Service]\\nWorkingDirectory=/srv/crane\\nExecStart=/usr/bin/python3 -m http.server 5077 --bind 127.0.0.1\\nRestart=always\\nRestartSec=3\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/appcrane.service
systemctl daemon-reload; systemctl enable --now appcrane.service
docker pull -q ${PROBE} >/dev/null; docker pull -q ${HELPER} >/dev/null
docker run -d --restart always --name keep ${PROBE} sleep 1d >/dev/null
for i in $(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:5077/api/info && break; sleep 0.5; done
echo "@@BEFORE $(docker version --format '{{.Server.Version}}') $(systemctl is-active appcrane.service)"
`;
const SD_AFTER = `
echo "@@RC $rc"
echo "@@AFTER $(docker version --format '{{.Server.Version}}')"
echo "@@UNITS $(systemctl is-active docker.socket docker.service appcrane.service | paste -sd' ' -)"
echo "@@HEALTH $(curl -fs -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:5077/api/info)"
echo "@@RUNNING $(docker ps -q | grep -c .)"
echo "@@HELPER $(docker image inspect ${HELPER} >/dev/null 2>&1 && echo present || echo absent)"
echo "@@STOPS $(journalctl -u appcrane --no-pager | grep -c 'Stopped appcrane.service')"
`;

function systemdScenario(env) {
  const name = `crane-test-dockerup-sd-${process.pid}`;
  const boot = spawnSync('docker', ['run', '-d', '--name', name, '--privileged', '--cgroupns=host', '-v', '/sys/fs/cgroup:/sys/fs/cgroup:rw',
    '-v', '/var/lib/docker', '-v', '/var/lib/containerd', '--tmpfs', '/run', '--tmpfs', '/run/lock', '-v', `${SCRIPTS}:/appcrane/scripts:ro`, SD_IMAGE], { encoding: 'utf8' });
  assert.equal(boot.status, 0, boot.stderr);
  try {
    let up = '';
    for (let i = 0; i < 60 && !/running|degraded/.test(up); i++) {
      up = spawnSync('docker', ['exec', name, 'systemctl', 'is-system-running'], { encoding: 'utf8' }).stdout.trim();
      spawnSync('sleep', ['1']);
    }
    const r = spawnSync('docker', ['exec', ...Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]), name, 'bash', '-c',
      `${SD_SETUP}\nset +e\nbash /appcrane/scripts/docker-upgrade.sh; rc=$?\n${SD_AFTER}`], { encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
    const out = r.stdout + r.stderr;
    const field = (k) => (new RegExp(`^@@${k} ?(.*)$`, 'm').exec(r.stdout) || [])[1]?.trim();
    return { out, field };
  } finally {
    spawnSync('docker', ['rm', '-f', '-v', name]);
  }
}

test('LIVE systemd: appcrane.service (Requires=docker.service) is stopped by the upgrade and started again; AppCrane answers', { skip, timeout: 600_000 }, () => {
  const { out, field } = systemdScenario({ DOCKER_UPGRADE_WAIT_S: '60' });
  assert.equal(field('BEFORE'), '29.1.3 active', out);
  assert.equal(field('RC'), '0', out);
  const [maj, min] = field('AFTER').split('.').map(Number);
  assert.ok(maj > 29 || (maj === 29 && min >= 3), out);
  assert.equal(field('UNITS'), 'active active active', out);
  assert.equal(field('HEALTH'), '200', out);
  assert.ok(Number(field('STOPS')) >= 1, `systemd stopped appcrane.service with docker.service (the B3 premise)\n${out}`);
  assert.match(out, /started again: +appcrane\.service\n/);
  assert.match(out, /AppCrane: +ok \(http:\/\/127\.0\.0\.1:5077\/api\/info\)/);
  assert.match(out, /runtimes: +runsc registered/);
  assert.match(out, /host-gateway: +ok/);
  assert.equal(field('RUNNING'), '1', out);
  assert.equal(field('HELPER'), 'present', 'a helper image that was already on the host is kept');
});

test('LIVE systemd: rollback starts docker.io and appcrane.service again', { skip, timeout: 600_000 }, () => {
  const { out, field } = systemdScenario({ DOCKER_UPGRADE_DOCKERD_WAIT_S: '0' });
  assert.equal(field('RC'), '1', out);
  assert.match(out, /Rolling back to the previous packages/);
  assert.equal(field('AFTER'), '29.1.3', out);
  assert.equal(field('UNITS'), 'active active active', out);
  assert.equal(field('HEALTH'), '200', out);
  assert.match(out, /AppCrane: ok/);
});
