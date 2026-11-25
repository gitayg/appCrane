import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Every Docker reload in scripts/host-hardening.sh goes through docker_reload:
// on Docker 28.x and 29.0-29.2 it does not reload at all, and after any reload
// it does, a throwaway container checks host-gateway. Measured with a SIGHUP in
// privileged docker:<version>-dind (busybox probe with --add-host
// probe.test:host-gateway): 27.5.1 ok; 28.0.4 and 28.5.2 `docker run` fails
// ("could not parse extra host IP invalid IP"); 29.0.0, 29.1.3, 29.2.0 write
// "invalid IP<TAB>probe.test" into /etc/hosts; 29.3.0, 29.4.0, 29.5.0, 29.10.1 ok.
// On 29.1.3 pinning host-gateway-ips in daemon.json, before the start or before
// the reload, did not survive the SIGHUP. Here dockerd and docker are shims (a
// real dockerd is not reloaded in this harness): the fake dockerd takes SIGHUP
// the way the script sends it without systemd, and the fake docker answers
// with the exact outputs measured above.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'host-hardening.sh');
const src = readFileSync(SCRIPT, 'utf8');
const { images, skipFor, block, exits } = await import('./host-hardening-harness.js');
const R = '24.04';

const FAKES = String.raw`
mkdir -p /run/fake /etc/docker
printf '#!/bin/sh\necho "runsc version release-20261116"\n' > /usr/local/bin/runsc; chmod 755 /usr/local/bin/runsc
cat > /run/fake/dockerd.sh <<'EOF'
on_hup() {
  echo hup >> /run/fake/hups
  touch /run/fake/reloaded
  if [ -f /run/fake/bug ]; then echo broken > /run/fake/hg; fi
}
trap on_hup HUP
while :; do sleep 0.1; done
EOF
cat > /usr/local/bin/docker <<'EOF'
#!/bin/bash
case "$1" in
  version) cat /run/fake/version; exit 0 ;;
  info) [[ "$*" == *Runtimes* ]] && { [ -f /run/fake/reloaded ] && echo '{"runc":{},"runsc":{}}' || echo '{"runc":{}}'; }; exit 0 ;;
  image) [[ "$3" == busybox:latest ]]; exit $? ;;
  images) exit 0 ;;
  network) echo "172.17.0.1 "; exit 0 ;;
  run)
    echo "$*" >> /run/fake/runs
    if [ "$(cat /run/fake/hg 2>/dev/null)" = broken ]; then
      if [ -f /run/fake/run-fails ]; then echo 'docker: Error response from daemon: could not parse extra host IP invalid IP: ParseAddr("invalid IP"): unable to parse IP' >&2; exit 125; fi
      printf '127.0.0.1\tlocalhost\ninvalid IP\tprobe.test\n'; exit 0
    fi
    printf '127.0.0.1\tlocalhost\n172.17.0.1\tprobe.test\n'; exit 0 ;;
esac
exit 0
EOF
chmod 755 /usr/local/bin/docker
(exec -a dockerd bash /run/fake/dockerd.sh) &
sleep 0.2
`;

function runFake(version, flags = []) {
  const body = [
    'set -e',
    'mkdir -p /opt/appcrane/scripts /opt/appcrane/data',
    'cp /src/host-hardening.sh /opt/appcrane/scripts/',
    'printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env',
    FAKES,
    `echo ${version} > /run/fake/version`,
    ...flags.map((f) => `touch /run/fake/${f}`),
    'set +e',
    'echo @@RUN; APPCRANE_RESERVE_MIN_FREE_GB=100000 bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"',
    'echo @@DAEMON; cat /etc/docker/daemon.json',
    'echo @@HUPS; if [ -f /run/fake/hups ]; then wc -l < /run/fake/hups; else echo 0; fi',
    'echo @@RUNS; if [ -f /run/fake/runs ]; then cat /run/fake/runs; fi',
    'echo @@BAKS; ls /etc/docker | grep -c appcrane-bak || true',
  ].join('\n');
  return execFileSync('docker', ['run', '--rm', '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, images[R], 'bash', '-c', body],
    { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] });
}

test('every reload goes through the host-gateway check', () => {
  const uses = [...src.matchAll(/\bdocker_reload\b(?!_raw)/g)].length;
  assert.ok(uses >= 4, 'gVisor calls docker_reload');
  assert.match(src, /^docker_reload\(\) \{\n  if docker_reload_breaks_host_gateway; then[\s\S]*?return 3\n  fi\n  docker_reload_raw \|\| return \$\?\n[\s\S]*?verify_host_gateway \|\| HH_FAILED\+=\("host-gateway"\)\n  return 0\n\}/m);
  const code = src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.doesNotMatch(code.replace(/^docker_reload_raw\(\) \{[\s\S]*?^\}/m, ''), /systemctl reload docker|kill -HUP/, 'no reload outside docker_reload_raw');
});

test('a Docker that reloads safely (29.10.1, 27.5.1): one SIGHUP, then the probe resolves host-gateway', { skip: skipFor(R) }, () => {
  for (const v of ['29.10.1', '27.5.1']) {
    const out = runFake(v);
    assert.deepEqual(exits(out), [0], out);
    assert.match(out, /gvisor: dockerd reloaded \(running containers untouched\); runsc is available/);
    assert.match(out, /host-gateway: a new container resolves host-gateway to 172\.17\.0\.1/);
    assert.equal(block(out, 'HUPS').trim(), '1', v);
    assert.match(block(out, 'RUNS'), /run --rm --network bridge --add-host probe\.test:host-gateway --entrypoint cat busybox:latest \/etc\/hosts/);
  }
});

test('Docker 28.x and 29.0-29.2 are never reloaded: runsc is registered for the next restart, no SIGHUP, the run still succeeds', { skip: skipFor(R) }, () => {
  for (const v of ['29.1.3', '28.0.4', '29.2.0']) {
    const out = runFake(v);
    assert.deepEqual(exits(out), [0], out);
    assert.match(out, new RegExp(`not reloading Docker ${v.replace(/\./g, '\\.')} — a reload on 28\\.x and 29\\.0-29\\.2 empties host-gateway`));
    assert.match(out, /gvisor: registered runsc/);
    assert.equal(block(out, 'HUPS').trim(), '0', v);
    assert.equal(block(out, 'RUNS'), '', 'no probe without a reload');
    assert.ok(JSON.parse(block(out, 'DAEMON')).runtimes.runsc);
  }
});

for (const [name, flags] of [['"invalid IP" in /etc/hosts, as 29.0-29.2 do', ['bug']], ['docker run refused, as 28.x does', ['bug', 'run-fails']]]) {
  test(`a reload that breaks host-gateway (${name}) on a version not known to: fails loudly, exit non-zero, daemon.json not touched for it`, { skip: skipFor(R) }, () => {
    const out = runFake('29.10.1', flags);
    assert.deepEqual(exits(out), [3], out);
    assert.match(out, /host-gateway: BROKEN after the Docker reload — a new container got '(invalid|no address)'.*Only restarting the Docker daemon repairs it/);
    if (flags.includes('run-fails')) assert.match(out, /could not parse extra host IP invalid IP/);
    assert.match(out, /failed sections: host-gateway/);
    assert.equal(JSON.parse(block(out, 'DAEMON'))['host-gateway-ips'], undefined);
    assert.equal(block(out, 'HUPS').trim(), '1');
  });
}
