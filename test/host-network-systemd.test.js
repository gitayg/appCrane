import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// appcrane-host-network.service under a real systemd (PID 1 in a privileged
// Ubuntu 24.04 container): enabled and active after a run, the interim
// hand-installed appcrane-docker-user unit stopped, disabled and removed only
// then, the chains re-applied when docker.service restarts (PartOf; docker is a
// stand-in oneshot unit here, no dockerd) and after a reboot (container restart).

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'host-hardening.sh');
const { buildNetImages, netImages, note } = await import('./host-hardening-harness.js');
buildNetImages();
const R = '24.04';
const TAG = `appcrane-test-host-network-systemd:${R}`;
let image = null;
if (netImages[R]) {
  const t0 = Date.now();
  try {
    execFileSync('docker', ['build', '-q', '-t', TAG, '-'], {
      input: `FROM ${netImages[R]}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd >/dev/null && rm -rf /var/lib/apt/lists/*\n`,
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 60000,
    });
    image = TAG;
  } catch (_) { /* skipped below */ }
  note(`ubuntu ${R} systemd image`, t0, !!image);
}

const dk = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] });
const SKELETON = '-N DOCKER-USER\n-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n-A DOCKER-USER -d 169.254.169.254/32 -i docker0 -j DROP\n-A DOCKER-USER -d 169.254.169.254/32 -i br-+ -j DROP\n-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB\n-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH\n-A DOCKER-USER -i eth0 -j DROP\n-A DOCKER-USER -j RETURN\n';

const INPUT = '-P INPUT ACCEPT\n-A INPUT -j APPCRANE-INPUT\n';

function waitBooted(name) {
  for (let i = 0; i < 60; i++) {
    try {
      const s = dk('exec', name, 'systemctl', 'is-system-running').trim();
      if (s === 'running' || s === 'degraded') return s;
    } catch (e) {
      if (/^(running|degraded)/.test(String(e.stdout || ''))) return String(e.stdout).trim();
    }
    execFileSync('sleep', ['0.5']);
  }
  throw new Error('systemd did not finish booting');
}

test('systemd: unit enabled and active, interim unit removed after it, chains back after a Docker restart and a reboot', { skip: image ? false : 'docker (or the package mirror) unavailable' }, () => {
  const name = `appcrane-test-hn-sd-${randomBytes(4).toString('hex')}`;
  try {
    dk('run', '-d', '--privileged', '--name', name, '--tmpfs', '/run', '--tmpfs', '/run/lock', '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, image, '/lib/systemd/systemd');
    waitBooted(name);
    const out = dk('exec', name, 'bash', '-c', `
      mkdir -p /opt/appcrane/scripts /opt/appcrane/data; cp /src/host-hardening.sh /opt/appcrane/scripts/; printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env
      printf "[Service]\\nType=oneshot\\nRemainAfterExit=yes\\nExecStart=/bin/true\\n[Install]\\nWantedBy=multi-user.target\\n" > /etc/systemd/system/docker.service
      printf "#!/bin/sh\\niptables -N DOCKER-USER 2>/dev/null; iptables -F DOCKER-USER; iptables -A DOCKER-USER -i eth0 -p udp --dport 31001 -j RETURN; iptables -A DOCKER-USER -i eth0 -j DROP\\n" > /usr/local/sbin/appcrane-docker-user.sh
      chmod 755 /usr/local/sbin/appcrane-docker-user.sh
      printf "[Unit]\\nAfter=docker.service\\n[Service]\\nType=oneshot\\nRemainAfterExit=yes\\nExecStart=/usr/local/sbin/appcrane-docker-user.sh\\n[Install]\\nWantedBy=multi-user.target\\n" > /etc/systemd/system/appcrane-docker-user.service
      systemctl daemon-reload; systemctl enable --now docker.service appcrane-docker-user.service >/dev/null 2>&1
      echo @@INTERIM; systemctl is-active appcrane-docker-user.service
      echo @@RUN; APPCRANE_RESERVE_MIN_FREE_GB=100000 bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"
      echo @@UNIT; systemctl is-enabled appcrane-host-network.service; systemctl is-active appcrane-host-network.service
      echo @@OLD; systemctl is-active appcrane-docker-user.service || true; ls /etc/systemd/system/appcrane-docker-user.service /usr/local/sbin/appcrane-docker-user.sh 2>&1 || true
      echo @@WANTS; ls /etc/systemd/system/docker.service.wants /etc/systemd/system/multi-user.target.wants | grep -c appcrane-host-network
      echo @@V4; iptables -S DOCKER-USER
      iptables -F DOCKER-USER; iptables -D INPUT -j APPCRANE-INPUT; iptables -F APPCRANE-INPUT; systemctl restart docker.service; sleep 1
      echo @@RESTARTED; iptables -S DOCKER-USER; iptables -S INPUT; iptables -S APPCRANE-INPUT | grep -c -- '-i eth0 .* -j DROP'
    `);
    assert.match(out, /^@@INTERIM\nactive$/m);
    assert.match(out, /^@@EXIT 0$/m, out);
    assert.match(out, /^@@UNIT\nenabled\nactive$/m);
    assert.match(out, /^@@OLD\ninactive\n.*No such file.*\n.*No such file/m);
    assert.match(out, /^@@WANTS\n2$/m);
    assert.ok(out.includes(`@@V4\n${SKELETON}`), out);
    assert.ok(out.includes(`@@RESTARTED\n${SKELETON}${INPUT}5\n`), `PartOf=docker.service re-applies on a Docker restart: ${out}`);

    dk('restart', name);
    waitBooted(name);
    const boot = dk('exec', name, 'bash', '-c', 'systemctl is-active appcrane-host-network.service; iptables -S DOCKER-USER; iptables -S INPUT; ip6tables -S INPUT');
    assert.equal(boot, `active\n${SKELETON}${INPUT}${INPUT}`, 'a reboot comes back with the chains, the INPUT policy never changed');
  } finally {
    try { dk('rm', '-f', name); } catch (_) { /* never started */ }
  }
});
