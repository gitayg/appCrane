import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The network section of scripts/host-hardening.sh, run for real in privileged
// Ubuntu containers (their own netfilter tables): the DOCKER-USER skeleton in
// both families, the INPUT baseline with and without ufw, and the boot script
// that re-applies it.
//
// Production evidence it answers (Docker 29.1.3): DOCKER-USER was empty, so two
// UDP ports published on 0.0.0.0 answered the internet although ufw had no rule
// for them; ufw never sees a published port, since FORWARD jumps to DOCKER-USER
// and DOCKER-FORWARD before ufw's chains.

const { RELEASES, buildNetImages, netImages, skipNet, runNet, block, exits } = await import('./host-hardening-harness.js');
const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'host-hardening.sh');
buildNetImages();

const SKELETON = (imds) => [
  '-N DOCKER-USER',
  '-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN',
  `-A DOCKER-USER -d ${imds} -i docker0 -j DROP`,
  `-A DOCKER-USER -d ${imds} -i br-+ -j DROP`,
  '-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH',
  '-A DOCKER-USER -i eth0 -j DROP',
  '-A DOCKER-USER -j RETURN',
].join('\n');
const PUBLISHED = '-A APPCRANE-PUBLISH -p udp -m conntrack --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
const SAVE = 'for t in iptables ip6tables; do $t-save -t filter | grep -v "^#" | sed "s/ \\[[0-9]*:[0-9]*\\]$//"; done';

// AppCrane's port is dropped on the public interface before anything accepts
// it, and before every per-port accept in APPCRANE-INPUT; the only accept for
// it is the one for every other interface, right after that DROP.
const DROP5001 = '-A APPCRANE-INPUT -i eth0 -p tcp -m tcp --dport 5001 -j DROP';
function assert5001Closed(save) {
  for (const fam of save.split('*filter').slice(1)) {
    const lines = fam.split('\n');
    const d = lines.indexOf(DROP5001);
    lines.forEach((l, i) => {
      if (/\b5001\b/.test(l) && /-j ACCEPT/.test(l)) {
        assert.ok(d >= 0 && i === d + 1 && l === '-A APPCRANE-INPUT -p tcp -m tcp --dport 5001 -j ACCEPT', `accepts 5001 on the public interface: ${l}`);
      }
    });
    const rules = lines.filter((l) => l.startsWith('-A APPCRANE-INPUT'));
    if (!rules.length) continue;
    const drop = rules.indexOf(DROP5001);
    assert.ok(drop > 0, fam);
    const firstPort = rules.findIndex((l) => /--dport \d+ -j ACCEPT/.test(l) && !/--sport/.test(l) && !/--dport 5001 /.test(l));
    assert.ok(drop < firstPort, 'the 5001 DROP precedes the port accepts');
  }
}

for (const rel of RELEASES) {
  test(`ubuntu ${rel}: DOCKER-USER skeleton in both families, APPCRANE-PUBLISH kept, idempotent, INPUT DROP, boot script re-applies it`, { skip: skipNet(rel) }, () => {
    const out = runNet(rel, `
      iptables -N APPCRANE-PUBLISH
      iptables ${PUBLISHED}
      hh
      echo @@V4; iptables -S DOCKER-USER
      echo @@V6; ip6tables -S DOCKER-USER
      echo @@PUB; iptables -S APPCRANE-PUBLISH; ip6tables -S APPCRANE-PUBLISH
      echo @@SAVE1; ${SAVE}
      hh
      echo @@SAVE2; ${SAVE}
      echo @@STATE; cat /var/lib/appcrane/host-network.state
      echo @@UNIT; cat /etc/systemd/system/appcrane-host-network.service
      echo @@BOOTMODE; stat -c '%U:%G %a' /usr/local/sbin/appcrane-host-network.sh
      for t in iptables ip6tables; do $t -P INPUT ACCEPT; $t -F; $t -X; done
      echo @@WIPED; ${SAVE}
      echo @@BOOT; /usr/local/sbin/appcrane-host-network.sh 2>&1; echo "@@BOOTEXIT $?"
      echo @@SAVE3; ${SAVE}
    `);
    const [a, b] = exits(out);
    assert.equal(a, 0, out);
    assert.equal(b, 0, out);
    assert.equal(block(out, 'V4').trim(), SKELETON('169.254.169.254/32'));
    assert.equal(block(out, 'V6').trim(), SKELETON('fd00:ec2::254/128'));
    assert.equal(block(out, 'PUB').trim(), ['-N APPCRANE-PUBLISH', PUBLISHED, '-N APPCRANE-PUBLISH'].join('\n'), 'the server-owned chain is created, never flushed');
    assert.equal(block(out, 'SAVE2'), block(out, 'SAVE1'), 'a second run yields the same tables');

    const save = block(out, 'SAVE2');
    assert.match(save, /^:INPUT DROP$/m);
    assert.equal(save.match(/^:INPUT DROP$/gm).length, 2, 'both families');
    assert.equal(save.match(/^-A INPUT -j APPCRANE-INPUT$/gm).length, 2);
    for (const r of ['-A APPCRANE-INPUT -i lo -j ACCEPT', '-A APPCRANE-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
      '-A APPCRANE-INPUT -p tcp -m tcp --dport 22 -j ACCEPT', '-A APPCRANE-INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
      '-A APPCRANE-INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT', '-A APPCRANE-INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT']) {
      assert.ok(save.includes(`${r}\n`), r);
    }
    assert5001Closed(save);

    const state = block(out, 'STATE');
    assert.match(state, /^result=ok$/m);
    assert.match(state, /^ext=eth0$/m);
    assert.match(state, /^input_mode=appcrane-input$/m);
    assert.match(state, /^input_policy=DROP$/m);
    const unit = block(out, 'UNIT');
    for (const l of ['After=docker.service network-online.target', 'PartOf=docker.service', 'Type=oneshot', 'RemainAfterExit=yes',
      'ExecStart=/usr/local/sbin/appcrane-host-network.sh', 'WantedBy=docker.service multi-user.target']) assert.ok(unit.includes(l), l);
    assert.equal(block(out, 'BOOTMODE').trim(), 'root:root 755');

    assert.doesNotMatch(block(out, 'WIPED'), /APPCRANE|DOCKER-USER|INPUT DROP/);
    assert.match(out, /^@@BOOTEXIT 0$/m, block(out, 'BOOT'));
    // After a reboot the server-owned chain starts empty; everything else is back.
    assert.equal(block(out, 'SAVE3'), save.replace(`${PUBLISHED}\n`, ''));
  });
}

const R = '24.04';

test('ufw active: only adds (allow 80, 443; existing port-22 rule kept, not widened; deny 5001 on eth0 first), never deletes or reorders', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    ufw allow proto tcp from 10.0.0.0/8 to any port 22 >/dev/null
    ufw allow 8080/tcp >/dev/null
    ufw --force enable >/dev/null
    echo @@BEFORE; ufw show added | grep '^ufw '
    hh; hh
    echo @@AFTER; ufw show added | grep '^ufw '
    echo @@NUMBERED; ufw status numbered
    echo @@CHAIN; { iptables-save; ip6tables-save; } | grep -c APPCRANE-INPUT || true
    echo @@V4; iptables -S DOCKER-USER
    echo @@STATE; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0, 0], out);
  const before = block(out, 'BEFORE').trim().split('\n');
  const after = block(out, 'AFTER').trim().split('\n');
  assert.deepEqual(after.filter((l) => before.includes(l)), before, 'existing rules kept, in order');
  assert.deepEqual(after.filter((l) => !before.includes(l)).sort(),
    ['ufw allow 443/tcp', 'ufw allow 80/tcp', 'ufw deny in on eth0 to any port 5001'].sort());
  assert.ok(!after.some((l) => /^ufw allow 22/.test(l)), 'the 10.0.0.0/8-only SSH rule is not widened');
  assert.match(block(out, 'NUMBERED'), /^\[ 1\] 5001 on eth0 +DENY IN/m);
  assert.match(block(out, 'NUMBERED'), /5001 \(v6\) on eth0 +DENY IN/);
  assert.equal(block(out, 'CHAIN').trim(), '0', 'no APPCRANE-INPUT in ufw mode');
  assert.equal(block(out, 'V4').trim(), SKELETON('169.254.169.254/32'), 'DOCKER-USER is set in ufw mode too');
  assert.match(block(out, 'STATE'), /^input_mode=ufw$/m);
});

test('no ufw: an uncovered listener refuses DROP (policy left ACCEPT, exit non-zero); APPCRANE_INPUT_ALLOW covers it; the app port and a 5001 allow never count', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    nc -lk 0.0.0.0 8080 >/dev/null 2>&1 &
    nc -lk 0.0.0.0 5001 >/dev/null 2>&1 &
    sleep 0.5
    hh
    echo @@REFUSED; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1; cat /var/lib/appcrane/host-network.state
    APPCRANE_INPUT_ALLOW="8080/tcp 5001/tcp bogus 022/tcp 08/tcp 0/udp" hh
    echo @@ALLOWED; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1; cat /var/lib/appcrane/host-network.state
    echo @@SAVE; ${SAVE}
  `);
  const [refused, allowed] = exits(out);
  assert.equal(refused, 3, out);
  assert.match(out, /INPUT policy NOT set to DROP .*8080\/tcp@0\.0\.0\.0\(nc\)/);
  assert.doesNotMatch(out.split('@@REFUSED')[0], /5001\/tcp@/, 'AppCrane\'s own port is not an uncovered listener');
  const r = block(out, 'REFUSED');
  assert.match(r, /^-P INPUT ACCEPT\n-P INPUT ACCEPT$/m);
  assert.match(r, /^input_mode=refused$/m);
  assert.match(r, /^uncovered=8080\/tcp@0\.0\.0\.0\(nc\)$/m);

  assert.equal(allowed, 0, out);
  assert.match(out, /names AppCrane's own port 5001\/tcp .* ignored/);
  assert.match(out, /entries ignored \(want port\/tcp or port\/udp\): bogus 022\/tcp 08\/tcp 0\/udp$/m);
  const a = block(out, 'ALLOWED');
  assert.match(a, /^-P INPUT DROP\n-P INPUT DROP$/m);
  assert.match(a, /^allow=22\/tcp 80\/tcp 443\/tcp 443\/udp 8080\/tcp$/m);
  assert.match(block(out, 'SAVE'), /^-A APPCRANE-INPUT -p tcp -m tcp --dport 8080 -j ACCEPT$/m);
  assert5001Closed(block(out, 'SAVE'));
});

test('no ufw: /etc/appcrane/host-network.conf is used when root-only, ignored when others can write it; APPCRANE_INPUT_FORCE=1 overrides the refusal', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    nc -lk 0.0.0.0 9090 >/dev/null 2>&1 &
    sleep 0.5
    mkdir -p /etc/appcrane; printf 'APPCRANE_INPUT_ALLOW="9090/tcp"\\n' > /etc/appcrane/host-network.conf
    chmod 666 /etc/appcrane/host-network.conf; hh
    echo @@LOOSE; iptables -S INPUT | head -1
    chmod 600 /etc/appcrane/host-network.conf; hh
    echo @@STRICT; iptables -S INPUT | head -1; iptables -S APPCRANE-INPUT | grep 9090
    printf 'APPCRANE_INPUT_FORCE=1\\n' > /etc/appcrane/host-network.conf; iptables -P INPUT ACCEPT; hh
    echo @@FORCED; iptables -S INPUT | head -1; iptables -S APPCRANE-INPUT | grep -c 9090 || true
  `);
  const [loose, strict, forced] = exits(out);
  assert.equal(loose, 3, out);
  assert.match(out, /host-network\.conf is not root-owned or is writable by others — ignored/);
  assert.match(block(out, 'LOOSE'), /^-P INPUT ACCEPT$/m);
  assert.equal(strict, 0, out);
  assert.match(block(out, 'STRICT'), /^-P INPUT DROP\n-A APPCRANE-INPUT -p tcp -m tcp --dport 9090 -j ACCEPT$/m);
  assert.equal(forced, 0, out);
  assert.match(out, /APPCRANE_INPUT_FORCE=1 — setting DROP although these listen uncovered: 9090\/tcp/);
  assert.match(block(out, 'FORCED'), /^-P INPUT DROP\n0$/m);
});

test('no default route: refuses (exit non-zero), leaves every chain as it was', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    ip route del default; ip -6 route del default 2>/dev/null || true
    echo @@BEFORE; ${SAVE}
    hh
    echo @@AFTER; ${SAVE}
    echo @@STATE; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [3], out);
  assert.match(out, /no default route, so the public interface is unknown/);
  assert.match(out, /failed sections: network/);
  assert.equal(block(out, 'AFTER'), block(out, 'BEFORE'));
  assert.match(block(out, 'STATE'), /^result=failed$/m);
});

test('the interim hand-installed DOCKER-USER policy is replaced and its unit and script removed', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    mkdir -p /etc/systemd/system /usr/local/sbin
    printf '[Service]\\nType=oneshot\\nExecStart=/usr/local/sbin/appcrane-docker-user.sh\\n' > /etc/systemd/system/appcrane-docker-user.service
    printf '#!/bin/sh\\niptables -F DOCKER-USER\\n' > /usr/local/sbin/appcrane-docker-user.sh
    iptables -N DOCKER-USER
    iptables -A DOCKER-USER -i eth0 -p udp --dport 31001 -j RETURN
    iptables -A DOCKER-USER -i eth0 -p udp --dport 31820 -j RETURN
    iptables -A DOCKER-USER -i eth0 -j DROP
    hh
    echo @@LS; ls /etc/systemd/system/appcrane-docker-user.service /usr/local/sbin/appcrane-docker-user.sh 2>&1 || true
    echo @@V4; iptables -S DOCKER-USER
    echo @@PUB; iptables -S APPCRANE-PUBLISH
    echo @@STATE; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0], out);
  assert.equal((block(out, 'LS').match(/No such file/g) || []).length, 2, block(out, 'LS'));
  assert.equal(block(out, 'V4').trim(), SKELETON('169.254.169.254/32'));
  assert.equal(block(out, 'PUB').trim(), '-N APPCRANE-PUBLISH', 'seeded from nothing');
  assert.match(out, /removed the interim .* AppCrane refills it with the ports it publishes within seconds/);
  assert.match(block(out, 'STATE'), /^interim_removed=yes$/m);
});

test('packets: from another host on the public interface, 22 and an allowed port answer and AppCrane\'s 5001 stops answering; loopback and a second (private) interface still reach 5001', { skip: skipNet(R) }, () => {
  const id = randomBytes(4).toString('hex');
  const net = `appcrane-test-hn-${id}`;
  const net2 = `appcrane-test-hn-priv-${id}`;
  const box = `appcrane-test-hn-box-${id}`;
  const dk = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  const probe = (n = net) => dk('run', '--rm', '--network', n, netImages[R], 'bash', '-c',
    `for p in 22 7000 5001; do nc -z -w 2 ${box} $p && echo "$p open" || echo "$p closed"; done`);
  try {
    dk('network', 'create', net);
    dk('network', 'create', net2);
    dk('run', '-d', '--privileged', '--network', net, '--name', box, '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, netImages[R], 'bash', '-c',
      'mkdir -p /opt/appcrane/scripts /opt/appcrane/data && cp /src/host-hardening.sh /opt/appcrane/scripts/ && printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env; for p in 22 7000 5001; do nc -lk 0.0.0.0 $p >/dev/null 2>&1 & done; sleep 300');
    dk('network', 'connect', net2, box);
    dk('exec', box, 'bash', '-c', 'for i in $(seq 50); do [ "$(ss -ltnH | wc -l)" -ge 3 ] && exit 0; sleep 0.1; done; exit 1');
    assert.equal(probe(), '22 open\n7000 open\n5001 open\n', 'before: everything answers');
    const log = dk('exec', '-e', 'APPCRANE_INPUT_ALLOW=7000/tcp', '-e', 'APPCRANE_RESERVE_MIN_FREE_GB=100000', box, 'bash', '-c', 'bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"');
    assert.deepEqual(exits(log), [0], log);
    assert.equal(probe(), '22 open\n7000 open\n5001 closed\n');
    assert.equal(probe(net2), '22 open\n7000 open\n5001 open\n', 'AppCrane\'s port stays reachable on a non-public interface (tailscale, VPN, private NIC)');
    assert.equal(dk('exec', box, 'bash', '-c', 'nc -z -w 2 127.0.0.1 5001 && echo open || echo closed'), 'open\n', 'Caddy reaches AppCrane on loopback');
  } finally {
    try { dk('rm', '-f', box); } catch (_) { /* not created */ }
    try { dk('network', 'rm', net); } catch (_) { /* not created */ }
    try { dk('network', 'rm', net2); } catch (_) { /* not created */ }
  }
});
