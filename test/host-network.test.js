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
  '-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB',
  '-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH',
  '-A DOCKER-USER -i eth0 -j DROP',
  '-A DOCKER-USER -j RETURN',
].join('\n');
const PUBLISHED = '-A APPCRANE-PUBLISH -p udp -m conntrack --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
const SAVE = 'for t in iptables ip6tables; do $t-save -t filter | grep -v "^#" | sed "s/ \\[[0-9]*:[0-9]*\\]$//"; done';

// APPCRANE-INPUT holds AppCrane's own surfaces only: its port accepted from
// the container bridges, new connections to its port and the managed database
// ports dropped on the public interface, new connections to the database ports
// dropped from docker0, nothing else.
const chain = (ext = 'eth0', dbs = ['45432', '43306', '47017', '46379:46878']) => [
  '-A APPCRANE-INPUT -i docker0 -p tcp -m tcp --dport 5001 -j ACCEPT',
  '-A APPCRANE-INPUT -i br-+ -p tcp -m tcp --dport 5001 -j ACCEPT',
  ...['5001', ...dbs].map((p) => `-A APPCRANE-INPUT -i ${ext} -p tcp -m tcp --dport ${p} -m conntrack --ctstate NEW -j DROP`),
  `-A APPCRANE-INPUT -i docker0 -p tcp -m multiport --dports ${dbs.join(',')} -m conntrack --ctstate NEW -j DROP`,
  '-A APPCRANE-INPUT -j RETURN',
];
// Both families: the policy as <policy>, one jump, and exactly chain().
function assertInput(save, policy = 'ACCEPT', dbs) {
  const fams = save.split('*filter').slice(1);
  assert.equal(fams.length, 2, save);
  for (const fam of fams) {
    const lines = fam.split('\n');
    assert.ok(lines.includes(`:INPUT ${policy}`), `INPUT policy is not ${policy}: ${fam}`);
    assert.deepEqual(lines.filter((l) => l.startsWith('-A INPUT')), ['-A INPUT -j APPCRANE-INPUT']);
    assert.deepEqual(lines.filter((l) => l.startsWith('-A APPCRANE-INPUT')), chain('eth0', dbs));
  }
}

for (const rel of RELEASES) {
  test(`ubuntu ${rel}: DOCKER-USER skeleton in both families, APPCRANE-PUBLISH kept, idempotent, INPUT policy untouched, APPCRANE-INPUT drops only AppCrane's ports on eth0, boot script re-applies it`, { skip: skipNet(rel) }, () => {
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
    assertInput(save);

    const state = block(out, 'STATE');
    assert.match(state, /^result=ok$/m);
    assert.match(state, /^ext=eth0$/m);
    assert.match(state, /^input_mode=appcrane-input$/m);
    assert.match(state, /^input_policy=ACCEPT$/m);
    assert.match(state, /^db_ports=45432 43306 47017 46379:46878$/m);
    const unit = block(out, 'UNIT');
    for (const l of ['After=docker.service network-online.target', 'PartOf=docker.service', 'Type=oneshot', 'RemainAfterExit=yes',
      'ExecStart=/usr/local/sbin/appcrane-host-network.sh', 'WantedBy=docker.service multi-user.target']) assert.ok(unit.includes(l), l);
    assert.equal(block(out, 'BOOTMODE').trim(), 'root:root 755');

    assert.doesNotMatch(block(out, 'WIPED'), /APPCRANE|DOCKER-USER/);
    assert.match(out, /^@@BOOTEXIT 0$/m, block(out, 'BOOT'));
    // After a reboot the server-owned chain starts empty; everything else is back.
    assert.equal(block(out, 'SAVE3'), save.replace(`${PUBLISHED}\n`, ''));
  });
}

const R = '24.04';

test('no ufw: other software is not AppCrane\'s business: a TCP 8080 and a UDP 41641 listener, an admin DROP policy and admin rules are left alone, exit 0; the retired knobs only warn; .env DB port overrides', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    nc -lk 0.0.0.0 8080 >/dev/null 2>&1 &
    nc -lku 0.0.0.0 41641 >/dev/null 2>&1 &
    sleep 0.5
    hh
    echo @@FIRST; ${SAVE}
    echo @@STATE1; cat /var/lib/appcrane/host-network.state
    iptables -P INPUT DROP; ip6tables -P INPUT DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT; iptables -A INPUT -s 10.9.0.0/16 -j DROP
    mkdir -p /etc/appcrane; printf 'APPCRANE_INPUT_FORCE=1\\n' > /etc/appcrane/host-network.conf; chmod 600 /etc/appcrane/host-network.conf
    APPCRANE_INPUT_ALLOW=8080/tcp hh
    echo @@ADMIN; ${SAVE}
    printf "DATA_DIR=/opt/appcrane/data\\nMANAGED_DB_POSTGRES_PORT=55432\\nMANAGED_DB_MARIADB_PORT=22\\nMANAGED_DB_MONGO_PORT=0\\nMANAGED_DB_REDIS_PORT_MIN='50000'\\n" > /opt/appcrane/.env
    hh
    echo @@ENV; iptables -S APPCRANE-INPUT; grep '^db_ports=' /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0, 0, 0], out);
  assert.doesNotMatch(out, /non-loopback addresses|NOT set to DROP/);
  assertInput(block(out, 'FIRST'));
  const s1 = block(out, 'STATE1');
  assert.match(s1, /^result=ok$/m);
  assert.match(s1, /^input_policy=ACCEPT$/m);
  assert.match(s1, /^input_policy_set=no$/m);

  const admin = block(out, 'ADMIN');
  assertInput(admin.replace(/^-A INPUT -(p tcp -m tcp --dport 22 -j ACCEPT|s 10\.9\.0\.0\/16 -j DROP)\n/gm, ''), 'DROP');
  assert.match(admin, /^-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -s 10\.9\.0\.0\/16 -j DROP$/m, 'admin rules kept, in order');
  assert.match(out, /APPCRANE_INPUT_ALLOW no longer has an effect/);
  assert.match(out, /APPCRANE_INPUT_FORCE no longer has an effect/);
  assert.doesNotMatch(admin, /--dport 8080/);

  assert.match(out, /MANAGED_DB_MARIADB_PORT=22 in \/opt\/appcrane\/\.env is below 1024.* not dropped on the public interface/);
  const env = block(out, 'ENV');
  assert.match(env, /^db_ports=55432 47017 50000:50499$/m);
  assert.deepEqual(env.split('\n').filter((l) => l.startsWith('-A APPCRANE-INPUT')), chain('eth0', ['55432', '47017', '50000:50499']));
});

test('upgrade from v2.145.0: an INPUT DROP it set itself is put back to ACCEPT (both families) and recorded; one set by the admin after that stays', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    mkdir -p /var/lib/appcrane
    printf 'result=ok\\next=eth0\\ninput_mode=appcrane-input\\ninput_policy=DROP\\nallow=22/tcp 80/tcp 443/tcp 443/udp\\napp_port=5001\\n' > /var/lib/appcrane/host-network.state
    iptables -P INPUT DROP; ip6tables -P INPUT DROP
    hh
    echo @@AFTER; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1; grep -E '^input_policy' /var/lib/appcrane/host-network.state
    iptables -P INPUT DROP; ip6tables -P INPUT DROP
    hh; hh
    echo @@AGAIN; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1; grep '^input_policy=' /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0, 0, 0], out);
  assert.match(out, /INPUT policy set back to ACCEPT \(iptables ip6tables\) — v2\.145\.0 had set DROP/);
  assert.equal(block(out, 'AFTER'), '-P INPUT ACCEPT\n-P INPUT ACCEPT\ninput_policy=ACCEPT\ninput_policy_set=no\ninput_policy_restored=iptables ip6tables\n');
  assert.equal(block(out, 'AGAIN'), '-P INPUT DROP\n-P INPUT DROP\ninput_policy=DROP\n', 'a DROP set after this version ran is the admin\'s, also once its state records DROP');
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

test('packets: from another host on the public interface, 22, a non-AppCrane TCP port and a UDP 41641 listener answer while 5001 and 45432 stop; loopback and a second (private) interface still reach both', { skip: skipNet(R) }, () => {
  const id = randomBytes(4).toString('hex');
  const net = `appcrane-test-hn-${id}`;
  const net2 = `appcrane-test-hn-priv-${id}`;
  const box = `appcrane-test-hn-box-${id}`;
  const dk = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  const probe = (n = net) => dk('run', '--rm', '--network', n, netImages[R], 'bash', '-c',
    `for p in 22 7000 5001 45432; do nc -z -w 2 ${box} $p && echo "$p open" || echo "$p closed"; done; echo "udp-${n}" | nc -u -w 1 ${box} 41641`);
  const udp = () => dk('exec', box, 'cat', '/tmp/udp.log');
  try {
    dk('network', 'create', net);
    dk('network', 'create', net2);
    dk('run', '-d', '--privileged', '--network', net, '--name', box, '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, netImages[R], 'bash', '-c',
      'mkdir -p /opt/appcrane/scripts /opt/appcrane/data && cp /src/host-hardening.sh /opt/appcrane/scripts/ && printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env; for p in 22 7000 5001 45432; do nc -lk 0.0.0.0 $p >/dev/null 2>&1 & done; nc -lku 0.0.0.0 41641 > /tmp/udp.log 2>&1 & sleep 300');
    dk('network', 'connect', net2, box);
    dk('exec', box, 'bash', '-c', 'for i in $(seq 50); do [ "$(ss -ltnH | wc -l)" -ge 4 ] && exit 0; sleep 0.1; done; exit 1');
    assert.equal(probe(), '22 open\n7000 open\n5001 open\n45432 open\n', 'before: everything answers');
    const log = dk('exec', '-e', 'APPCRANE_RESERVE_MIN_FREE_GB=100000', box, 'bash', '-c', 'bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"');
    assert.deepEqual(exits(log), [0], log);
    assert.equal(probe(), '22 open\n7000 open\n5001 closed\n45432 closed\n');
    assert.match(udp(), new RegExp(`udp-${net}\n`), 'a UDP listener that is not AppCrane\'s (Tailscale\'s 41641) still receives from the public interface');
    assert.equal(probe(net2).split('\n').slice(0, 4).join('\n'), '22 open\n7000 open\n5001 open\n45432 open', 'AppCrane\'s ports are dropped on the public interface only');
    assert.equal(dk('exec', box, 'bash', '-c', 'nc -z -w 2 127.0.0.1 5001 && echo open || echo closed'), 'open\n', 'Caddy reaches AppCrane on loopback');
  } finally {
    try { dk('rm', '-f', box); } catch (_) { /* not created */ }
    try { dk('network', 'rm', net); } catch (_) { /* not created */ }
    try { dk('network', 'rm', net2); } catch (_) { /* not created */ }
  }
});
