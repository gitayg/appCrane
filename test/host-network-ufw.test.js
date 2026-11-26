import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The network section of scripts/host-hardening.sh on a host where ufw is
// active, run for real in privileged Ubuntu 24.04 containers.
//
// Production evidence (a ufw host): a global "ufw deny 5001" plus ufw's default
// deny incoming dropped 31,805 connections from containers to AppCrane at
// host.docker.internal:5001; managed databases kept working because they go
// through Docker's DNAT (FORWARD), not INPUT. And Tailscale's UDP listener made
// v2.145.0 refuse to finish: AppCrane must leave the rest of the server alone.

const { buildNetImages, netImages, skipNet, runNet, block, exits } = await import('./host-hardening-harness.js');
const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'host-hardening.sh');
buildNetImages();
const R = '24.04';

// docker stand-in: answers `docker network inspect ... <name>` from
// /tmp/net-<name> ("<id> <bridge name option>"), fails for anything else.
const FAKE_DOCKER = `cat > /usr/local/bin/docker <<'S'
#!/bin/sh
[ "$1 $2" = "network inspect" ] || exit 1
for a; do n=$a; done
[ -f /tmp/net-$n ] || { echo "Error: No such network: $n" >&2; exit 1; }
cat /tmp/net-$n
S
chmod 755 /usr/local/bin/docker
echo "6370c886f7d06f1a6403185a5b220be793c9606f70f99d1117cdd7769269f576 docker0" > /tmp/net-bridge
echo "a2d101c04cff403b6f1365595fa0fb973d9bd047d14c5f3550a54fab8b8be766 <no value>" > /tmp/net-appcrane-apps`;

const EXT = ['5001', '45432/tcp', '43306/tcp', '47017/tcp', '46379:46878/tcp'];
const added = (out, name) => block(out, name).split('\n').filter((l) => l.startsWith('ufw '));
// Per family, the numbered rules in order: [action, rest].
function families(numbered) {
  const fam = { 4: [], 6: [] };
  for (const l of numbered.split('\n')) {
    const m = l.match(/^\[ *\d+\] (.*?) +(ALLOW|DENY|REJECT|LIMIT) IN /);
    if (m) fam[/\(v6\)/.test(l) ? 6 : 4].push([m[2], l]);
  }
  return fam;
}
function assertBridgesFirst(numbered, bridges) {
  for (const [f, rules] of Object.entries(families(numbered))) {
    const firstDeny = rules.findIndex(([a, l]) => a !== 'ALLOW' && !/# appcrane-ext$/.test(l.trimEnd()));
    for (const b of bridges) {
      const i = rules.findIndex(([a, l]) => a === 'ALLOW' && new RegExp(`^\\[ *\\d+\\] 5001/tcp${f === '6' ? ' \\(v6\\)' : ''} on ${b} `).test(l) && /# appcrane-bridge$/.test(l.trimEnd()));
      assert.ok(i >= 0, `v${f}: no allow for ${b}\n${numbered}`);
      if (firstDeny >= 0) assert.ok(i < firstDeny, `v${f}: the allow for ${b} is behind a deny\n${numbered}`);
    }
  }
}

test('ufw: only scoped rules added (5001 and the DB ports denied on eth0, 5001 allowed on docker0 and the appcrane-apps bridge ahead of every deny); the global deny 5001 replaced in both families; default policy, INPUT policy and every other rule untouched; idempotent; a recreated network, a later admin deny and an unreachable Docker', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    ${FAKE_DOCKER}
    ufw allow proto tcp from 10.0.0.0/8 to any port 22 >/dev/null
    ufw allow 41641/udp >/dev/null
    ufw deny 5001 >/dev/null
    ufw --force enable >/dev/null
    echo @@BEFORE; ufw show added
    echo @@POLICY0; ufw status verbose | grep '^Default:'; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1
    hh
    echo @@ADDED1; ufw show added
    echo @@NUM1; ufw status numbered
    hh
    echo @@ADDED2; ufw show added
    echo @@POLICY2; ufw status verbose | grep '^Default:'; iptables -S INPUT | head -1; ip6tables -S INPUT | head -1
    echo @@CHAIN; { iptables-save; ip6tables-save; } | grep -c APPCRANE-INPUT || true
    echo @@STATE; cat /var/lib/appcrane/host-network.state
    echo "3725c188229b5e9a0e4d1f1b6b6a3e8c3d6f0a4b5c6d7e8f9a0b1c2d3e4f5a6b <no value>" > /tmp/net-appcrane-apps
    hh
    echo @@ADDED3; ufw show added
    echo @@NUM3; ufw status numbered
    ufw prepend deny from 172.16.0.0/12 >/dev/null
    hh
    echo @@NUM4; ufw status numbered
    rm /tmp/net-bridge
    hh
    echo @@ADDED5; ufw show added
  `);
  assert.deepEqual(exits(out), [0, 0, 0, 0, 0], out);
  const before = added(out, 'BEFORE');
  const a1 = added(out, 'ADDED1');
  assert.deepEqual(a1.filter((l) => before.includes(l)), before.filter((l) => l !== 'ufw deny 5001'), 'other rules kept, in order');
  assert.ok(!a1.includes('ufw deny 5001'), 'the global deny 5001 is gone');
  const bridges = ['docker0', 'br-a2d101c04cff'];
  assert.deepEqual(a1.filter((l) => !before.includes(l)).sort(), [
    ...bridges.map((b) => `ufw allow in on ${b} to any port 5001 proto tcp comment 'appcrane-bridge'`),
    ...EXT.map((p) => `ufw deny in on eth0 to any port ${p.replace('/tcp', ' proto tcp')} comment 'appcrane-ext'`),
  ].sort());
  assert.ok(!a1.some((l) => /^ufw allow (22|80|443)\//.test(l)), 'no 22, 80 or 443 allow added');
  const n1 = block(out, 'NUM1');
  assert.doesNotMatch(n1, /^\[ *\d+\] 5001( \(v6\))? +DENY IN/m, 'no global deny 5001 in either family');
  assert.match(n1, /^\[ *\d+\] 5001 \(v6\) on eth0 +DENY IN/m);
  assertBridgesFirst(n1, bridges);
  assert.match(out, /ufw deny 5001 \(every interface, so containers could not reach AppCrane\) replaced by the deny on eth0/);

  assert.deepEqual(added(out, 'ADDED2'), a1, 'a second run changes nothing');
  assert.equal(block(out, 'POLICY2'), block(out, 'POLICY0'), 'ufw default policy and the INPUT policies untouched');
  assert.equal(block(out, 'CHAIN').trim(), '0', 'no APPCRANE-INPUT in ufw mode');
  const st = block(out, 'STATE');
  assert.match(st, /^input_mode=ufw$/m);
  assert.match(st, /^bridges=docker0 br-a2d101c04cff$/m);
  assert.match(st, /^db_ports=45432 43306 47017 46379:46878$/m);

  const a3 = added(out, 'ADDED3');
  assert.ok(!a3.some((l) => l.includes('br-a2d101c04cff')), 'the stale bridge rule is deleted');
  assert.match(out, /ufw rule no longer AppCrane's deleted: allow in on br-a2d101c04cff to any port 5001 proto tcp/);
  assertBridgesFirst(block(out, 'NUM3'), ['docker0', 'br-3725c188229b']);
  assert.equal(a3.length, a1.length);

  const n4 = block(out, 'NUM4');
  assert.match(n4, /Anywhere +DENY IN +172\.16\.0\.0\/12/);
  assertBridgesFirst(n4, ['docker0', 'br-3725c188229b']);

  assert.match(out, /Docker could not be asked for its bridges — ufw bridge allows left as they are/);
  assert.equal(added(out, 'ADDED5').filter((l) => /appcrane-bridge/.test(l)).length, 2, 'Docker down: the bridge allows are kept');
});

test('ufw packets: with a global deny 5001 a container on the appcrane-apps bridge cannot reach AppCrane (the production failure); after Apply it can, while 5001 stays closed from the public interface and an admin-allowed UDP 41641 still answers', { skip: skipNet(R) }, () => {
  const id = randomBytes(4).toString('hex');
  const net = `appcrane-test-hnu-${id}`;
  const box = `appcrane-test-hnu-box-${id}`;
  const dk = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  const fromBridge = () => dk('exec', box, 'bash', '-c', 'ip netns exec c1 nc -z -w 2 172.30.0.1 5001 && echo open || echo closed');
  const fromExt = () => dk('run', '--rm', '--network', net, netImages[R], 'bash', '-c',
    `nc -z -w 2 ${box} 5001 && echo "5001 open" || echo "5001 closed"; echo "udp-ext" | nc -u -w 1 ${box} 41641`);
  try {
    dk('network', 'create', net);
    dk('run', '-d', '--privileged', '--network', net, '--name', box, '-v', `${SCRIPT}:/src/host-hardening.sh:ro`, netImages[R], 'bash', '-c',
      'mkdir -p /opt/appcrane/scripts /opt/appcrane/data && cp /src/host-hardening.sh /opt/appcrane/scripts/ && printf "DATA_DIR=/opt/appcrane/data\\n" > /opt/appcrane/.env; nc -lk 0.0.0.0 5001 >/dev/null 2>&1 & nc -lku 0.0.0.0 41641 > /tmp/udp.log 2>&1 & sleep 300');
    dk('exec', box, 'bash', '-c', `${FAKE_DOCKER}
      ip link add br-a2d101c04cff type bridge && ip addr add 172.30.0.1/24 dev br-a2d101c04cff && ip link set br-a2d101c04cff up
      ip netns add c1 && ip link add veth-h type veth peer name veth-c && ip link set veth-c netns c1
      ip link set veth-h master br-a2d101c04cff && ip link set veth-h up
      ip netns exec c1 ip addr add 172.30.0.2/24 dev veth-c && ip netns exec c1 ip link set veth-c up && ip netns exec c1 ip link set lo up
      ufw allow 41641/udp >/dev/null; ufw deny 5001 >/dev/null; ufw --force enable >/dev/null`);
    assert.equal(fromBridge(), 'closed\n', 'reproduced: global deny 5001 + default deny incoming cut containers off');
    const log = dk('exec', '-e', 'APPCRANE_RESERVE_MIN_FREE_GB=100000', box, 'bash', '-c', 'bash /opt/appcrane/scripts/host-hardening.sh 2>&1; echo "@@EXIT $?"');
    assert.deepEqual(exits(log), [0], log);
    assert.equal(fromBridge(), 'open\n', 'a container on the appcrane-apps bridge reaches AppCrane');
    assert.equal(fromExt(), '5001 closed\n');
    assert.match(dk('exec', box, 'cat', '/tmp/udp.log'), /udp-ext\n/, 'the admin-allowed UDP listener still receives');
  } finally {
    try { dk('rm', '-f', box); } catch (_) { /* not created */ }
    try { dk('network', 'rm', net); } catch (_) { /* not created */ }
  }
});
