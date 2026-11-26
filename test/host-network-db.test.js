import { test } from 'node:test';
import assert from 'node:assert/strict';

// The APPCRANE-DB side of the network section, run for real in privileged
// Ubuntu containers: host-hardening.sh jumping from DOCKER-USER to APPCRANE-DB
// for connections DNATed to the default bridge (where the managed database
// servers run), creating that chain empty and never flushing it, and
// scripts/appcrane-db-chain.sh, the root-owned helper a non-root AppCrane runs
// through sudo to fill it.

const { buildNetImages, skipNet, runNet, block, exits } = await import('./host-hardening-harness.js');
buildNetImages();
const R = '24.04';
const P = '/opt/appcrane/scripts/appcrane-db-chain.sh';
const JUMP = '-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB';
const SKELETON = (imds) => [
  '-N DOCKER-USER',
  '-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN',
  `-A DOCKER-USER -d ${imds} -i docker0 -j DROP`,
  `-A DOCKER-USER -d ${imds} -i br-+ -j DROP`,
  JUMP,
  '-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH',
  '-A DOCKER-USER -i eth0 -j DROP',
  '-A DOCKER-USER -j RETURN',
].join('\n');
const ALLOW = (src, port) => `-A APPCRANE-DB -s ${src} -p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL -j RETURN`;
const DROP = (port) => `-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL -j DROP`;
const LOG = (port) => `-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL\n-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL -m limit --limit 10/min --limit-burst 10 -j LOG --log-prefix "APPCRANE-DB-WOULD-DROP "`;

test('skeleton: DOCKER-USER jumps to APPCRANE-DB after the replies and metadata drops and before APPCRANE-PUBLISH, in both families, on every run; APPCRANE-DB created empty, never flushed; boot script recreates it; db_chain recorded and kept on a failed run', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    hh
    echo @@V1; iptables -S DOCKER-USER; ip6tables -S DOCKER-USER
    echo @@DB1; iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB
    echo @@S1; cat /var/lib/appcrane/host-network.state
    iptables -A APPCRANE-DB -s 10.0.0.9/32 -j RETURN; ip6tables -A APPCRANE-DB -s fd00::9/128 -j RETURN
    hh
    echo @@V2; iptables -S DOCKER-USER; ip6tables -S DOCKER-USER
    echo @@DB2; iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB
    for t in iptables ip6tables; do $t -F DOCKER-USER; $t -F APPCRANE-DB; $t -X APPCRANE-DB; done
    /usr/local/sbin/appcrane-host-network.sh >/dev/null 2>&1; echo "@@BOOT $?"
    echo @@V3; iptables -S DOCKER-USER; ip6tables -S DOCKER-USER
    echo @@DB3; iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB
    printf "DATA_DIR=/opt/appcrane/data\\nPORT=22\\n" > /opt/appcrane/.env
    hh
    echo @@S4; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0, 0, 3], out);
  const both = `${SKELETON('169.254.169.254/32')}\n${SKELETON('fd00:ec2::254/128')}`;
  assert.equal(block(out, 'V1').trim(), both);
  assert.equal(block(out, 'DB1').trim(), '-N APPCRANE-DB\n-N APPCRANE-DB', 'created empty in both families');
  assert.match(block(out, 'S1'), /^db_chain=yes$/m);
  assert.equal(block(out, 'V2').trim(), both, 'a second run leaves exactly one jump in place');
  assert.equal(block(out, 'DB2').trim(), '-N APPCRANE-DB\n-A APPCRANE-DB -s 10.0.0.9/32 -j RETURN\n-N APPCRANE-DB\n-A APPCRANE-DB -s fd00::9/128 -j RETURN', 'the server-owned chain is never flushed');
  assert.match(out, /^@@BOOT 0$/m);
  assert.equal(block(out, 'V3').trim(), both, 'the boot script re-applies the jump');
  assert.equal(block(out, 'DB3').trim(), '-N APPCRANE-DB\n-N APPCRANE-DB', 'the boot script recreates a missing chain');
  const s4 = block(out, 'S4');
  assert.match(s4, /^result=failed$/m);
  assert.match(s4, /^db_chain=yes$/m, 'a failed run keeps the last decision');
});

test('skeleton: with the interim unit kept, DOCKER-USER is left alone (no jump) and db_chain=no', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    cp "$(readlink -f "$(command -v nc)")" /usr/local/bin/docker-proxy
    docker-proxy -lk 0.0.0.0 38080 >/dev/null 2>&1 &
    for i in $(seq 50); do ss -H -ltnp | grep -q docker-proxy && break; sleep 0.1; done
    mkdir -p /etc/systemd/system /usr/local/sbin
    printf '[Service]\\nType=oneshot\\nExecStart=/usr/local/sbin/appcrane-docker-user.sh\\n' > /etc/systemd/system/appcrane-docker-user.service
    printf '#!/bin/sh\\n' > /usr/local/sbin/appcrane-docker-user.sh
    iptables -N DOCKER-USER; iptables -A DOCKER-USER -i eth0 -j DROP
    hh
    echo @@V; iptables -S DOCKER-USER
    echo @@S; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0], out);
  assert.equal(block(out, 'V').trim(), '-N DOCKER-USER\n-A DOCKER-USER -i eth0 -j DROP');
  assert.match(block(out, 'S'), /^docker_user=interim$/m);
  assert.match(block(out, 'S'), /^db_chain=no$/m);
});

test('appcrane-db-chain.sh: exact rules per family (IPv4 allows to iptables, IPv6 allows to ip6tables, DROPs to both), port order kept, duplicates dropped, silent; no args empties; other chains untouched; ip6tables unusable is skipped', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    iptables -N OTHER; iptables -A OTHER -p tcp --dport 1 -j ACCEPT
    iptables -N APPCRANE-DB; iptables -A APPCRANE-DB -p tcp --dport 2 -j DROP
    echo @@OK; ${P} allow:45432:172.30.0.2 allow:45432:FD00:abc::2 allow:43306:172.30.0.3 close:47017 allow:45432:172.30.0.2 close:45432 allow:45432:172.30.0.4 2>&1; echo "rc=$?"
    echo @@V4; iptables -S APPCRANE-DB
    echo @@V6; ip6tables -S APPCRANE-DB
    echo @@EMPTY; ${P} 2>&1; echo "rc=$?"; iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB
    echo @@OTHER; iptables -S OTHER
    mkdir /tmp/v6; mv /usr/sbin/ip6tables /usr/sbin/ip6tables-restore /tmp/v6/
    echo @@NO6; ${P} close:45432 allow:45432:fd00::5 2>&1; echo "rc=$?"; iptables -S APPCRANE-DB
    echo @@END
  `);
  assert.equal(block(out, 'OK'), 'rc=0\n', 'prints nothing on success');
  assert.equal(block(out, 'V4').trim(), [
    '-N APPCRANE-DB',
    ALLOW('172.30.0.2/32', 45432), ALLOW('172.30.0.4/32', 45432), DROP(45432),
    ALLOW('172.30.0.3/32', 43306), DROP(43306),
    DROP(47017),
  ].join('\n'), 'old rule gone, IPv4 allows only, every named port dropped after its allows');
  assert.equal(block(out, 'V6').trim(), [
    '-N APPCRANE-DB',
    ALLOW('fd00:abc::2/128', 45432), DROP(45432),
    DROP(43306),
    DROP(47017),
  ].join('\n'), 'created in IPv6 with IPv6 allows only and the same DROPs');
  assert.equal(block(out, 'EMPTY').trim(), 'rc=0\n-N APPCRANE-DB\n-N APPCRANE-DB');
  assert.equal(block(out, 'OTHER').trim(), '-N OTHER\n-A OTHER -p tcp -m tcp --dport 1 -j ACCEPT');
  assert.equal(block(out, 'NO6').trim(), `rc=0\n-N APPCRANE-DB\n${DROP(45432)}`);
});

test('appcrane-db-chain.sh observe mode: log:<port> writes, after that port\'s allows, a rate-limited LOG instead of the DROP, in both families; a port with both close and log exits 2 and changes nothing, in either order', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    echo @@OK; ${P} allow:45432:172.30.0.2 log:45432 allow:45432:fd00::2 close:43306 allow:43306:172.30.0.3 log:47017 log:45432 allow:46379:172.30.0.4 2>&1; echo "rc=$?"
    echo @@V4; iptables -S APPCRANE-DB
    echo @@V6; ip6tables -S APPCRANE-DB
    SNAP() { iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB; }
    before="$(SNAP)"
    echo @@BOTH
    ${P} close:45432 allow:45432:172.30.0.9 log:45432 2>&1; echo "rc=$? $([ "$(SNAP)" = "$before" ] && echo same || echo CHANGED)"
    ${P} log:45432 close:45432 2>&1; echo "rc=$? $([ "$(SNAP)" = "$before" ] && echo same || echo CHANGED)"
    echo @@END
  `);
  assert.equal(block(out, 'OK'), 'rc=0\n', 'prints nothing on success');
  assert.equal(block(out, 'V4').trim(), [
    '-N APPCRANE-DB',
    ALLOW('172.30.0.2/32', 45432), LOG(45432),
    ALLOW('172.30.0.3/32', 43306), DROP(43306),
    LOG(47017),
    ALLOW('172.30.0.4/32', 46379), DROP(46379),
  ].join('\n'), 'logged ports end in LOG, closed and allow-only ports in DROP');
  assert.equal(block(out, 'V6').trim(), [
    '-N APPCRANE-DB',
    ALLOW('fd00::2/128', 45432), LOG(45432),
    DROP(43306),
    LOG(47017),
    DROP(46379),
  ].join('\n'));
  assert.deepEqual(block(out, 'BOTH').trim().split('\n'), [
    'appcrane-db-chain: argument 3 names port 45432, which is already close: a port has close or log, not both', 'rc=2 same',
    'appcrane-db-chain: argument 2 names port 45432, which is already log: a port has close or log, not both', 'rc=2 same',
  ]);
});

test('appcrane-db-chain.sh: every malformed argument exits 2 and leaves both chains as they were; 2048 arguments accepted, 2049 refused', { skip: skipNet(R) }, () => {
  const bad = [
    'allow:0:172.30.0.2', 'allow:045432:172.30.0.2', 'allow:65536:172.30.0.2', 'allow:99999:172.30.0.2', 'allow::172.30.0.2',
    'allow:45432:256.1.1.1', 'allow:45432:01.2.3.4', 'allow:45432:1.2.3', 'allow:45432:1.2.3.4.5', 'allow:45432:1.2.3.4/32',
    'allow:45432:1.2.3.4;id', 'allow:45432: 1.2.3.4', 'allow:45432:1.2.3.4 ', 'allow:45432:0x1.2.3.4', 'allow:45432:',
    'allow:45432', 'allow:45432:fe80::1%eth0', 'allow:45432:::ffff:1.2.3.4', 'allow:45432:1:2:3:4:5:6:7:8:9', 'allow:45432:1:2:3:4:5:6:7',
    'allow:45432:1::2::3', 'allow:45432:12345::1', 'allow:45432:g::1', 'allow:45432::1:2', 'allow:45432:1:2:3:4:5:6:7:',
    'allow:45432:1:::2', 'allow:45432:fd00::/64', 'close:', 'close:0', 'close:045432', 'close:65536', 'close:45432:1.2.3.4',
    'close:45432 ', ' close:45432', 'open:45432', 'ALLOW:45432:172.30.0.2', 'CLOSE:45432', '-h', '',
    'log:', 'log:0', 'log:045432', 'log:65536', 'log:45432:1.2.3.4', 'LOG:45432', 'log:47017',
    'allow:45432:172.30.0.2\nclose:1',
  ];
  const args = bad.map((a) => `'${a}'`).join(' ');
  const out = runNet(R, `
    ${P} allow:45432:172.30.0.2 allow:45432:fd00::2 close:43306
    SNAP() { iptables -S APPCRANE-DB; ip6tables -S APPCRANE-DB; }
    before="$(SNAP)"
    echo @@BAD
    for a in ${args}; do ${P} close:47017 "$a" >/dev/null 2>/tmp/err; rc=$?; [ "$(SNAP)" = "$before" ] && same=same || same=CHANGED; echo "rc=$rc $same $(head -c 80 /tmp/err | tr '\\n' ' ')"; done
    echo @@MAX
    ${P} $(for i in $(seq 2049); do printf 'close:%s ' $((i + 10000)); done) >/dev/null 2>&1; echo "rc=$? $([ "$(SNAP)" = "$before" ] && echo same || echo CHANGED)"
    ${P} $(for i in $(seq 2048); do printf 'close:%s ' $((i + 10000)); done) >/dev/null 2>&1; echo "rc=$? $(iptables -S APPCRANE-DB | grep -c DROP) $(ip6tables -S APPCRANE-DB | grep -c DROP)"
    echo @@END
  `, { timeout: 120000 });
  const lines = block(out, 'BAD').trim().split('\n');
  assert.equal(lines.length, bad.length, out);
  lines.forEach((l, i) => assert.match(l, /^rc=2 same appcrane-db-chain: argument 2 /, `${JSON.stringify(bad[i])}: ${l}`));
  assert.deepEqual(block(out, 'MAX').trim().split('\n'), ['rc=2 same', 'rc=0 2048 2048']);
});
