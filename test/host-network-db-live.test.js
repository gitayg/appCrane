import { test } from 'node:test';
import assert from 'node:assert/strict';

// APPCRANE-DB against real DNAT and a real FORWARD path. A privileged
// container plays the host the way Docker lays it out: a docker0 bridge
// with a "db" namespace on it, as the managed database servers are (a real
// docker0 is 172.17.0.1/16, but the test container's own eth0 usually sits in
// that subnet, and the rules match the name docker0, not an address); an appcrane-apps style br-<12 hex> bridge with two app namespaces
// behind it; PREROUTING DNATs <docker0 address>:45432 and :43306 to the
// database namespace (as `docker run -p 172.17.0.1:45432:5432` does); FORWARD is DROP
// and jumps to DOCKER-USER first. DOCKER-USER is written by the real
// scripts/host-hardening.sh and APPCRANE-DB by the real
// scripts/appcrane-db-chain.sh, the second time through sudo as a non-root
// run user, as install-host-hardening.sh sets it up.

import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';

const { buildNetImages, skipNet, runNet, block, exits, netImages } = await import('./host-hardening-harness.js');
buildNetImages();
const R = '24.04';
const BR = 'br-0123456789ab';

test('live: an empty APPCRANE-DB admits every app; an allowlist admits the listed source, drops another source on that port, leaves an unlisted port alone, and a rewrite keeps an established connection', { skip: skipNet(R), timeout: 180000 }, () => {
  const out = runNet(R, `
    sysctl -qw net.ipv4.ip_forward=1
    ip link add docker0 type bridge; ip addr add 10.117.0.1/24 dev docker0; ip link set docker0 up
    ip netns add db; ip link add vdb0 type veth peer name vdb1; ip link set vdb1 netns db; ip link set vdb0 master docker0 up
    ip netns exec db ip addr add 10.117.0.2/24 dev vdb1; ip netns exec db ip link set vdb1 up; ip netns exec db ip link set lo up
    ip netns exec db ip route add default via 10.117.0.1
    ip link add ${BR} type bridge; ip addr add 10.130.0.1/24 dev ${BR}; ip link set ${BR} up
    for n in 2 3; do
      ip netns add app$n; ip link add va$n type veth peer name vb$n; ip link set vb$n netns app$n; ip link set va$n master ${BR} up
      ip netns exec app$n ip addr add 10.130.0.$n/24 dev vb$n; ip netns exec app$n ip link set vb$n up; ip netns exec app$n ip link set lo up
      ip netns exec app$n ip route add default via 10.130.0.1
    done
    for m in "45432 5432" "43306 3306"; do set -- $m
      iptables -t nat -A PREROUTING -d 10.117.0.1/32 ! -i docker0 -p tcp --dport $1 -j DNAT --to-destination 10.117.0.2:$2
    done
    iptables -P FORWARD DROP; iptables -N DOCKER-USER; iptables -A FORWARD -j DOCKER-USER; iptables -A FORWARD -j ACCEPT
    ip netns exec db setsid nc -lk 5432 > /tmp/recv 2>/dev/null < /dev/null &
    ip netns exec db setsid nc -lk 3306 > /dev/null 2>&1 < /dev/null &
    sleep 0.5
    probe() { ip netns exec app$1 nc -z -w 2 10.117.0.1 $2 >/dev/null 2>&1 && echo "app$1:$2=open" || echo "app$1:$2=dropped"; }
    useradd -m app; chown -R app:app /opt/appcrane
    bash /opt/appcrane/scripts/install-host-hardening.sh app >/dev/null 2>&1; echo "install=$?"
    hh
    echo @@DU; iptables -S DOCKER-USER; iptables -S APPCRANE-DB
    echo @@EMPTY; probe 2 45432; probe 3 45432; probe 2 43306
    echo @@EST; mkfifo /tmp/f
    ip netns exec app2 nc 10.117.0.1 45432 < /tmp/f > /dev/null 2>&1 &
    exec 3>/tmp/f; echo first >&3; sleep 0.5
    /opt/appcrane/scripts/appcrane-db-chain.sh allow:45432:10.130.0.3 close:47017; echo "w1=$?"
    echo @@ONLY3; probe 3 45432; probe 2 45432; probe 2 43306
    echo second >&3; sleep 0.5
    echo @@RECV1; cat /tmp/recv
    echo @@W2; su app -c "sudo -n /usr/local/lib/appcrane/appcrane-db-chain.sh allow:45432:10.130.0.2"; echo "w2=$?"
    echo @@ONLY2; probe 2 45432; probe 3 45432; probe 3 43306
    echo third >&3; sleep 0.5
    echo @@RECV2; cat /tmp/recv
    echo @@CHAIN; iptables -S APPCRANE-DB
    echo @@W3; /opt/appcrane/scripts/appcrane-db-chain.sh allow:43306:10.130.0.2 log:43306; echo "w3=$?"
    echo @@OBSERVE; probe 3 43306; probe 2 43306
    echo @@LOGGED; iptables -L APPCRANE-DB -v -n -x | awk '/LOG/ { print $1 }'
    echo @@END
  `, { timeout: 170000 });
  assert.deepEqual(exits(out), [0], out);
  assert.match(out, /^install=0$/m, out);
  const du = block(out, 'DU');
  assert.match(du, /^-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB$/m, du);
  assert.match(du, /^-N APPCRANE-DB\n$/m, 'starts empty');
  assert.deepEqual(block(out, 'EMPTY').trim().split('\n'), ['app2:45432=open', 'app3:45432=open', 'app2:43306=open'], 'empty chain fails open');
  assert.match(out, /^w1=0$/m);
  assert.deepEqual(block(out, 'ONLY3').trim().split('\n'), ['app3:45432=open', 'app2:45432=dropped', 'app2:43306=open'],
    'allowed source passes, another source on the same port is dropped, an unlisted port passes');
  assert.equal(block(out, 'RECV1'), 'first\nsecond\n', 'the connection app2 opened before the rewrite still carries data');
  assert.match(out, /^w2=0$/m, 'the non-root run user rewrites the chain through sudo');
  assert.deepEqual(block(out, 'ONLY2').trim().split('\n'), ['app2:45432=open', 'app3:45432=dropped', 'app3:43306=open']);
  assert.equal(block(out, 'RECV2'), 'first\nsecond\nthird\n');
  assert.equal(block(out, 'CHAIN').trim(), [
    '-N APPCRANE-DB',
    '-A APPCRANE-DB -s 10.130.0.2/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
  ].join('\n'));
  assert.match(out, /^w3=0$/m);
  assert.deepEqual(block(out, 'OBSERVE').trim().split('\n'), ['app3:43306=open', 'app2:43306=open'], 'observe mode refuses nothing');
  assert.ok(Number(block(out, 'LOGGED').trim()) >= 1, `the source that would be dropped is logged: ${block(out, 'LOGGED')}`);
});

// A container on docker0 (a coder container, for one) that dials the gateway
// reaches a database port through docker-proxy, in INPUT, never FORWARD, so
// APPCRANE-DB does not see it; APPCRANE-INPUT drops it. AppCrane's own
// connection over loopback and the replies to the host's own outgoing
// connections whose ephemeral source port is a database port (on docker0 and
// on the public interface) must still pass. A peer container on Docker's
// default network plays a server on the internet.
test('live: APPCRANE-INPUT drops a docker0 container dialling a database port on the gateway, keeps loopback, and keeps replies to the host\'s own connections from ephemeral ports in the database ranges', { skip: skipNet(R), timeout: 180000 }, () => {
  const peer = `appcrane-test-dbscript-peer-${randomBytes(4).toString('hex')}`;
  const dk = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    dk('run', '-d', '--rm', '--name', peer, netImages[R], 'nc', '-lk', '8080');
    const peerIp = dk('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', peer).trim();
    assert.match(peerIp, /^\d+\.\d+\.\d+\.\d+$/);
    const out = runNet(R, `
      ip link add docker0 type bridge; ip addr add 10.117.0.1/24 dev docker0; ip link set docker0 up
      for n in db coder; do
        ip netns add $n; ip link add v$n-h type veth peer name v$n-c; ip link set v$n-c netns $n; ip link set v$n-h master docker0 up
        ip netns exec $n ip link set v$n-c up; ip netns exec $n ip link set lo up
      done
      ip netns exec db ip addr add 10.117.0.2/24 dev vdb-c; ip netns exec coder ip addr add 10.117.0.3/24 dev vcoder-c
      ip netns exec db setsid nc -lk 5432 >/dev/null 2>&1 < /dev/null &
      setsid nc -lk 10.117.0.1 45432 >/dev/null 2>&1 < /dev/null &
      setsid nc -lk 127.0.0.1 45432 >/dev/null 2>&1 < /dev/null &
      sleep 0.5
      t() { nc -z -w 2 "$@" >/dev/null 2>&1 && echo open || echo dropped; }
      check() {
        echo "coder->gateway:45432=$(ip netns exec coder nc -z -w 2 10.117.0.1 45432 >/dev/null 2>&1 && echo open || echo dropped)"
        echo "host->127.0.0.1:45432=$(t 127.0.0.1 45432)"
        echo "host:$1->db:5432=$(t -p $1 10.117.0.2 5432)"
        echo "host:$2->internet:8080=$(t -p $2 ${peerIp} 8080)"
      }
      echo @@BEFORE; check 46400 46401
      hh
      echo @@AFTER; check 46402 46403
      echo @@AFTER2; check 43306 47017
      echo @@CHAIN; iptables -S APPCRANE-INPUT | grep docker0
      echo @@END
    `, { timeout: 170000 });
    assert.deepEqual(exits(out), [0], out);
    assert.deepEqual(block(out, 'BEFORE').trim().split('\n'), ['coder->gateway:45432=open', 'host->127.0.0.1:45432=open', 'host:46400->db:5432=open', 'host:46401->internet:8080=open'], 'reproduced: the docker0 path is open');
    assert.deepEqual(block(out, 'AFTER').trim().split('\n'), ['coder->gateway:45432=dropped', 'host->127.0.0.1:45432=open', 'host:46402->db:5432=open', 'host:46403->internet:8080=open']);
    assert.deepEqual(block(out, 'AFTER2').trim().split('\n'), ['coder->gateway:45432=dropped', 'host->127.0.0.1:45432=open', 'host:43306->db:5432=open', 'host:47017->internet:8080=open']);
    assert.match(block(out, 'CHAIN'), /^-A APPCRANE-INPUT -i docker0 -p tcp -m multiport --dports 45432,43306,47017,46379:46878 -m conntrack --ctstate NEW -j DROP$/m);
  } finally {
    try { dk('rm', '-f', peer); } catch (_) { /* not started */ }
  }
});
