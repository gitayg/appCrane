import { test } from 'node:test';
import assert from 'node:assert/strict';

// The APPCRANE-PUBLISH side of the network section, run for real in privileged
// Ubuntu containers: scripts/appcrane-publish-chain.sh (the root-owned helper a
// non-root AppCrane runs through sudo), install-host-hardening.sh installing it
// with its sudoers rule, and host-hardening.sh installing DOCKER-USER's DROP on
// the public interface only when the server can keep that chain filled and
// already has. Without those checks a non-root box, or an Apply before the
// server synced, dropped every published app port.

const { buildNetImages, skipNet, runNet, block, exits } = await import('./host-hardening-harness.js');
buildNetImages();
const R = '24.04';
const H = '/usr/local/lib/appcrane/appcrane-publish-chain.sh';
const SAVE = 'for t in iptables ip6tables; do $t-save -t filter | grep -v "^#" | sed "s/ \\[[0-9]*:[0-9]*\\]$//"; done';
const RULE = (proto, port) => `-A APPCRANE-PUBLISH -p ${proto} -m conntrack --ctstate DNAT --ctorigdstport ${port} --ctdir ORIGINAL -j ACCEPT`;
const SKELETON = (drop) => [
  '-N DOCKER-USER',
  '-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN',
  '-A DOCKER-USER -d 169.254.169.254/32 -i docker0 -j DROP',
  '-A DOCKER-USER -d 169.254.169.254/32 -i br-+ -j DROP',
  '-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH',
  ...(drop ? ['-A DOCKER-USER -i eth0 -j DROP'] : []),
  '-A DOCKER-USER -j RETURN',
].join('\n');
// A process named docker-proxy listening where Docker's would.
const FAKE_PROXY = 'cp "$(readlink -f "$(command -v nc)")" /usr/local/bin/docker-proxy';

test('appcrane-publish-chain.sh: replaces the chain in both families with --ctstate DNAT accepts, silent; refuses bad arguments with exit 2 and no change; no args empties; other chains untouched; skips unusable ip6tables', { skip: skipNet(R) }, () => {
  const P = '/opt/appcrane/scripts/appcrane-publish-chain.sh';
  const out = runNet(R, `
    iptables -N OTHER; iptables -A OTHER -p tcp --dport 1 -j ACCEPT
    iptables -N APPCRANE-PUBLISH; iptables -A APPCRANE-PUBLISH -p tcp --dport 2 -j ACCEPT
    echo @@OK; ${P} tcp:8080 udp:31001 tcp:8080 2>&1; echo "rc=$?"
    echo @@C1; iptables -S APPCRANE-PUBLISH; ip6tables -S APPCRANE-PUBLISH
    echo @@BAD
    for a in tcp:0 tcp:080 tcp:65536 tcp:99999 sctp:9 'tcp:80 ' 'tcp:80;id' ' tcp:80' -h udp: TCP:80 'tcp:1
tcp:2'; do ${P} tcp:9 "$a" >/dev/null 2>&1; echo "rc=$?"; done
    ${P} $(for i in $(seq 513); do printf 'tcp:%s ' $((i + 1000)); done) >/dev/null 2>&1; echo "rc=$?"
    ${P} $(for i in $(seq 512); do printf 'tcp:%s ' $((i + 1000)); done) >/dev/null 2>&1; echo "max=$? $(iptables -S APPCRANE-PUBLISH | grep -c ACCEPT)"
    ${P} tcp:8080 udp:31001
    echo @@C2; iptables -S APPCRANE-PUBLISH; ip6tables -S APPCRANE-PUBLISH
    echo @@EMPTY; ${P} 2>&1; echo "rc=$?"; iptables -S APPCRANE-PUBLISH; ip6tables -S APPCRANE-PUBLISH
    echo @@OTHER; iptables -S OTHER
    mkdir /tmp/v6; mv /usr/sbin/ip6tables /usr/sbin/ip6tables-restore /tmp/v6/
    echo @@NO6; ${P} udp:7 2>&1; echo "rc=$?"; iptables -S APPCRANE-PUBLISH
    echo @@END
  `);
  assert.equal(block(out, 'OK'), 'rc=0\n', 'prints nothing on success');
  const both = ['-N APPCRANE-PUBLISH', RULE('tcp', 8080), RULE('udp', 31001)].join('\n');
  assert.equal(block(out, 'C1').trim(), `${both}\n${both}`, 'replaced (old rule gone), deduplicated, created in IPv6');
  assert.deepEqual(block(out, 'BAD').trim().split('\n'), [...Array(13).fill('rc=2'), 'max=0 512']);
  assert.equal(block(out, 'C2').trim(), `${both}\n${both}`);
  assert.equal(block(out, 'EMPTY').trim(), 'rc=0\n-N APPCRANE-PUBLISH\n-N APPCRANE-PUBLISH');
  assert.equal(block(out, 'OTHER').trim(), '-N OTHER\n-A OTHER -p tcp -m tcp --dport 1 -j ACCEPT');
  assert.equal(block(out, 'NO6').trim(), `rc=0\n-N APPCRANE-PUBLISH\n${RULE('udp', 7)}`);
});

test('non-root AppCrane: without the helper the skeleton goes in without the DROP (warned, recorded); install-host-hardening.sh installs helper and sudoers, the run user can sudo exactly it, and the next Apply adds the DROP; a broken sudoers file takes it out again', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    useradd -m app; chown -R app:app /opt/appcrane
    hh
    echo @@V1; iptables -S DOCKER-USER
    echo @@S1; cat /var/lib/appcrane/host-network.state
    iptables -F DOCKER-USER; /usr/local/sbin/appcrane-host-network.sh >/dev/null 2>&1
    echo @@BOOT1; iptables -S DOCKER-USER
    echo @@INSTALL; bash /opt/appcrane/scripts/install-host-hardening.sh app 2>&1; echo "rc=$?"
    echo @@MODE; stat -c '%U:%G %a' ${H} /etc/sudoers.d/appcrane-publish-chain; cat /etc/sudoers.d/appcrane-publish-chain
    echo @@SUDO; su app -c "sudo -n ${H} udp:31001" 2>&1; echo "rc=$?"
    iptables -S APPCRANE-PUBLISH
    su app -c "sudo -n ${H} 'tcp:22;id'" >/dev/null 2>&1; echo "bad=$?"
    su app -c "sudo -n /usr/sbin/iptables -S" >/dev/null 2>&1; echo "other=$?"
    hh
    echo @@V2; iptables -S DOCKER-USER; ip6tables -S DOCKER-USER
    echo @@S2; cat /var/lib/appcrane/host-network.state
    echo 'Runas_Alias = ' >> /etc/sudoers.d/appcrane-publish-chain
    hh
    echo @@V3; iptables -S DOCKER-USER
    echo @@S3; cat /var/lib/appcrane/host-network.state
  `);
  const [first, second, third] = exits(out);
  assert.equal(first, 0, out);
  assert.match(out, /DOCKER-USER installed WITHOUT the DROP on eth0: AppCrane runs as app and \/usr\/local\/lib\/appcrane\/appcrane-publish-chain\.sh is not installed/);
  assert.equal(block(out, 'V1').trim(), SKELETON(false));
  const s1 = block(out, 'S1');
  assert.match(s1, /^run_user=app$/m);
  assert.match(s1, /^publish_drop=no$/m);
  assert.match(s1, /^publish_drop_reason=AppCrane runs as app and .* is not installed/m);
  assert.equal(block(out, 'BOOT1').trim(), SKELETON(false), 'the boot script keeps the no-DROP decision');

  assert.match(block(out, 'INSTALL'), /rc=0$/m, block(out, 'INSTALL'));
  assert.match(block(out, 'MODE'), /^root:root 755\nroot:root 440\n/);
  assert.match(block(out, 'MODE'), /^app ALL=\(root\) NOPASSWD: \/usr\/local\/lib\/appcrane\/appcrane-publish-chain\.sh$/m);
  const sudo = block(out, 'SUDO');
  assert.match(sudo, /^rc=0\n/, sudo);
  assert.ok(sudo.includes(`${RULE('udp', 31001)}\n`), sudo);
  assert.match(sudo, /^bad=2$/m, 'the helper itself refuses a bad argument under sudo');
  assert.match(sudo, /^other=1$/m, 'nothing else is sudoable');

  assert.equal(second, 0, out);
  assert.equal(block(out, 'V2').trim(), `${SKELETON(true)}\n${SKELETON(true).replace(/169\.254\.169\.254\/32/g, 'fd00:ec2::254/128')}`);
  assert.match(block(out, 'S2'), /^publish_drop=yes$/m);
  assert.match(block(out, 'S2'), /^publish_drop_reason=$/m);

  assert.equal(third, 0, out);
  assert.equal(block(out, 'V3').trim(), SKELETON(false));
  assert.match(block(out, 'S3'), /^publish_drop_reason=\/etc\/sudoers\.d\/appcrane-publish-chain is missing or does not validate/m);
});

test('Apply before the server synced: with the interim unit present DOCKER-USER is left to it and the unit kept; once APPCRANE-PUBLISH accepts every docker-proxy port (both families) the DROP goes in and the interim unit goes; unsynced without the interim unit means no DROP', { skip: skipNet(R) }, () => {
  const P = '/opt/appcrane/scripts/appcrane-publish-chain.sh';
  const out = runNet(R, `
    ${FAKE_PROXY}
    docker-proxy -lku 0.0.0.0 31001 >/dev/null 2>&1 &
    docker-proxy -lk 0.0.0.0 38080 >/dev/null 2>&1 &
    sysctl -qw net.ipv6.bindv6only=1; docker-proxy -6 -lk :: 38081 >/dev/null 2>&1 &
    sleep 0.3; sysctl -qw net.ipv6.bindv6only=0; docker-proxy -6 -lk :: 38083 >/dev/null 2>&1 &
    nc -lk 127.0.0.1 38082 >/dev/null 2>&1 &
    for i in $(seq 50); do [ "$(ss -H -ltnup | grep -c docker-proxy)" -ge 4 ] && break; sleep 0.1; done
    echo @@SS; ss -H -ltnup | grep -o '[^ ]*:3808[13] ' | sort
    mkdir -p /etc/systemd/system /usr/local/sbin
    printf '[Service]\\nType=oneshot\\nExecStart=/usr/local/sbin/appcrane-docker-user.sh\\n' > /etc/systemd/system/appcrane-docker-user.service
    printf '#!/bin/sh\\n' > /usr/local/sbin/appcrane-docker-user.sh
    iptables -N DOCKER-USER
    iptables -A DOCKER-USER -i eth0 -p udp --dport 31001 -j RETURN
    iptables -A DOCKER-USER -i eth0 -j DROP
    echo @@BEFORE; iptables -S DOCKER-USER
    hh
    echo @@A; iptables -S DOCKER-USER; iptables -S APPCRANE-PUBLISH; ls /etc/systemd/system/appcrane-docker-user.service /usr/local/sbin/appcrane-docker-user.sh; cat /var/lib/appcrane/host-network.state
    /usr/local/sbin/appcrane-host-network.sh >/dev/null 2>&1
    echo @@ABOOT; iptables -S DOCKER-USER
    ${P} udp:31001 tcp:38080 tcp:38081 tcp:38083
    ip6tables -F APPCRANE-PUBLISH
    hh
    echo @@B; iptables -S DOCKER-USER; cat /var/lib/appcrane/host-network.state
    ${P} udp:31001 tcp:38080 tcp:38081 tcp:38083
    hh
    echo @@C; iptables -S DOCKER-USER; ls /etc/systemd/system/appcrane-docker-user.service /usr/local/sbin/appcrane-docker-user.sh 2>&1; cat /var/lib/appcrane/host-network.state
    ${P} udp:31001
    hh
    echo @@D; iptables -S DOCKER-USER; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [0, 0, 0, 0], out);
  assert.equal(block(out, 'SS'), '*:38083 \n[::]:38081 \n', 'one IPv6-only and one dual-stack listener');
  const interim = block(out, 'BEFORE').trim();
  const a = block(out, 'A');
  assert.match(out, /AppCrane has not synced published ports yet; Apply again after the server is on v2\.145\.0 \(APPCRANE-PUBLISH lacks tcp:38080 tcp:38081 tcp:38083 udp:31001,/);
  assert.ok(a.startsWith(`${interim}\n-N APPCRANE-PUBLISH\n`), a);
  assert.match(a, /^\/etc\/systemd\/system\/appcrane-docker-user\.service\n\/usr\/local\/sbin\/appcrane-docker-user\.sh$/m, 'interim unit kept');
  assert.match(a, /^docker_user=interim$/m);
  assert.match(a, /^publish_drop=no$/m);
  assert.match(a, /^interim_removed=no$/m);
  assert.doesNotMatch(a, /38082/, 'a loopback listener is not a public publish');
  assert.equal(block(out, 'ABOOT').trim(), interim, 'the boot script leaves DOCKER-USER to the interim unit too');

  const b = block(out, 'B');
  assert.ok(b.startsWith(`${interim}\n`), b);
  assert.match(b, /^publish_drop_reason=AppCrane has not synced published ports yet: APPCRANE-PUBLISH lacks tcp:38081 tcp:38083$/m, 'a [::] listener is checked in ip6tables, a dual-stack * listener in both');

  const c = block(out, 'C');
  assert.ok(c.startsWith(`${SKELETON(true)}\n`), c);
  assert.equal((c.match(/No such file/g) || []).length, 2, c);
  assert.match(c, /^publish_drop=yes$/m);
  assert.match(c, /^interim_removed=yes$/m);

  const d = block(out, 'D');
  assert.ok(d.startsWith(`${SKELETON(false)}\n`), d);
  assert.match(d, /^docker_user=skeleton$/m);
  assert.match(d, /^publish_drop_reason=AppCrane has not synced published ports yet: APPCRANE-PUBLISH lacks tcp:38080 tcp:38081 tcp:38083$/m);
});

test('ss failing: its stderr is shown, the listeners count as unchecked, so neither the DOCKER-USER DROP nor the INPUT DROP goes in', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    printf '#!/bin/sh\\necho "ss: simulated netlink failure" >&2\\nexit 1\\n' > /usr/local/bin/ss; chmod 755 /usr/local/bin/ss
    hh
    echo @@V; iptables -S DOCKER-USER; iptables -S INPUT | head -1
    echo @@S; cat /var/lib/appcrane/host-network.state
  `);
  assert.deepEqual(exits(out), [3], out);
  assert.match(out, /ss: simulated netlink failure/);
  assert.match(out, /ss failed, so the listening sockets cannot be checked/);
  const v = block(out, 'V');
  assert.ok(v.startsWith(`${SKELETON(false)}\n-P INPUT ACCEPT`), v);
  const s = block(out, 'S');
  assert.match(s, /^input_mode=refused$/m);
  assert.match(s, /^uncovered=ss-failed$/m);
  assert.match(s, /^publish_drop_reason=cannot check which ports docker-proxy listens on \(ss-failed\)$/m);
});

test('PORT in .env below 1024 or in the base allow list: refused, every chain left as it was, failure recorded with the last good decision kept for the boot script', { skip: skipNet(R) }, () => {
  const out = runNet(R, `
    hh
    echo @@GOOD; ${SAVE}
    for p in 22 80 443 1023 0 99999 abc; do
      printf "DATA_DIR=/opt/appcrane/data\\nPORT=$p\\n" > /opt/appcrane/.env
      hh
      echo "@@AFTER$p"; ${SAVE}
      echo "@@STATE$p"; cat /var/lib/appcrane/host-network.state
    done
    for t in iptables ip6tables; do $t -P INPUT ACCEPT; $t -F; $t -X; done
    /usr/local/sbin/appcrane-host-network.sh >/dev/null 2>&1; echo "@@BOOT $?"
    echo @@SAVE3; ${SAVE}
    eval "$(sed -n '/^hn_app_port_ok() {/,/^}/p' /opt/appcrane/scripts/host-hardening.sh)"
    echo @@BASEALLOW; for p in 8443 8444; do HN_BASE_ALLOW="22/tcp 8443/tcp" hn_app_port_ok $p; echo "$p=$?"; done
    sed -i 's/^app_port=.*/app_port=22/' /var/lib/appcrane/host-network.state
    for t in iptables ip6tables; do $t -P INPUT ACCEPT; $t -F; $t -X; done
    echo @@BOOT22OUT; /usr/local/sbin/appcrane-host-network.sh 2>&1; echo "@@BOOT22 $?"
    echo @@SAVE4; ${SAVE}
  `);
  const ports = ['22', '80', '443', '1023', '0', '99999', 'abc'];
  assert.deepEqual(exits(out), [0, ...ports.map(() => 3)], out);
  const good = block(out, 'GOOD');
  for (const p of ports) {
    assert.equal(block(out, `AFTER${p}`), good, `PORT=${p} changed a chain`);
    const st = block(out, `STATE${p}`);
    assert.match(st, new RegExp(`^error=app port ${p} refused: below 1024 or in 22/tcp 80/tcp 443/tcp 443/udp$`, 'm'));
    assert.match(st, /^result=failed$/m);
    assert.match(st, /^app_port=5001$/m);
    assert.match(st, /^input_mode=appcrane-input$/m);
  }
  assert.match(out, /PORT=22 in \/opt\/appcrane\/\.env is below 1024 or a port the baseline accepts/);
  assert.doesNotMatch(good, /--dport 22 -j DROP/);
  assert.equal(block(out, 'BASEALLOW'), '8443=1\n8444=0\n', 'a port in the base allow list is refused even when 1024 or above');
  assert.match(out, /^@@BOOT 0$/m);
  assert.equal(block(out, 'SAVE3'), good, 'the boot script re-applies the last good decision');
  assert.match(out, /app_port '22' in \/var\/lib\/appcrane\/host-network\.state is not usable — INPUT not applied/);
  const s4 = block(out, 'SAVE4');
  assert.doesNotMatch(s4, /APPCRANE-INPUT|--dport 22/, 'a tampered state never makes the boot script drop 22');
  assert.match(s4, /^-A DOCKER-USER -i eth0 -j DROP$/m);
});
