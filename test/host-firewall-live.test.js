import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

// The rules AppCrane writes, applied by the real iptables-restore of an
// ubuntu:24.04 host, against real DNAT and a real FORWARD path. A privileged
// container plays the host: an "outside" namespace reaches it on o0, an "app"
// namespace sits behind it the way a Docker container does, PREROUTING DNATs
// four host ports to the app (as `docker run -p` does), FORWARD is DROP and
// jumps to DOCKER-USER (as Docker does). DOCKER-USER is then written by host
// hardening's own hn_docker_user, taken from scripts/host-hardening.sh, and
// the non-root path uses scripts/appcrane-publish-chain.sh through a real
// sudoers rule. AppCrane's database publishes tcp/31001 and udp/31003; 31002
// and 31004 are DNATed too, so only the firewall stands between them and the
// outside.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-firewall-live-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { assignPublicPort } = await import('../server/services/tcpIngress.js');
const P = await import('../server/services/hostFirewall/publishChain.js');
initDb();
const db = getDb();

const NAME = `crane-fw-live-${randomBytes(4).toString('hex')}`;
const IMAGE = 'ubuntu:24.04';
const SCRIPTS = process.env.APPCRANE_HOST_SCRIPTS_DIR || join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');
const HARDENING = join(SCRIPTS, 'host-hardening.sh');
const HELPER_SRC = join(SCRIPTS, 'appcrane-publish-chain.sh');

function shellFunction(text, name) {
  return new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}$`, 'm').exec(text)?.[0] || null;
}
const hardeningText = existsSync(HARDENING) ? readFileSync(HARDENING, 'utf8') : '';
const HN_FUNCS = ['hn_publish_chain', 'hn_docker_user'].map(n => shellFunction(hardeningText, n));
const HELPER_TEXT = existsSync(HELPER_SRC) ? readFileSync(HELPER_SRC, 'utf8') : null;

const SETUP = `set -e
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive  apt-get install -y -qq iptables iproute2 socat sudo >/dev/null 2>&1
ip netns add outside; ip netns add app
ip link add o0 type veth peer name o1; ip link set o1 netns outside
ip addr add 10.9.0.1/24 dev o0; ip link set o0 up
ip netns exec outside ip addr add 10.9.0.2/24 dev o1; ip netns exec outside ip link set o1 up
ip link add a0 type veth peer name a1; ip link set a1 netns app
ip addr add 10.8.0.1/24 dev a0; ip link set a0 up
ip netns exec app ip addr add 10.8.0.2/24 dev a1; ip netns exec app ip link set a1 up
ip netns exec app ip route add default via 10.8.0.1
ip netns exec outside ip route add 10.8.0.0/24 via 10.9.0.1
sysctl -qw net.ipv4.ip_forward=1
for m in "tcp 31001 5080" "tcp 31002 5081" "udp 31003 5082" "udp 31004 5083"; do set -- $m
  iptables -t nat -A PREROUTING -i o0 -p $1 --dport $2 -j DNAT --to-destination 10.8.0.2:$3
done
iptables -P FORWARD DROP
iptables -N DOCKER-USER
iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j ACCEPT
for p in 5080 5081 31005; do ip netns exec app setsid socat TCP-LISTEN:$p,fork,reuseaddr SYSTEM:'echo ok' >/dev/null 2>&1 < /dev/null & done
for p in 5082 5083; do ip netns exec app setsid socat UDP-RECVFROM:$p,fork SYSTEM:'echo ok' >/dev/null 2>&1 < /dev/null & done
sleep 1
echo READY
`;

function sh(args, { input = null, timeout = 180_000 } = {}) {
  return new Promise((res) => {
    const c = execFile('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      res({ code: err ? (typeof err.code === 'number' ? err.code : null) : 0, stdout: String(stdout), stderr: String(stderr), missing: false, error: err && typeof err.code !== 'number' ? err.message : null });
    });
    c.stdin.end(input ?? '');
  });
}

let skip = null;
if (HN_FUNCS.some(f => !f) || !HELPER_TEXT) {
  skip = `host hardening's hn_publish_chain/hn_docker_user or appcrane-publish-chain.sh not found under ${SCRIPTS} (set APPCRANE_HOST_SCRIPTS_DIR)`;
}
if (!skip) try {
  execFileSync('docker', ['version', '--format', '{{.Server.Os}}'], { timeout: 15_000, stdio: ['ignore', 'pipe', 'pipe'] });
} catch (e) {
  skip = `Docker is not reachable: ${String(e.stderr || e.message).split('\n')[0]}`;
}
if (!skip) {
  const started = await sh(['run', '-d', '--rm', '--privileged', '--name', NAME, IMAGE, 'sleep', '600'], { timeout: 240_000 });
  if (started.code !== 0) skip = `could not start ${IMAGE} privileged: ${started.stderr.split('\n')[0]}`;
  else {
    const setup = await sh(['exec', '-i', NAME, 'bash', '-s'], { input: SETUP, timeout: 240_000 });
    if (!setup.stdout.includes('READY')) skip = `host setup failed (apt or netns): ${(setup.stderr || setup.stdout).trim().split('\n').slice(-1)[0]}`;
    else {
      const hn = await sh(['exec', '-i', NAME, 'bash', '-s'], { input: `set -e\n${HN_FUNCS.join('\n')}\nhn_docker_user iptables 169.254.169.254 o0 yes\nhn_docker_user ip6tables fd00:ec2::254 o0 yes\necho HN-OK\n` });
      if (!hn.stdout.includes('HN-OK')) throw new Error(`host hardening's hn_docker_user failed: ${hn.stderr}`);
    }
  }
}
after(async () => {
  await sh(['rm', '-f', NAME], { timeout: 60_000 });
  rmSync(DATA_DIR, { recursive: true, force: true });
});

// AppCrane's exec seam, pointed at the fake host: iptables runs inside it;
// `docker ps` answers as the real host's Docker would for these two apps.
function hostRun(dockerPs, user = null) {
  return async (cmd, args, opts = {}) => {
    if (cmd === 'docker') return { code: 0, stdout: dockerPs, stderr: '', missing: false, error: null };
    return sh(['exec', '-i', ...(user ? ['-u', user] : []), NAME, cmd, ...args], { input: opts.input ?? null, timeout: 30_000 });
  };
}

async function reach(proto, port, addr = '10.9.0.1') {
  const r = await sh(['exec', '-i', NAME, 'timeout', '5', 'ip', 'netns', 'exec', 'outside', 'socat', '-T2', '-', `${proto}:${addr}:${port}`], { input: 'hi\n', timeout: 20_000 });
  return r.stdout.includes('ok');
}

test('live: the written chain admits the ports AppCrane published and the skeleton drops the rest', { skip: skip || false, timeout: 240_000 }, async () => {
  const insert = db.prepare('INSERT INTO apps (name, slug, slot, source_type, ingress_type, data_plane_port, data_plane_protocol) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const a = insert.run('live-tcp', 'live-tcp', 901, 'github', 'tcp', null, null).lastInsertRowid;
  const b = insert.run('live-udp', 'live-udp', 902, 'github', 'dual', 5082, 'udp').lastInsertRowid;
  assignPublicPort(db, a, 31001, 'production');
  assignPublicPort(db, b, 31003, 'production');
  const c = insert.run('live-direct', 'live-direct', 903, 'github', 'tcp', null, null).lastInsertRowid;
  assignPublicPort(db, c, 31005, 'production');
  const dockerPs = [
    'appcrane-live-direct-production|true|live-direct|production|0.0.0.0:31005->31005/tcp',
    'appcrane-live-tcp-production|true|live-tcp|production|127.0.0.1:4901->3000/tcp, 0.0.0.0:31001->5080/tcp',
    'appcrane-live-udp-production|true|live-udp|production|127.0.0.1:4902->3000/tcp, 0.0.0.0:31003->5082/udp',
    'other|||| 0.0.0.0:31002->5081/tcp',
  ].join('\n') + '\n';

  const du = await sh(['exec', NAME, 'iptables', '-w', '-S', 'DOCKER-USER']);
  assert.match(du.stdout, /-A DOCKER-USER -i o0 -j APPCRANE-PUBLISH\n-A DOCKER-USER -i o0 -j DROP\n/, du.stdout);
  assert.equal(await reach('TCP', 31001), false, 'before the sync the skeleton drops everything');

  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: hostRun(dockerPs) } });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.families.v4.state, 'applied');
  assert.equal(r.families.v6.state, 'applied', 'ip6tables read back what was written');
  assert.deepEqual(r.strays.map(s => `${s.container} ${s.proto}/${s.port}`), ['other tcp/31002']);

  assert.equal(await reach('TCP', 31001), true, 'tcp/31001 published by AppCrane is accepted');
  assert.equal(await reach('UDP', 31003), true, 'udp/31003 published by AppCrane is accepted');
  assert.equal(await reach('TCP', 31002), false, 'tcp/31002 is DNATed but not published by AppCrane');
  assert.equal(await reach('UDP', 31004), false, 'udp/31004 is DNATed but not published by AppCrane');
  assert.equal(await reach('TCP', 31005, '10.8.0.2'), false, 'routed straight at the container address (no DNAT): --ctstate DNAT keeps it out although 31005 is accepted');

  const again = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: hostRun(dockerPs) } });
  assert.equal(again.families.v4.state, 'unchanged', 'the real iptables -S output parses back to the same list');

  db.prepare("UPDATE apps SET ingress_type = 'http' WHERE id = ?").run(a);
  db.prepare("DELETE FROM app_host_ports WHERE app_id = ?").run(a);
  db.prepare('UPDATE apps SET public_port = NULL WHERE id = ?').run(a);
  const removed = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: hostRun(dockerPs.split('\n').filter(l => !l.startsWith('appcrane-live-tcp')).join('\n')) } });
  assert.equal(removed.status, 'ok', removed.reason);
  assert.equal(await reach('TCP', 31001), false, 'withdrawn once AppCrane no longer publishes it');
  assert.equal(await reach('UDP', 31003), true);
});

test('live, not root: AppCrane writes the chain through sudo -n and host hardening\'s helper', { skip: skip || false, timeout: 240_000 }, async () => {
  const copy = await sh(['exec', '-i', NAME, 'bash', '-c', 'mkdir -p /usr/local/lib/appcrane && cat > /usr/local/lib/appcrane/appcrane-publish-chain.sh'], { input: HELPER_TEXT });
  assert.equal(copy.code, 0, copy.stderr);
  const install = await sh(['exec', '-i', NAME, 'bash', '-s'], { input: `set -e
useradd -m crane
chown root:root /usr/local/lib/appcrane/appcrane-publish-chain.sh; chmod 0755 /usr/local/lib/appcrane/appcrane-publish-chain.sh
iptables -w -F APPCRANE-PUBLISH; ip6tables -w -F APPCRANE-PUBLISH
echo INSTALLED
` });
  assert.match(install.stdout, /INSTALLED/, install.stderr);
  db.prepare('DELETE FROM app_host_ports').run();
  db.prepare('DELETE FROM apps').run();
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type, ingress_type) VALUES ('nr-tcp', 'nr-tcp', 903, 'github', 'tcp')").run().lastInsertRowid;
  assignPublicPort(db, id, 31001, 'production');
  const dockerPs = 'appcrane-nr-tcp-production|true|nr-tcp|production|0.0.0.0:31001->5080/tcp\n';
  const state = (drop) => () => `result=ok\next=o0\nfamilies=IPv4+IPv6\ndocker_user=skeleton\npublish_drop=${drop}\n`;
  const deps = (extra) => ({ platform: 'linux', uid: 1000, exists: () => true, run: hostRun(dockerPs, 'crane'), ...extra });

  assert.equal(await reach('TCP', 31001), false, 'empty chain, DROP in place');
  const refused = await P.syncPublishChain({ deps: deps({ readFile: state('yes') }) });
  assert.equal(refused.status, 'failed', 'no sudoers rule yet, and the skeleton drops');
  assert.match(refused.reason, /sudo refused the helper/);
  const na = await P.syncPublishChain({ deps: deps({ readFile: state('no') }) });
  assert.equal(na.status, 'not_applicable', 'no sudoers rule, skeleton without the DROP');

  const sudoers = await sh(['exec', '-i', NAME, 'bash', '-c', "echo 'crane ALL=(root) NOPASSWD: /usr/local/lib/appcrane/appcrane-publish-chain.sh' > /etc/sudoers.d/appcrane-publish-chain && chmod 0440 /etc/sudoers.d/appcrane-publish-chain && visudo -cf /etc/sudoers.d/appcrane-publish-chain"]);
  assert.equal(sudoers.code, 0, sudoers.stderr);
  const r = await P.syncPublishChain({ deps: deps({ readFile: state('yes') }) });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.mode, 'helper');
  assert.equal(await reach('TCP', 31001), true, 'written by the helper as non-root: admitted');
  assert.equal(await reach('TCP', 31002), false, 'DNATed, not published: still dropped');
  const read = await sh(['exec', NAME, 'iptables', '-w', '-S', 'APPCRANE-PUBLISH']);
  assert.deepEqual(read.stdout.trim().split('\n'), ['-N APPCRANE-PUBLISH', '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT']);
  const six = await sh(['exec', NAME, 'ip6tables', '-w', '-S', 'APPCRANE-PUBLISH']);
  assert.match(six.stdout, /--ctstate DNAT --ctorigdstport 31001 /, 'ip6tables written too');
});
