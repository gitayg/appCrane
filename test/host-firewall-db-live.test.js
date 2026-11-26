import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

// APPCRANE-DB written by the real iptables-restore of an ubuntu:24.04 host,
// against real DNAT and a real FORWARD path. A privileged container plays the
// host: a "db" namespace sits behind an interface named docker0 at
// 172.17.0.1 (a managed database server on Docker's default bridge), and two
// app namespaces sit behind their own bridges, as containers on
// appcrane-apps do. PREROUTING DNATs 172.17.0.1:45432 to the server the way
// Docker's publish does; FORWARD is DROP and jumps to DOCKER-USER, whose
// line into APPCRANE-DB is the contract host hardening writes:
//   -A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-db-chain-live-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const DC = await import('../server/services/hostFirewall/dbChain.js');
initDb();
const db = getDb();

const NAME = `crane-dbchain-live-${randomBytes(4).toString('hex')}`;
const IMAGE = 'ubuntu:24.04';

const SETUP = `set -e
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iproute2 socat >/dev/null 2>&1
sysctl -qw net.ipv4.ip_forward=1
# This container's own eth0 is on Docker's default bridge, 172.17.0.0/16: with
# no other container there it is 172.17.0.2, the fake database server's
# address, and every connection to it stays local and is refused.
ip -4 addr flush dev eth0
mk() { ip netns add $1; ip link add $2 type veth peer name p-$1; ip link set p-$1 netns $1
  ip addr add $3.1/24 dev $2; ip link set $2 up
  ip netns exec $1 ip addr add $3.2/24 dev p-$1; ip netns exec $1 ip link set p-$1 up; ip netns exec $1 ip link set lo up
  ip netns exec $1 ip route add default via $3.1; }
mk db docker0 172.17.0
mk app1 br-app1 10.8.0
mk app2 br-app2 10.7.0
iptables -t nat -A PREROUTING -d 172.17.0.1/32 ! -i docker0 -p tcp --dport 45432 -j DNAT --to-destination 172.17.0.2:5432
iptables -P FORWARD DROP
iptables -N DOCKER-USER
iptables -N APPCRANE-DB
iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j ACCEPT
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
iptables -A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB
ip6tables -N APPCRANE-DB
ip netns exec db setsid socat TCP-LISTEN:5432,fork,reuseaddr SYSTEM:'echo ok' >/dev/null 2>&1 < /dev/null &
sleep 1
echo READY
`;

function setMode(m) {
  db.prepare("INSERT INTO settings (key, value) VALUES ('db_allowlist_mode', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(m);
}

function sh(args, { input = null, timeout = 180_000 } = {}) {
  return new Promise((res) => {
    const c = execFile('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      res({ code: err ? (typeof err.code === 'number' ? err.code : null) : 0, stdout: String(stdout), stderr: String(stderr), missing: false, error: err && typeof err.code !== 'number' ? err.message : null });
    });
    c.stdin.end(input ?? '');
  });
}

let skip = null;
try {
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
  }
}
after(async () => {
  await sh(['rm', '-f', NAME], { timeout: 60_000 });
  rmSync(DATA_DIR, { recursive: true, force: true });
});

// docker answers as the real host's Docker would: app1's container runs at
// 10.8.0.2. iptables runs inside the fake host.
let containers = [['appcrane-live-db-production', '10.8.0.2,', '']];
const dockerAnswer = (args) => {
  if (args[0] === 'ps') return containers.map(c => `${c[0]}\n`).join('');
  if (args[0] === 'inspect') return containers.map((c, i) => `cid${i}|/${c[0]}|running|appcrane-apps|${c[1]};|${c[2]}\n`).join('');
  return '';
};
const run = async (cmd, args, opts = {}) => {
  if (cmd === 'docker') return { code: 0, stdout: dockerAnswer(args), stderr: '', missing: false, error: null };
  return sh(['exec', '-i', NAME, cmd, ...args], { input: opts.input ?? null, timeout: 30_000 });
};

async function reach(ns) {
  const r = await sh(['exec', '-i', NAME, 'timeout', '5', 'ip', 'netns', 'exec', ns, 'socat', '-T2', '-', 'TCP:172.17.0.1:45432'], { input: 'hi\n', timeout: 20_000 });
  return r.stdout.includes('ok');
}

test('live: the allowed container reaches its database port, another container is dropped, a pending start opens it', { skip: skip || false, timeout: 240_000 }, async () => {
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('live-db', 'live-db', 950, 'github')").run().lastInsertRowid;
  db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES ('postgres', 'c', 'i', 45432, 'x')").run();
  db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', 'crane_a1', 'crane_a1_u', 'x')").run(appId);
  setMode('enforce');

  assert.equal(await reach('app1'), true, 'empty chain: open');
  assert.equal(await reach('app2'), true, 'empty chain: open to every container (fails open)');

  const r = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.families.v4.state, 'applied');
  assert.equal(r.families.v6.state, 'applied', 'ip6tables read back what was written');
  assert.deepEqual(r.jump, { v4: 'present', v6: 'absent', source: 'rules' }, 'the fake host jumps in iptables only');
  assert.equal(r.enforcement.state, 'enforced');
  assert.equal(await reach('app1'), true, 'app1 (10.8.0.2) is on the allowlist');
  assert.equal(await reach('app2'), false, 'app2 (10.7.0.2) is not: dropped');

  const read = await sh(['exec', NAME, 'iptables', '-w', '-S', 'APPCRANE-DB']);
  assert.deepEqual(read.stdout.trim().split('\n'), [
    '-N APPCRANE-DB',
    '-A APPCRANE-DB -s 10.8.0.2/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
  ]);
  const again = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(again.families.v4.state, 'unchanged', 'the real iptables -S output parses back to the same rules');
  assert.equal(again.families.v6.state, 'unchanged');

  const pending = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run }, pendingNames: new Set(['appcrane-live-db-production']) });
  assert.equal(pending.plan[0].state, 'open');
  assert.equal(await reach('app2'), true, 'while the app is starting its port fails open');
});

test('live: observe writes a counting rule and a rate-limited LOG instead of the DROP, lets the other container through and counts it; off empties the chain', { skip: skip || false, timeout: 240_000 }, async () => {
  setMode('observe');
  DC._resetDbChainForTests();
  const r = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.families.v4.state, 'applied');
  assert.equal(r.enforcement.state, 'observing');
  const read = await sh(['exec', NAME, 'iptables', '-w', '-S', 'APPCRANE-DB']);
  assert.deepEqual(read.stdout.trim().split('\n'), [
    '-N APPCRANE-DB',
    '-A APPCRANE-DB -s 10.8.0.2/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -m limit --limit 10/min --limit-burst 10 -j LOG --log-prefix "APPCRANE-DB-WOULD-DROP "',
  ]);
  assert.equal(await reach('app1'), true);
  assert.equal(await reach('app2'), true, 'observe never drops');
  const counters = await sh(['exec', NAME, 'iptables', '-w', '-L', 'APPCRANE-DB', '-v', '-x', '-n']);
  const again = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(again.families.v4.state, 'unchanged', `the real -S output of the observe lines parses back: ${read.stdout}`);
  assert.ok(again.would_drop.ports[45432] >= 1, `app2's connection is counted as a would-drop: ${JSON.stringify(again.would_drop)}\n${counters.stdout}`);
  const allowedOnly = again.would_drop.ports[45432];
  assert.equal(await reach('app1'), true);
  const third = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(third.would_drop.ports[45432], allowedOnly, 'the allowed container is not counted');

  setMode('off');
  const off = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
  assert.equal(off.status, 'ok', off.reason);
  assert.equal(off.enforcement.state, 'off');
  const empty = await sh(['exec', NAME, 'iptables', '-w', '-S', 'APPCRANE-DB']);
  assert.deepEqual(empty.stdout.trim().split('\n'), ['-N APPCRANE-DB']);
});

// The same plan written two ways must leave the same chain, byte for byte:
// AppCrane as root (iptables-restore from dbRules.dbRuleLines) and a non-root
// AppCrane through sudo running the real scripts/appcrane-db-chain.sh with
// dbRules.dbHelperArgs. Then a root sync must read the helper's chain back as
// its own (unchanged), so switching between the two never rewrites the chain.
test('live: the root-written and the helper-written APPCRANE-DB are byte-identical in enforce and observe, in both families', { skip: skip || false, timeout: 240_000 }, async () => {
  const cp = await sh(['exec', NAME, 'mkdir', '-p', '/usr/local/lib/appcrane']);
  assert.equal(cp.code, 0, cp.stderr);
  const copied = await sh(['cp', join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'appcrane-db-chain.sh'), `${NAME}:/usr/local/lib/appcrane/appcrane-db-chain.sh`]);
  assert.equal(copied.code, 0, copied.stderr);
  const app2 = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('live-db2', 'live-db2', 951, 'github')").run().lastInsertRowid;
  db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES ('mariadb', 'm', 'i', 43306, 'x')").run();
  db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', 'crane_a2', 'crane_a2_u', 'x')").run(app2);
  db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'mariadb', 'crane_a2m', 'crane_a2m_u', 'x')").run(app2);
  containers = [
    ['appcrane-live-db-production', '10.8.0.2,fd00:8::2', ''],
    ['appcrane-live-db2-production', '10.7.0.2,fd00:7::2', '='],
    ['appcrane-live-db2-sandbox', '10.6.0.3,', '='],
  ];
  const helperRun = async (cmd, args, opts = {}) => {
    if (cmd === 'sudo') {
      assert.equal(args[0], '-n');
      return sh(['exec', '-i', NAME, 'bash', ...args.slice(1)], { timeout: 30_000 });
    }
    return run(cmd, args, opts);
  };
  const dump = async () => {
    const v4 = await sh(['exec', NAME, 'iptables', '-w', '-S', 'APPCRANE-DB']);
    const v6 = await sh(['exec', NAME, 'ip6tables', '-w', '-S', 'APPCRANE-DB']);
    return `${v4.stdout}@@v6\n${v6.stdout}`;
  };
  const empty = async () => {
    for (const t of ['iptables', 'ip6tables']) assert.equal((await sh(['exec', NAME, t, '-w', '-F', 'APPCRANE-DB'])).code, 0);
  };
  for (const mode of ['enforce', 'observe']) {
    setMode(mode);
    DC._resetDbChainForTests();
    await empty();
    const root = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
    assert.equal(root.status, 'ok', root.reason);
    assert.deepEqual(root.plan.map(p => [p.port, p.state, p.allow]), [
      [43306, 'closed', ['10.6.0.3', '10.7.0.2', 'fd00:7::2']],
      [45432, 'closed', ['10.6.0.3', '10.7.0.2', '10.8.0.2', 'fd00:7::2', 'fd00:8::2']],
    ]);
    const byRoot = await dump();
    await empty();
    assert.notEqual(await dump(), byRoot, 'emptied between the two writes');
    const viaHelper = await DC.syncDbChain({ deps: { platform: 'linux', uid: 1000, run: helperRun, exists: () => true, readFile: () => null } });
    assert.equal(viaHelper.status, 'ok', viaHelper.reason);
    assert.equal(viaHelper.families.v4.via, 'helper');
    const byHelper = await dump();
    assert.equal(byHelper, byRoot, `${mode}: the helper wrote a different chain\n--- root\n${byRoot}\n--- helper\n${byHelper}`);
    const back = await DC.syncDbChain({ deps: { platform: 'linux', uid: 0, run } });
    assert.equal(back.families.v4.state, 'unchanged', `${mode}: root reads the helper's v4 chain as its own`);
    assert.equal(back.families.v6.state, 'unchanged', `${mode}: root reads the helper's v6 chain as its own`);
  }
  setMode('off');
  await empty();
});
