import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// APPCRANE-PUBLISH: the ACCEPT list AppCrane keeps for the host ports it
// publishes on 0.0.0.0. The host is faked through the exec seam: every call is
// recorded as (cmd, argv, stdin), and a tiny in-memory "kernel" answers
// `iptables -S APPCRANE-PUBLISH` and applies `iptables-restore --noflush`.
// The real kernel is exercised by test/host-firewall-live.test.js.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-firewall-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { assignPublicPort } = await import('../server/services/tcpIngress.js');
const R = await import('../server/services/hostFirewall/rules.js');
const D = await import('../server/services/hostFirewall/desired.js');
const P = await import('../server/services/hostFirewall/publishChain.js');
const HF = await import('../server/services/hostFirewall/index.js');
const HN = await import('../server/services/hostFirewall/hostNet.js');
const JH = await import('../server/services/jobHealth.js');
initDb();
const db = getDb();
after(() => { HF.stopHostFirewall(); rmSync(DATA_DIR, { recursive: true, force: true }); });

const ALLOWED_CMDS = new Set(['docker', 'ip', 'iptables', 'ip6tables', 'iptables-restore', 'ip6tables-restore']);

function fakeHost({ dockerPs = '', dockerFails = false, chains = {}, restoreFails = null, missing = [], ipAddr = null, sudo = null } = {}) {
  const calls = [];
  const kernel = { v4: chains.v4 ?? null, v6: chains.v6 ?? null };
  const famOf = (cmd) => (cmd.startsWith('ip6') ? 'v6' : 'v4');
  const run = async (cmd, args, opts = {}) => {
    calls.push({ cmd, args: [...args], input: opts.input ?? null });
    if (missing.includes(cmd)) return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    if (cmd === 'docker') {
      return dockerFails
        ? { code: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon', missing: false, error: null }
        : { code: 0, stdout: dockerPs, stderr: '', missing: false, error: null };
    }
    if (cmd === 'iptables' || cmd === 'ip6tables') {
      const lines = kernel[famOf(cmd)];
      if (lines === null) return { code: 1, stdout: '', stderr: `${cmd}: No chain/target/match by that name.\n`, missing: false, error: null };
      return { code: 0, stdout: [`-N ${R.CHAIN}`, ...lines].join('\n') + '\n', stderr: '', missing: false, error: null };
    }
    if (cmd.endsWith('-restore')) {
      if (restoreFails) return { code: 4, stdout: '', stderr: restoreFails, missing: false, error: null };
      kernel[famOf(cmd)] = opts.input.split('\n').filter(l => l.startsWith(`-A ${R.CHAIN} `));
      return { code: 0, stdout: '', stderr: '', missing: false, error: null };
    }
    if (cmd === 'ip' && ipAddr) {
      if (args[0] === '-o') return { code: 0, stdout: ipAddr, stderr: '', missing: false, error: null };
      return { code: 0, stdout: args[0] === '-6' ? '' : 'default via 203.0.113.1 dev eth0 proto dhcp\n', stderr: '', missing: false, error: null };
    }
    if (cmd === 'sudo' && sudo) return { missing: false, error: null, stdout: '', stderr: '', ...sudo };
    if (cmd === 'ip' || cmd === 'ss' || cmd === 'sudo') return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    throw new Error(`unexpected command ${cmd}`);
  };
  return { run, calls, kernel };
}

let seq = 0;
function mkApp({ ingress = 'tcp', dataPlanePort = null, protocol = null } = {}) {
  seq += 1;
  const slug = `fw-app-${seq}`;
  const id = db.prepare('INSERT INTO apps (name, slug, slot, source_type, ingress_type, data_plane_port, data_plane_protocol) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(slug, slug, 400 + seq, 'github', ingress, dataPlanePort, protocol).lastInsertRowid;
  return { id, slug };
}

beforeEach(() => {
  db.prepare('DELETE FROM app_host_ports').run();
  db.prepare('DELETE FROM apps').run();
  P._resetPublishChainForTests();
});

const ps = (...rows) => rows.map(r => r.join('|')).join('\n') + '\n';

test('exact argv for both families, rule text on stdin, never a shell', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const b = mkApp({ ingress: 'dual', dataPlanePort: 5080, protocol: 'udp' });
  assignPublicPort(db, b.id, 31820, 'sandbox');
  const h = fakeHost({
    dockerPs: ps(
      [`appcrane-${a.slug}-production`, 'true', a.slug, 'production', '127.0.0.1:4001->3000/tcp, 0.0.0.0:31001->3000/tcp, [::]:31001->3000/tcp'],
      [`appcrane-${b.slug}-sandbox`, 'true', b.slug, 'sandbox', '127.0.0.1:4002->3000/tcp, 0.0.0.0:31820->5080/udp, [::]:31820->5080/udp'],
    ),
  });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.status, 'ok', r.reason);

  const expectedInput = [
    '*filter',
    ':APPCRANE-PUBLISH - [0:0]',
    '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT',
    '-A APPCRANE-PUBLISH -p udp -m conntrack --ctstate DNAT --ctorigdstport 31820 --ctdir ORIGINAL -j ACCEPT',
    'COMMIT',
    '',
  ].join('\n');
  assert.deepEqual(h.calls.map(c => [c.cmd, c.args, c.input]), [
    ['docker', ['ps', '--format', '{{.Names}}|{{.Label "appcrane"}}|{{.Label "slug"}}|{{.Label "env"}}|{{.Ports}}'], null],
    ['ip', ['route', 'show', 'default'], null],
    ['ip', ['-6', 'route', 'show', 'default'], null],
    ['ip', ['-o', 'addr', 'show'], null],
    ['iptables', ['-w', '-S', 'APPCRANE-PUBLISH'], null],
    ['iptables-restore', ['-w', '--noflush'], expectedInput],
    ['iptables', ['-w', '-S', 'APPCRANE-PUBLISH'], null],
    ['ip6tables', ['-w', '-S', 'APPCRANE-PUBLISH'], null],
    ['ip6tables-restore', ['-w', '--noflush'], expectedInput],
    ['ip6tables', ['-w', '-S', 'APPCRANE-PUBLISH'], null],
  ]);
  for (const c of h.calls) {
    assert.ok(ALLOWED_CMDS.has(c.cmd), `no shell: ${c.cmd}`);
    assert.ok(Array.isArray(c.args));
  }
  assert.deepEqual(r.families.v4.state, 'applied');
  assert.deepEqual(r.families.v6.state, 'applied');
});

test('an unchanged chain is not rewritten', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const line = '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
  const h = fakeHost({ chains: { v4: [line], v6: [line] } });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.status, 'ok');
  assert.ok(!h.calls.some(c => c.cmd.endsWith('-restore')));
  assert.equal(r.families.v4.state, 'unchanged');
});

test('a rule AppCrane did not write is removed', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const ours = '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
  const h = fakeHost({ chains: { v4: [ours, '-A APPCRANE-PUBLISH -j ACCEPT'], v6: [ours] } });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.status, 'ok');
  assert.deepEqual(h.kernel.v4, [ours]);
  assert.equal(h.calls.filter(c => c.cmd === 'iptables-restore').length, 1);
  assert.equal(h.calls.filter(c => c.cmd === 'ip6tables-restore').length, 0);
});

test('a stray 0.0.0.0 publish is not accepted, and a known port held by the wrong container is withdrawn', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const b = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, b.id, 31002, 'production');
  const h = fakeHost({
    dockerPs: ps(
      [`appcrane-${a.slug}-production`, 'true', a.slug, 'production', '0.0.0.0:31001->3000/tcp'],
      ['rogue', '', '', '', '0.0.0.0:31500->80/tcp, 127.0.0.1:9000->9000/tcp'],
      ['intruder', '', '', '', '0.0.0.0:31002->80/tcp'],
    ),
  });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.accept.map(e => `${e.proto}/${e.port}`), ['tcp/31001']);
  assert.deepEqual(r.strays.map(s => `${s.container} ${s.proto}/${s.port}`), ['intruder tcp/31002', 'rogue tcp/31500']);
  assert.deepEqual(r.strays.find(s => s.container === 'intruder').claimed_by, { slug: b.slug, env: 'production' });
  assert.deepEqual(h.kernel.v4, ['-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT']);
  const restored = h.calls.find(c => c.cmd === 'iptables-restore').input;
  assert.ok(!restored.includes('31500') && !restored.includes('31002'), restored);
});

test('pending_port_release stays accepted until the container is recreated (udp, from docker)', async () => {
  const c = mkApp({ ingress: 'dual', dataPlanePort: 5080, protocol: 'udp' });
  assignPublicPort(db, c.id, 31003, 'production');
  db.prepare("UPDATE apps SET ingress_type = 'http' WHERE id = ?").run(c.id);
  const h = fakeHost({ dockerPs: ps([`appcrane-${c.slug}-production`, 'true', c.slug, 'production', '0.0.0.0:31003->5080/udp']) });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.deepEqual(r.accept.map(e => `${e.proto}/${e.port}/${e.reason}`), ['udp/31003/pending_port_release']);
  assert.deepEqual(r.strays, []);

  const after = fakeHost({ dockerPs: ps([`appcrane-${c.slug}-production`, 'true', c.slug, 'production', '127.0.0.1:4003->3000/tcp']) });
  const r2 = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: after.run } });
  assert.deepEqual(r2.accept, [], 'recreated without the publish: nothing to keep');
});

test('with Docker unreadable, the database decides: published and reserved ports both kept', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const c = mkApp({ ingress: 'dual', dataPlanePort: 5080, protocol: 'udp' });
  assignPublicPort(db, c.id, 31003, 'production');
  db.prepare("UPDATE apps SET ingress_type = 'http' WHERE id = ?").run(c.id);
  db.prepare("INSERT INTO app_host_ports (host_port, app_id, env, state) VALUES (31444, ?, 'production', 'draining')").run(a.id);
  const h = fakeHost({ dockerFails: true });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.docker, 'unreadable');
  assert.deepEqual(r.accept.map(e => `${e.proto}/${e.port}/${e.reason}`),
    ['tcp/31001/published', 'tcp/31444/draining', 'udp/31003/pending_port_release']);
});

test('http apps and dual apps without a data plane publish nothing', async () => {
  const a = mkApp({ ingress: 'http' });
  const d = mkApp({ ingress: 'dual', dataPlanePort: null });
  assignPublicPort(db, d.id, 31009, 'production');
  const h = fakeHost();
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.ok(a.id);
  assert.deepEqual(r.accept, []);
  assert.equal(h.calls.find(c => c.cmd === 'iptables-restore').input, '*filter\n:APPCRANE-PUBLISH - [0:0]\nCOMMIT\n');
});

test('off Linux nothing runs and the status is not applicable', async () => {
  const h = fakeHost();
  const r = await P.syncPublishChain({ deps: { platform: 'darwin', run: h.run } });
  assert.equal(r.status, 'not_applicable');
  assert.equal(h.calls.length, 0);
});

const STATE_ENFORCING = '# Written by AppCrane scripts/host-hardening.sh\napplied_at=2026-11-25T00:00:00Z\nresult=ok\next=eth0\nfamilies=IPv4+IPv6\ninput_mode=appcrane-input\ninput_policy=DROP\nallow=22/tcp 80/tcp 443/tcp 443/udp\napp_port=5001\nuncovered=\n';
const STATE_NO_DROP = `${STATE_ENFORCING}${HN.STATE_DROP_KEY}=no\n`;
const noState = () => null;
const helperAbsent = () => false;
const helperPresent = (p) => p === R.HELPER;

test('iptables missing: not applicable; root but refused by the kernel with the skeleton dropping: failed', async () => {
  const missing = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: fakeHost({ missing: ['iptables', 'ip6tables'] }).run } });
  assert.equal(missing.status, 'not_applicable');
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const denied = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, readFile: () => STATE_ENFORCING, run: fakeHost({ restoreFails: 'iptables-restore v1.8.10 (nf_tables): Permission denied (you must be root)\n' }).run } });
  assert.equal(denied.status, 'failed');
  assert.match(denied.reason, /cannot change the host firewall/);
});

test('not root: the helper is called through sudo -n with validated proto:port argv, and nothing else touches iptables', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const b = mkApp({ ingress: 'dual', dataPlanePort: 5080, protocol: 'udp' });
  assignPublicPort(db, b.id, 31820, 'sandbox');
  const h = fakeHost({ sudo: { code: 0 } });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperPresent, readFile: noState, run: h.run } });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.mode, 'helper');
  const sudo = h.calls.filter(c => c.cmd === 'sudo');
  assert.deepEqual(sudo.map(c => c.args), [['-n', '/usr/local/lib/appcrane/appcrane-publish-chain.sh', 'tcp:31001', 'udp:31820']]);
  assert.equal(sudo[0].input, null);
  assert.ok(!h.calls.some(c => c.cmd.startsWith('ip') && c.cmd !== 'ip'), 'no iptables call as non-root');
  assert.equal(r.families.v4.state, 'applied');
  assert.deepEqual(r.families.v6.entries, [{ proto: 'tcp', port: 31001 }, { proto: 'udp', port: 31820 }]);

  const empty = fakeHost({ sudo: { code: 0 } });
  db.prepare('DELETE FROM app_host_ports').run();
  db.prepare('DELETE FROM apps').run();
  await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperPresent, readFile: noState, run: empty.run } });
  assert.deepEqual(empty.calls.find(c => c.cmd === 'sudo').args, ['-n', R.HELPER], 'zero pairs empties the chain');
});

test('not root, no helper: not applicable when the skeleton does not drop, failed when it does', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const none = fakeHost();
  const absent = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperAbsent, readFile: noState, run: none.run } });
  assert.equal(absent.status, 'not_applicable', absent.reason);
  assert.match(absent.reason, /not running as root/);
  assert.ok(!none.calls.some(c => c.cmd === 'sudo'), 'no sudo call without the helper');

  const noDrop = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperAbsent, readFile: () => STATE_NO_DROP, run: fakeHost().run } });
  assert.equal(noDrop.status, 'not_applicable', 'skeleton installed without the DROP');

  const refused = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperPresent, readFile: () => STATE_NO_DROP, run: fakeHost({ sudo: { code: 1, stderr: 'sudo: a password is required\n' } }).run } });
  assert.equal(refused.status, 'not_applicable', 'sudoers rule missing');

  const dropping = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperAbsent, readFile: () => STATE_ENFORCING, run: fakeHost().run } });
  assert.equal(dropping.status, 'failed');
  assert.match(dropping.reason, /not running as root.*may be dropped/);
});

test('helper exit 2 (argument refused) and other helper errors are failures', async () => {
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const two = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperPresent, readFile: noState, run: fakeHost({ sudo: { code: 2, stderr: 'appcrane-publish-chain: bad argument\n' } }).run } });
  assert.equal(two.status, 'failed');
  assert.match(two.reason, /refused the port list/);
  const one = await P.syncPublishChain({ deps: { platform: 'linux', uid: 1000, exists: helperPresent, readFile: noState, run: fakeHost({ sudo: { code: 1, stderr: 'iptables-restore: line 3 failed\n' } }).run } });
  assert.equal(one.status, 'failed');
  assert.match(one.reason, /the helper failed/);
});

test('scheduler: not applicable on a non-root host without the helper: Job Health ok and no mail', async () => {
  JH._resetJobHealthForTests();
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  db.prepare("INSERT INTO users (name, email, username, role, active, kind) VALUES ('fwadmin', 'fwadmin@t.test', 'fwadmin', 'platform_admin', 1, 'human')").run();
  const before = db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'host-network'").get().n;
  const out = await HF.runHostNetwork({ withPosture: true, d: { platform: 'linux', uid: 1000, exists: helperAbsent, readFile: noState, run: fakeHost().run, probeImds: async () => ({ status: 'not_measured', detail: 'test' }) } });
  assert.equal(out.sync.status, 'not_applicable');
  assert.equal(out.posture, null);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'host-network'").get().n, before);
  const job = JH.getJobHealth().find(j => j.id === 'host-network');
  assert.notEqual(job.status, 'failing', JSON.stringify(job));
  db.prepare("DELETE FROM users WHERE username = 'fwadmin'").run();
});

test('the rule form carries --ctstate DNAT, and an older rule without it is rewritten', async () => {
  assert.equal(R.ruleLine({ proto: 'udp', port: 31003 }), '-A APPCRANE-PUBLISH -p udp -m conntrack --ctstate DNAT --ctorigdstport 31003 --ctdir ORIGINAL -j ACCEPT');
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const old = '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
  assert.deepEqual(R.parseChain(`-N APPCRANE-PUBLISH\n${old}\n`).foreign, [old]);
  const h = fakeHost({ chains: { v4: [old], v6: [old] } });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.equal(r.families.v4.state, 'applied');
  assert.deepEqual(h.kernel.v4, [R.ruleLine({ proto: 'tcp', port: 31001 })]);
});

test('managed DB servers on the bridge gateway and other private bindings are never strays; EXT addresses are', async () => {
  const net = { ext: { v4: 'eth0', v6: null }, addrs: HN.parseAddrs(IP_ADDR), extAddrs: new Set(['203.0.113.10']) };
  const containers = D.parseDockerPs(ps(
    ['appcrane-mdb-postgres', '', '', '', '172.17.0.1:15432->5432/tcp'],
    ['appcrane-mdb-redis', '', '', '', '172.18.0.1:16379->6379/tcp'],
    ['vpc-bound', '', '', '', '10.0.0.5:8080->80/tcp'],
    ['ext-bound', '', '', '', '203.0.113.10:8081->80/tcp'],
    ['wild', '', '', '', '0.0.0.0:8082->80/tcp, [::]:8082->80/tcp'],
  ));
  const d = D.computeDesired([], { ok: true, containers }, net);
  assert.deepEqual(d.strays.map(s => `${s.container} ${s.host_ip}`), ['ext-bound 203.0.113.10', 'wild 0.0.0.0']);
  const unknown = D.computeDesired([], { ok: true, containers }, { ext: {}, addrs: null, extAddrs: new Set() });
  assert.deepEqual(unknown.strays.map(s => s.container), ['ext-bound', 'wild'], 'addresses unreadable: private ranges still not public');

  const h = fakeHost({ ipAddr: IP_ADDR, dockerPs: ps(['appcrane-mdb-postgres', '', '', '', '172.17.0.1:15432->5432/tcp']) });
  const r = await P.syncPublishChain({ deps: { platform: 'linux', uid: 0, run: h.run } });
  assert.deepEqual(r.strays, []);
});

test('ruleLine refuses anything that is not tcp/udp and a port number', () => {
  assert.throws(() => R.ruleLine({ proto: 'tcp; reboot', port: 1 }));
  assert.throws(() => R.ruleLine({ proto: 'tcp', port: '31001 -j DROP' }));
  assert.throws(() => R.ruleLine({ proto: 'tcp', port: 70000 }));
});

const IP_ADDR = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '2: eth0    inet 203.0.113.10/24 metric 100 brd 203.0.113.255 scope global dynamic eth0\\       valid_lft 3000sec preferred_lft 3000sec',
  '2: eth0    inet6 2001:db8::10/64 scope global dynamic mngtmpaddr \\       valid_lft forever preferred_lft forever',
  '3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever',
  '4: br-1a2b3c    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-1a2b3c\\       valid_lft forever preferred_lft forever',
  '7: eth1@if9    inet 10.0.0.5/24 scope global eth1\\       valid_lft forever preferred_lft forever',
].join('\n') + '\n';

test('parseAddrs reads ip -o addr show, including veth-style names', () => {
  const m = HN.parseAddrs(IP_ADDR);
  assert.deepEqual(m.get('eth0'), ['203.0.113.10', '2001:db8::10']);
  assert.deepEqual(m.get('eth1'), ['10.0.0.5']);
  assert.deepEqual(m.get('br-1a2b3c'), ['172.18.0.1']);
});

test('parsePublicBindings: loopback dropped, IPv6 and ranges read', () => {
  assert.deepEqual(D.parsePublicBindings('127.0.0.1:4013->3000/tcp, 0.0.0.0:8080->10800/tcp, [::]:8080->10800/tcp, [::1]:9->9/tcp, 9229/tcp, 0.0.0.0:7000-7001->7000-7001/udp'), [
    { hostIp: '0.0.0.0', port: 8080, proto: 'tcp' },
    { hostIp: '::', port: 8080, proto: 'tcp' },
    { hostIp: '0.0.0.0', port: 7000, proto: 'udp' },
    { hostIp: '0.0.0.0', port: 7001, proto: 'udp' },
  ]);
});

function fakeSpawn() {
  const children = [];
  const fn = (cmd, args) => {
    const p = new EventEmitter();
    p.stdout = new PassThrough();
    p.stderr = new PassThrough();
    p.exitCode = null;
    p.kill = () => { p.exitCode = 0; p.emit('close', 0); };
    p.cmd = cmd; p.args = args;
    children.push(p);
    return p;
  };
  return { fn, children };
}

const until = async (cond, ms = 8000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (cond()) return true; await new Promise(r => setTimeout(r, 50)); }
  return false;
};

test('scheduler: syncs at start and after a docker event, records Job Health, never throws', async () => {
  JH._resetJobHealthForTests();
  const a = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, a.id, 31001, 'production');
  const h = fakeHost();
  const sp = fakeSpawn();
  const started = HF.startHostFirewall({ deps: { platform: 'linux', uid: 0, run: h.run, probeImds: async () => ({ status: 'not_measured', detail: 'test' }) }, spawn: sp.fn, backstopMs: 60 * 60_000 });
  assert.equal(started, true);
  assert.deepEqual([sp.children[0].cmd, sp.children[0].args], ['docker', [...HF.EVENTS_ARGS]]);
  await HF._waitForIdle();
  const restoresAtStart = h.calls.filter(c => c.cmd === 'iptables-restore').length;
  assert.equal(restoresAtStart, 1);
  let job = JH.getJobHealth().find(j => j.id === 'host-network');
  assert.equal(job.status, 'ok', JSON.stringify(job));

  const b = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, b.id, 31002, 'production');
  sp.children[0].stdout.write('{"status":"start","id":"x"}\n{"status":"die","id":"y"}\n');
  assert.ok(await until(() => h.calls.filter(c => c.cmd === 'iptables-restore').length === 2), 'one debounced sync for two events');
  await HF._waitForIdle();
  assert.match(h.calls.filter(c => c.cmd === 'iptables-restore').at(-1).input, /--ctorigdstport 31002/);

  HF.stopHostFirewall();
  const failing = fakeHost();
  const c = mkApp({ ingress: 'tcp' });
  assignPublicPort(db, c.id, 31003, 'production');
  const out = await HF.runHostNetwork({ withPosture: false, d: { platform: 'linux', uid: 1000, exists: helperAbsent, readFile: () => STATE_ENFORCING, run: failing.run } });
  assert.equal(out, null);
  job = JH.getJobHealth().find(j => j.id === 'host-network');
  assert.match(JSON.stringify(job), /not running as root/);
});
