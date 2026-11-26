import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import express from 'express';

// Host network posture: read from `iptables -S`, `ip route`, `ss` and
// `docker ps` through the exec seam (nothing is sent off the host), turned into
// findings, mailed to platform admins once per finding set per day, and served
// to platform admins only at GET /api/platform/host-network.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-network-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { assignPublicPort } = await import('../server/services/tcpIngress.js');
const PO = await import('../server/services/hostFirewall/posture.js');
const AL = await import('../server/services/hostFirewall/alerts.js');
const { createHostNetworkRouter } = await import('../server/routes/hostNetwork.js');
initDb();
const db = getDb();

const OURS = '-A APPCRANE-PUBLISH -p tcp -m conntrack --ctstate DNAT --ctorigdstport 31001 --ctdir ORIGINAL -j ACCEPT';
const SKELETON = [
  '-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN',
  '-A DOCKER-USER -d 169.254.169.254/32 -i docker0 -j DROP',
  '-A DOCKER-USER -d 169.254.169.254/32 -i br-+ -j DROP',
  '-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB',
  '-A DOCKER-USER -i eth0 -j APPCRANE-PUBLISH',
  '-A DOCKER-USER -i eth0 -j DROP',
  '-A DOCKER-USER -j RETURN',
];
const table = ({ input = 'DROP', dockerUser = SKELETON, chain = [OURS], extra = [] } = {}) => [
  `-P INPUT ${input}`, '-P FORWARD DROP', '-P OUTPUT ACCEPT',
  '-N APPCRANE-PUBLISH', '-N DOCKER-USER', '-N ufw-user-input',
  '-A FORWARD -j DOCKER-USER', '-A FORWARD -j DOCKER-FORWARD',
  ...dockerUser, ...chain, ...extra,
].join('\n') + '\n';

const IP_ADDR = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '2: eth0    inet 172.31.5.5/20 metric 100 brd 172.31.15.255 scope global dynamic eth0\\       valid_lft 3000sec preferred_lft 3000sec',
  '3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever',
].join('\n') + '\n';
const DENIED = { code: 4, stdout: '', stderr: 'iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\n', missing: false, error: null };

function host({ v4 = table(), v6 = table(), route4 = 'default via 172.31.0.1 dev eth0 proto dhcp src 172.31.5.5 metric 100\n', ss = 'LISTEN 0 511 127.0.0.1:5001 0.0.0.0:*\n', dockerPs = null, denied = false, broken = false } = {}) {
  const calls = [];
  const ok = (stdout) => ({ code: 0, stdout, stderr: '', missing: false, error: null });
  const run = async (cmd, args) => {
    calls.push([cmd, ...args]);
    if ((cmd === 'iptables' || cmd === 'ip6tables') && denied) return DENIED;
    if ((cmd === 'iptables' || cmd === 'ip6tables') && broken) return { code: 1, stdout: '', stderr: 'iptables: Resource temporarily unavailable.\n', missing: false, error: null };
    if (cmd === 'iptables') return args.includes('APPCRANE-PUBLISH') ? ok(`-N APPCRANE-PUBLISH\n${OURS}\n`) : ok(v4);
    if (cmd === 'ip6tables') return args.includes('APPCRANE-PUBLISH') ? ok(`-N APPCRANE-PUBLISH\n${OURS}\n`) : ok(v6);
    if (cmd === 'ip') return ok(args[0] === '-o' ? IP_ADDR : args[0] === '-6' ? '' : route4);
    if (cmd === 'ss') return ok(ss);
    if (cmd === 'docker') return ok(dockerPs ?? `appcrane-${APP}-production|true|${APP}|production|0.0.0.0:31001->3000/tcp\n`);
    throw new Error(`unexpected ${cmd}`);
  };
  return { run, calls };
}

const APP = 'posture-app';
const appId = db.prepare('INSERT INTO apps (name, slug, slot, source_type, ingress_type) VALUES (?, ?, ?, ?, ?)')
  .run(APP, APP, 700, 'github', 'tcp').lastInsertRowid;
assignPublicPort(db, appId, 31001, 'production');

beforeEach(() => {
  PO._resetPostureForTests();
  db.prepare("DELETE FROM email_queue WHERE source = 'host-network'").run();
});

const ids = (p) => p.findings.map(f => f.id);
const posture = (h, extra = {}) => PO.computePosture({ deps: { platform: 'linux', uid: 0, run: h.run, port: 5001, readFile: () => null, ...extra } });
const STATE = (extra = '') => `# Written by AppCrane scripts/host-hardening.sh\napplied_at=2026-11-25T00:00:00Z\nresult=ok\next=eth0\nfamilies=IPv4\ninput_mode=appcrane-input\ninput_policy=DROP\nallow=22/tcp 80/tcp 443/tcp 443/udp\napp_port=5001\nuncovered=\n${extra}`;
const ROGUE = (bind = '0.0.0.0') => `appcrane-${APP}-production|true|${APP}|production|0.0.0.0:31001->3000/tcp\nrogue||||${bind}:31999->80/tcp\n`;

test('a fully applied host reports no high or medium finding, and nothing runs off the host', async () => {
  const h = host();
  const p = await posture(h);
  assert.equal(p.applicable, true);
  assert.deepEqual(p.findings.filter(f => f.severity === 'high' || f.severity === 'medium'), []);
  assert.equal(p.families.v4.skeleton, 'applied');
  assert.deepEqual(p.desired.map(e => `${e.proto}/${e.port}`), ['tcp/31001']);
  for (const c of h.calls) assert.ok(['iptables', 'ip6tables', 'ip', 'ss', 'docker'].includes(c[0]), c.join(' '));
  assert.deepEqual(h.calls.find(c => c[0] === 'iptables'), ['iptables', '-w', '-S']);
  assert.deepEqual(h.calls.find(c => c[0] === 'ss'), ['ss', '-Hltn']);
});

test('no skeleton jump: "host network section not applied", and strays become high', async () => {
  const bare = table({ dockerUser: [] });
  const h = host({ v4: bare, v6: bare, dockerPs: `appcrane-${APP}-production|true|${APP}|production|0.0.0.0:31001->3000/tcp\nrogue||||0.0.0.0:31999->80/tcp\n` });
  const p = await posture(h);
  const f = p.findings.find(x => x.id === 'host-network-not-applied-v4');
  assert.equal(f.severity, 'high');
  assert.match(f.message, /Host network section not applied/);
  assert.equal(p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999').severity, 'high');
  assert.equal(p.findings[0].severity, 'high', 'findings come sorted, most severe first');
});

test('stray publish with the skeleton applied is low: the firewall drops it', async () => {
  const h = host({ dockerPs: `appcrane-${APP}-production|true|${APP}|production|0.0.0.0:31001->3000/tcp\nrogue||||0.0.0.0:31999->80/tcp\n` });
  const p = await posture(h);
  assert.equal(p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999').severity, 'low');
});

test('jump without a DROP, and a skeleton on the wrong interface', async () => {
  const noDrop = table({ dockerUser: SKELETON.filter(l => l !== '-A DOCKER-USER -i eth0 -j DROP') });
  let p = await posture(host({ v4: noDrop }));
  assert.ok(ids(p).includes('host-network-no-drop-v4'), ids(p).join());
  p = await posture(host({ route4: 'default via 10.0.0.1 dev ens5\n' }));
  assert.ok(ids(p).includes('host-network-interface-v4'), ids(p).join());
});

test('chain drift is reported when the chain differs from the desired list', async () => {
  const p = await posture(host({ v4: table({ chain: [] }) }));
  assert.ok(ids(p).includes('publish-chain-drift-v4'));
  assert.ok(!ids(p).includes('publish-chain-drift-v6'));
});

test("AppCrane's port: loopback only is fine; 0.0.0.0 with INPUT ACCEPT or an explicit ACCEPT is high", async () => {
  let p = await posture(host());
  assert.ok(!ids(p).includes('appcrane-port-public'));
  p = await posture(host({ ss: 'LISTEN 0 511 0.0.0.0:5001 0.0.0.0:*\n' }));
  assert.ok(!ids(p).includes('appcrane-port-public'), 'INPUT DROP with no accept for 5001');
  p = await posture(host({ ss: 'LISTEN 0 511 0.0.0.0:5001 0.0.0.0:*\n', v4: table({ input: 'ACCEPT' }) }));
  assert.equal(p.findings.find(f => f.id === 'appcrane-port-public')?.severity, 'high');
  p = await posture(host({ ss: 'LISTEN 0 511 *:5001 *:*\n', v4: table({ extra: ['-A INPUT -j ufw-user-input', '-A ufw-user-input -p tcp -m tcp --dport 5001 -j ACCEPT'] }) }));
  assert.ok(ids(p).includes('appcrane-port-public'));
  p = await posture(host({ ss: 'LISTEN 0 511 *:5001 *:*\n', v4: table({ extra: ['-A INPUT -j ufw-user-input', '-A ufw-user-input -s 10.0.0.0/8 -p tcp -m tcp --dport 5001 -j ACCEPT'] }) }));
  assert.ok(!ids(p).includes('appcrane-port-public'), 'a source-restricted accept is not the internet');
});

test('IMDS exposure from the cached probe is a high finding with the fix', async () => {
  PO.setCachedImds({ status: 'exposed', detail: 'from a bridge container: IMDSv2 token request 200', token: '200', v1: null });
  const p = await posture(host());
  const f = p.findings.find(x => x.id === 'imds-exposed');
  assert.equal(f.severity, 'high');
  assert.match(f.fix, /http-put-response-hop-limit 1/);
});

test('a failed chain sync is high, with the not-root reason', async () => {
  const p = await posture(host(), { lastSync: { status: 'failed', reason: 'AppCrane cannot change the host firewall (v4): it is not running as root.' } });
  assert.equal(p.findings.find(x => x.id === 'publish-chain-sync-failed').severity, 'high');
});

test('off Linux: not applicable and nothing runs', async () => {
  const h = host();
  const p = await PO.computePosture({ deps: { platform: 'darwin', run: h.run } });
  assert.equal(p.applicable, false);
  assert.equal(h.calls.length, 0);
});

function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare("INSERT INTO users (name, email, username, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${tag}`, `u${tag}@t.test`, `u${tag}`, role, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return { id, token, email: `u${tag}@t.test` };
}
const ADMIN = mkUser('platform_admin');
const PLAIN = mkUser('user');

test('mail: once per finding set per day per admin; a new set or a new day mails again', async () => {
  const bare = table({ dockerUser: [] });
  const p = await posture(host({ v4: bare, v6: bare }));
  const now = Date.UTC(2026, 10, 25, 12);
  const first = AL.mailPostureFindings(p, { now });
  assert.ok(first.includes(ADMIN.email));
  assert.ok(!first.includes(PLAIN.email));
  assert.deepEqual(AL.mailPostureFindings(p, { now: now + 3600_000 }), [], 'same set, same day');
  const more = { findings: [...p.findings, { id: 'imds-exposed', severity: 'high', message: 'm', fix: null }] };
  assert.ok(AL.mailPostureFindings(more, { now: now + 3600_000 }).includes(ADMIN.email), 'new set');
  assert.ok(AL.mailPostureFindings(p, { now: now + 24 * 3600_000 }).includes(ADMIN.email), 'next day');
  const row = db.prepare("SELECT subject, body_text FROM email_queue WHERE source = 'host-network' AND to_email = ? ORDER BY id LIMIT 1").get(ADMIN.email);
  assert.match(row.subject, /Host network/);
  assert.match(row.body_text, /Host network section not applied/);
  assert.deepEqual(AL.mailPostureFindings({ findings: [{ id: 'x', severity: 'low', message: 'm' }] }, { now }), [], 'low findings are not mailed');
});

const app = express();
app.use(express.json());
app.use('/api/platform', createHostNetworkRouter({ platform: 'linux', uid: 0, run: host().run }));
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); rmSync(DATA_DIR, { recursive: true, force: true }); });

async function get(token) {
  const res = await fetch(`${BASE}/api/platform/host-network`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  let body = null;
  try { body = await res.json(); } catch (_) {}
  return { status: res.status, body };
}

test('route: platform admin only (401 without a session, 403 for a user), posture + chain + desired', async () => {
  assert.equal((await get(null)).status, 401);
  const plain = await get(PLAIN.token);
  assert.equal(plain.status, 403);
  assert.equal(plain.body?.posture, undefined);
  const r = await get(ADMIN.token);
  assert.equal(r.status, 200);
  assert.equal(r.body.posture.applicable, true);
  assert.ok(Array.isArray(r.body.posture.findings));
  assert.deepEqual(r.body.chain.v4.entries, [{ proto: 'tcp', port: 31001 }]);
  assert.deepEqual(r.body.desired.map(e => `${e.proto}/${e.port}/${e.slug}/${e.env}`), [`tcp/31001/${APP}/production`]);
  assert.equal(r.body.posture.families.v4.table, undefined, 'internal parse object is not serialized');
});

test('P1: a managed DB server on the bridge gateway is not a stray; a wildcard stray without the skeleton says reachable', async () => {
  const bare = table({ dockerUser: [] });
  let p = await posture(host({ v4: bare, v6: bare, dockerPs: ROGUE('172.17.0.1') }));
  assert.ok(!ids(p).some(i => i.startsWith('stray-publish:')), ids(p).join());
  assert.deepEqual(p.strays, []);
  p = await posture(host({ v4: bare, v6: bare, dockerPs: ROGUE('172.31.5.5') }));
  assert.equal(p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999')?.severity, 'high', 'an address on EXT is public');
  p = await posture(host({ dockerPs: ROGUE() }));
  const low = p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999');
  assert.equal(low.severity, 'low');
  assert.doesNotMatch(low.message, /internet/);
  assert.match(low.message, /drops it from eth0/);
  p = await posture(host({ broken: true, dockerPs: ROGUE() }));
  const um = p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999');
  assert.equal(um.severity, 'medium');
  assert.doesNotMatch(um.message, /reachable from the internet/);
});

test('P2: INPUT is evaluated in order: an early app-port DROP wins over a later ACCEPT, and the reverse is reported', async () => {
  const listen = 'LISTEN 0 511 0.0.0.0:5001 0.0.0.0:*\n';
  const appcraneInput = [
    '-N APPCRANE-INPUT', '-A INPUT -j APPCRANE-INPUT',
    '-A APPCRANE-INPUT -i lo -j ACCEPT', '-A APPCRANE-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    '-A APPCRANE-INPUT -i docker0 -j ACCEPT', '-A APPCRANE-INPUT -i br-+ -j ACCEPT',
    '-A APPCRANE-INPUT -p tcp -m tcp --dport 5001 -j DROP', '-A APPCRANE-INPUT -p tcp -m tcp --dport 22 -j ACCEPT', '-A APPCRANE-INPUT -j RETURN',
  ];
  let p = await posture(host({ ss: listen, v4: table({ input: 'ACCEPT', extra: [...appcraneInput, '-A INPUT -p tcp -m tcp --dport 5001 -j ACCEPT'] }) }));
  assert.ok(!ids(p).includes('appcrane-port-public'), 'refused mode: policy ACCEPT but APPCRANE-INPUT drops 5001 first');

  const ufw = [
    '-N ufw-before-input', '-N ufw-user-input', '-A INPUT -j ufw-before-input',
    '-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', '-A ufw-before-input -m conntrack --ctstate INVALID -j DROP',
    '-A ufw-before-input -j ufw-user-input',
  ];
  const deny = '-A ufw-user-input -i eth0 -p tcp -m tcp --dport 5001 -j DROP';
  const allow = '-A ufw-user-input -p tcp -m tcp --dport 5001 -j ACCEPT';
  p = await posture(host({ ss: listen, v4: table({ extra: [...ufw, deny, allow] }) }));
  assert.ok(!ids(p).includes('appcrane-port-public'), 'a prepended ufw deny wins over an older allow');
  p = await posture(host({ ss: listen, v4: table({ extra: [...ufw, allow, deny] }) }));
  const f = p.findings.find(x => x.id === 'appcrane-port-public');
  assert.equal(f?.severity, 'high');
  assert.match(f.message, /--dport 5001 -j ACCEPT/);

  p = await posture(host({ ss: 'LISTEN 0 511 172.17.0.1:5001 0.0.0.0:*\n', v4: table({ input: 'ACCEPT' }) }));
  assert.ok(!ids(p).includes('appcrane-port-public'), 'listening on the bridge gateway only is not public');
});

test('P2 + B1: non-root posture reads host hardening state for the skeleton and the app port', async () => {
  const listen = 'LISTEN 0 511 0.0.0.0:5001 0.0.0.0:*\n';
  let p = await posture(host({ denied: true, ss: listen, dockerPs: ROGUE() }), { uid: 1000, readFile: () => STATE() });
  assert.equal(p.families.v4.skeleton, 'applied');
  assert.equal(p.families.v4.skeleton_source, 'state');
  assert.equal(p.findings.find(x => x.id === 'firewall-unreadable-v4').severity, 'info');
  assert.ok(!ids(p).includes('appcrane-port-public'));
  assert.ok(!ids(p).includes('appcrane-port-unmeasured'), 'state says APPCRANE-INPUT drops the app port');
  assert.equal(p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999').severity, 'low');
  assert.equal(p.host_network_state.input_mode, 'appcrane-input');
  assert.deepEqual(p.findings.filter(x => x.severity === 'high' || x.severity === 'medium'), []);

  p = await posture(host({ denied: true, ss: listen, dockerPs: ROGUE() }), { uid: 1000, readFile: () => STATE('publish_drop=no\n') });
  assert.equal(p.findings.find(x => x.id === 'host-network-not-applied-v4').severity, 'high');
  assert.match(p.findings.find(x => x.id === 'host-network-not-applied-v4').message, /according to host hardening's state file/);
  assert.equal(p.findings.find(x => x.id === 'stray-publish:rogue:tcp/31999').severity, 'high');

  p = await posture(host({ denied: true, ss: listen, dockerPs: ROGUE() }), { uid: 1000, readFile: () => STATE('docker_user=interim\n') });
  assert.equal(p.families.v4.skeleton, 'not_applied', 'the interim unit owns DOCKER-USER: nothing jumps to APPCRANE-PUBLISH');

  p = await posture(host({ denied: true, ss: listen }), { uid: 1000, readFile: () => STATE().replace('input_mode=appcrane-input', 'input_mode=none') });
  assert.ok(ids(p).includes('appcrane-port-unmeasured'));
});

test('inputEval: jumps, RETURN, negation, unknown matches skipped and reported', async () => {
  const IE = await import('../server/services/hostFirewall/inputEval.js');
  const t = IE.parseRules([
    '-P INPUT DROP', '-N A', '-N B',
    '-A INPUT -j A', '-A A -s 10.0.0.0/8 -j ACCEPT', '-A A -j B', '-A B -p tcp ! --dport 5001 -j ACCEPT', '-A B -j RETURN',
    '-A INPUT -m set --match-set allow src -j ACCEPT', '-A INPUT -p tcp -m multiport --dports 80,5000:5002 -m comment --comment "web ports" -j ACCEPT',
  ].join('\n'));
  const r = IE.evaluateInput(t, { proto: 'tcp', dport: 5001, iface: 'eth0' });
  assert.equal(r.verdict, 'ACCEPT');
  assert.match(r.by, /--dports 80,5000:5002/);
  assert.equal(r.uncertain.length, 1);
  assert.equal(IE.evaluateInput(t, { proto: 'tcp', dport: 22, iface: 'eth0' }).verdict, 'ACCEPT');
  assert.equal(IE.evaluateInput(t, { proto: 'udp', dport: 5001, iface: 'eth0' }).verdict, 'DROP', 'no tcp rule matches udp; the policy decides');
});
