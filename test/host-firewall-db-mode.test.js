import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import express from 'express';

// APPCRANE-DB v2.147.0 fixes: db_allowlist_mode (off | observe | enforce,
// default observe), would-drop counters, enforcement read from DOCKER-USER or
// host hardening's state file, the scope label a container was started with,
// the wake start, the docker events reconnect and an unusable ip6tables.
// iptables and Docker go through the exec seam (the kernel's real output for
// the observe lines is in test/host-firewall-db-live.test.js); the label is
// read from a real Docker when one is reachable.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-db-mode-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { SANDBOX_TENANT, setSeparateSandboxDb } = await import('../server/services/sandboxDb.js');
const DM = await import('../server/services/hostFirewall/dbMode.js');
const DR = await import('../server/services/hostFirewall/dbRules.js');
const DD = await import('../server/services/hostFirewall/dbDesired.js');
const DC = await import('../server/services/hostFirewall/dbChain.js');
const HF = await import('../server/services/hostFirewall/index.js');
const PO = await import('../server/services/hostFirewall/posture.js');
const { defaultRun } = await import('../server/services/hostFirewall/exec.js');
const { createHostNetworkRouter } = await import('../server/routes/hostNetwork.js');
const wake = await import('../server/services/envWake.js');
const { setSleepState } = await import('../server/services/envSleepState.js');
initDb();
const db = getDb();

beforeEach(() => {
  for (const t of ['managed_databases', 'managed_db_servers', 'app_settings', 'apps']) db.prepare(`DELETE FROM ${t}`).run();
  db.prepare("DELETE FROM settings WHERE key = 'db_allowlist_mode'").run();
  DC._resetDbChainForTests();
});

let seq = 0;
const mkApp = (slug) => db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(slug, slug, 700 + (++seq)).lastInsertRowid;
const server = (engine, port) => db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES (?, ?, 'img', ?, 'x')").run(engine, `appcrane-db-${engine}`, port);
function row(appId, engine, { tenant = '', port = null } = {}) {
  seq += 1;
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc, host_port, container_name)
              VALUES (?, ?, ?, ?, ?, 'x', ?, ?)`).run(appId, tenant, engine, `db${seq}`, `u${seq}`, port, port ? `appcrane-db-redis-${seq}` : null);
}
const setMode = (m) => db.prepare("INSERT INTO settings (key, value) VALUES ('db_allowlist_mode', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(m);

const JUMP = '-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB';
const ok = (stdout = '') => ({ code: 0, stdout, stderr: '', missing: false, error: null });

// docker: ps lists names, inspect answers {name: {ips, status, scope}}.
// iptables: one APPCRANE-DB per family, DOCKER-USER, and `-L -v -x -n` text.
function fakeHost({ containers = {}, jump = { v4: [JUMP], v6: [JUMP] }, counters = { v4: '', v6: '' }, v6Fails = null, sudo = null } = {}) {
  const calls = [];
  const kernel = { v4: [], v6: [] };
  const fam = (cmd) => (cmd.startsWith('ip6') ? 'v6' : 'v4');
  const run = async (cmd, args, opts = {}) => {
    calls.push({ cmd, args: [...args], input: opts.input ?? null });
    if (cmd === 'docker' && args[0] === 'ps') return ok(Object.keys(containers).join('\n') + '\n');
    if (cmd === 'docker' && args[0] === 'inspect') {
      return ok(args.slice(3).map((n) => {
        const c = containers[n];
        return `id-${n}|/${n}|${c.status || 'running'}|appcrane-apps|${(c.ips || []).map(ip => `${ip},;`).join('')}|${c.scope === undefined ? '' : `=${c.scope}`}`;
      }).join('\n') + '\n');
    }
    if (cmd.startsWith('ip6') && v6Fails) return { code: 3, stdout: '', stderr: v6Fails, missing: false, error: null };
    if (cmd.endsWith('-restore')) { kernel[fam(cmd)] = opts.input.split('\n').filter(l => l.startsWith('-A APPCRANE-DB ')); return ok(); }
    if (args.includes('DOCKER-USER')) return ok(['-N DOCKER-USER', ...jump[fam(cmd)]].join('\n') + '\n');
    if (args.includes('-L')) return ok(counters[fam(cmd)]);
    if (cmd === 'iptables' || cmd === 'ip6tables') return ok(['-N APPCRANE-DB', ...kernel[fam(cmd)]].join('\n') + '\n');
    if (cmd === 'sudo' && sudo) return { missing: false, error: null, stdout: '', stderr: '', ...sudo };
    throw new Error(`unexpected ${cmd} ${args.join(' ')}`);
  };
  return { run, calls, kernel };
}
const root = (h, extra = {}) => ({ platform: 'linux', uid: 0, run: h.run, ...extra });

// `iptables -L APPCRANE-DB -v -x -n` as ubuntu:24.04's iptables 1.8.10 prints
// it (measured in the live test): prot is 6, the counting rule has no target.
const listing = (port, ret, count, log) => [
  'Chain APPCRANE-DB (1 references)',
  '    pkts      bytes target     prot opt in     out     source               destination',
  `       ${ret}       60 RETURN     6    --  *      *       172.18.0.5           0.0.0.0/0            ctorigdstport ${port} ctdir ORIGINAL`,
  `       ${count}      180            6    --  *      *       0.0.0.0/0            0.0.0.0/0            ctorigdstport ${port} ctdir ORIGINAL`,
  `       ${log}       60 LOG        6    --  *      *       0.0.0.0/0            0.0.0.0/0            ctorigdstport ${port} ctdir ORIGINAL limit: avg 10/min burst 10 LOG flags 0 level 4 prefix "APPCRANE-DB-WOULD-DROP "`,
  '',
].join('\n');

test('mode: default observe, unknown values fall back to observe, and only a move towards off weakens', () => {
  assert.equal(DM.dbAllowlistMode(db), 'observe', 'no setting row');
  setMode('ENFORCE');
  assert.equal(DM.dbAllowlistMode(db), 'enforce');
  setMode('drop-everything');
  assert.equal(DM.dbAllowlistMode(db), 'observe');
  assert.equal(DM.dbModeWeakens('enforce', 'observe'), true);
  assert.equal(DM.dbModeWeakens('enforce', 'off'), true);
  assert.equal(DM.dbModeWeakens('observe', 'off'), true);
  assert.equal(DM.dbModeWeakens('observe', 'enforce'), false);
  assert.equal(DM.dbModeWeakens('off', 'observe'), false);
  assert.equal(DM.dbModeWeakens(null, 'off'), true, 'an unset setting is observe');
});

test('observe (the default): RETURN per source, a counting rule and a rate-limited LOG instead of the DROP; it reads back unchanged', async () => {
  server('postgres', 45432);
  row(mkApp('ob'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-ob-production': { ips: ['172.18.0.5'] } } });
  const r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.allowlist_mode, 'observe');
  assert.deepEqual(h.kernel.v4, [
    '-A APPCRANE-DB -s 172.18.0.5/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -m limit --limit 10/min --limit-burst 10 -j LOG --log-prefix "APPCRANE-DB-WOULD-DROP "',
  ]);
  assert.ok(!h.kernel.v4.some(l => / -j DROP$/.test(l)), 'observe never drops');
  assert.deepEqual(r.enforcement.state, 'observing');
  const again = await DC.syncDbChain({ deps: root(h) });
  assert.equal(again.families.v4.state, 'unchanged');
  assert.equal(again.families.v6.state, 'unchanged');
});

test('observe counters: per-port would-drops add up across syncs and survive the zeroing a rewrite causes', async () => {
  server('postgres', 45432);
  row(mkApp('ct'), 'postgres');
  const containers = { 'appcrane-ct-production': { ips: ['172.18.0.5'] } };
  const counters = { v4: '', v6: '' };
  const h = fakeHost({ containers, counters });
  await DC.syncDbChain({ deps: root(h) });
  counters.v4 = listing(45432, 9, 5, 5);
  let r = await DC.syncDbChain({ deps: root(h) });
  assert.deepEqual(r.would_drop.ports, { 45432: 5 }, 'the counting rule, not the RETURN or the rate-limited LOG');
  counters.v4 = listing(45432, 9, 8, 6);
  r = await DC.syncDbChain({ deps: root(h) });
  assert.deepEqual(r.would_drop.ports, { 45432: 8 });
  containers['appcrane-ct-production'].ips = ['172.18.0.6'];
  counters.v4 = listing(45432, 9, 9, 6);
  r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.families.v4.state, 'applied', 'the new address rewrote the chain, zeroing its counters');
  counters.v4 = listing(45432, 0, 12, 10);
  r = await DC.syncDbChain({ deps: root(h) });
  assert.deepEqual(r.would_drop.ports, { 45432: 21 }, '9 before the rewrite and 12 after it');
  assert.ok(h.calls.some(c => c.cmd === 'iptables' && c.args.join(' ') === '-w -L APPCRANE-DB -v -x -n'));
  const view = PO.dbAllowlistView(DC.getLastDbSync());
  assert.equal(view.allowlist_mode, 'observe');
  assert.equal(view.enforcement.state, 'observing');
  assert.deepEqual(view.ports.map(p => [p.port, p.sources.join(','), p.would_drop]), [[45432, '172.18.0.6', 21]]);
});

test('enforce writes the DROP; off empties the chain, even one full of rules', async () => {
  server('postgres', 45432);
  row(mkApp('of'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-of-production': { ips: ['172.18.0.5'] } } });
  setMode('enforce');
  let r = await DC.syncDbChain({ deps: root(h) });
  assert.ok(h.kernel.v4.includes('-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP'));
  assert.equal(r.enforcement.state, 'enforced');
  assert.equal(r.would_drop, null);
  setMode('off');
  r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.status, 'ok');
  assert.deepEqual(h.kernel.v4, []);
  assert.deepEqual(h.kernel.v6, []);
  assert.equal(r.families.v4.state, 'applied');
  assert.equal(r.enforcement.state, 'off');
});

test('helper: observe passes log:<port>, enforce close:<port>, off no port at all', async () => {
  server('postgres', 45432);
  row(mkApp('hl'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-hl-production': { ips: ['172.18.0.5'] } }, sudo: { code: 0 } });
  const d = { platform: 'linux', uid: 1000, exists: () => true, run: h.run, readFile: () => 'db_chain=yes\n' };
  const argv = () => h.calls.filter(c => c.cmd === 'sudo').at(-1).args;
  let r = await DC.syncDbChain({ deps: d });
  assert.deepEqual(argv(), ['-n', DR.DB_HELPER, 'allow:45432:172.18.0.5', 'log:45432']);
  assert.equal(r.enforcement.state, 'observing');
  assert.match(r.would_drop.why, /not root/);
  setMode('enforce');
  r = await DC.syncDbChain({ deps: d });
  assert.deepEqual(argv(), ['-n', DR.DB_HELPER, 'allow:45432:172.18.0.5', 'close:45432']);
  assert.deepEqual(r.jump, { v4: 'present', v6: 'present', source: 'state' });
  assert.equal(r.enforcement.state, 'enforced');
  setMode('off');
  await DC.syncDbChain({ deps: d });
  assert.deepEqual(argv(), ['-n', DR.DB_HELPER]);
  assert.equal(h.calls.filter(c => c.cmd.startsWith('ip')).length, 0, 'not root: never iptables');
});

test('enforcement: never reported enforced when DOCKER-USER does not jump to APPCRANE-DB, by the rules or by the state file', async () => {
  server('postgres', 45432);
  row(mkApp('ju'), 'postgres');
  setMode('enforce');
  const containers = { 'appcrane-ju-production': { ips: ['172.18.0.5'] } };
  let r = await DC.syncDbChain({ deps: root(fakeHost({ containers, jump: { v4: ['-A DOCKER-USER -j RETURN'], v6: [] } })) });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.jump, { v4: 'absent', v6: 'absent', source: 'rules' });
  assert.equal(r.enforcement.state, 'not_enforced');
  assert.match(r.enforcement.why, /does not jump to APPCRANE-DB/);

  const helper = fakeHost({ containers, sudo: { code: 0 } });
  const d = (state) => ({ platform: 'linux', uid: 1000, exists: () => true, run: helper.run, readFile: () => state });
  r = await DC.syncDbChain({ deps: d('docker_user=interim\ndb_chain=no\n') });
  assert.equal(r.enforcement.state, 'not_enforced');
  assert.match(r.enforcement.why, /db_chain=no/);
  r = await DC.syncDbChain({ deps: d(null) });
  assert.equal(r.enforcement.state, 'unknown', 'no state file and no readable rules: unknown, not enforced');

  r = await DC.syncDbChain({ deps: { platform: 'linux', uid: 1000, exists: () => false, run: helper.run, readFile: () => 'db_chain=yes\n' } });
  assert.equal(r.status, 'not_applicable');
  assert.equal(r.enforcement.state, 'not_enforced', 'the jump is there but AppCrane cannot write the chain');
  assert.match(r.enforcement.why, /cannot write APPCRANE-DB/);
});

test('ip6tables that cannot initialize (kernel booted with ipv6.disable=1): v6 is not_applicable and the sync is ok', async () => {
  server('postgres', 45432);
  row(mkApp('v6'), 'postgres');
  setMode('enforce');
  const msg = "ip6tables v1.8.7 (legacy): can't initialize ip6tables table `filter': Address family not supported by protocol\nPerhaps ip6tables or your kernel needs to be upgraded.\n";
  const h = fakeHost({ containers: { 'appcrane-v6-production': { ips: ['172.18.0.5'] } }, v6Fails: msg });
  const r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.families.v4.state, 'applied');
  assert.equal(r.families.v6.state, 'not_applicable');
  assert.equal(r.jump.v6, 'not_applicable');
  assert.equal(r.enforcement.state, 'enforced');
  const other = await DC.syncDbChain({ deps: root(fakeHost({ containers: { 'appcrane-v6-production': { ips: ['172.18.0.5'] } }, v6Fails: 'ip6tables: Resource temporarily unavailable\n' })) });
  assert.equal(other.status, 'failed', 'any other ip6tables error is still a failure');
});

test('scope label: a running container keeps the scope it was started with when Separate sandbox database is flipped', async () => {
  const rd = mkApp('lb');
  row(rd, 'redis', { port: 46380 });
  row(rd, 'redis', { tenant: SANDBOX_TENANT, port: 46381 });
  setMode('enforce');
  const containers = {
    'appcrane-lb-production': { ips: ['172.18.0.5'], scope: '' },
    'appcrane-lb-sandbox': { ips: ['172.18.0.6'], scope: '' },
  };
  setSeparateSandboxDb(db, rd, true);
  const r = await DC.syncDbChain({ deps: root(fakeHost({ containers })) });
  const by = Object.fromEntries(r.plan.map(p => [p.port, p.allow.join(',')]));
  assert.equal(by[46380], '172.18.0.5,172.18.0.6', 'the sandbox still holds the shared REDIS_URL it was started with');
  assert.equal(by[46381], '', 'and not the sandbox scope it will get on its next deploy');
  assert.deepEqual(r.plan[0].scopes['appcrane-lb-sandbox'], { scope: '', source: 'label' });

  containers['appcrane-lb-sandbox'].scope = SANDBOX_TENANT;
  setSeparateSandboxDb(db, rd, false);
  const r2 = await DC.syncDbChain({ deps: root(fakeHost({ containers })) });
  const by2 = Object.fromEntries(r2.plan.map(p => [p.port, p.allow.join(',')]));
  assert.equal(by2[46380], '172.18.0.5', 'labelled sandbox scope: off the shared port whatever the setting says');
  assert.equal(by2[46381], '172.18.0.6');

  delete containers['appcrane-lb-sandbox'].scope;
  const r3 = await DC.syncDbChain({ deps: root(fakeHost({ containers })) });
  const by3 = Object.fromEntries(r3.plan.map(p => [p.port, p.allow.join(',')]));
  assert.equal(by3[46380], '172.18.0.5,172.18.0.6', 'no label: the setting decides (off: shared)');
  assert.equal(by3[46381], '172.18.0.6', 'and a deployhub.json sandbox scope is not stored, so it keeps its own too');
  assert.deepEqual(r3.plan[0].scopes['appcrane-lb-sandbox'], { scope: null, source: 'setting' });
});

let dockerSkip = null;
try { execFileSync('docker', ['version', '--format', '{{.Server.Os}}'], { timeout: 15_000, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { dockerSkip = `Docker is not reachable: ${String(e.stderr || e.message).split('\n')[0]}`; }

test('scope label read from a real Docker: empty value, a sandbox value and no label at all are told apart', { skip: dockerSkip || false, timeout: 120_000 }, async () => {
  const tag = randomBytes(3).toString('hex');
  const names = [`crane-dbscope-a-${tag}`, `crane-dbscope-b-${tag}`, `crane-dbscope-c-${tag}`];
  const labels = [['--label', `${DD.DB_SCOPE_LABEL}=`], ['--label', `${DD.DB_SCOPE_LABEL}=${SANDBOX_TENANT}`], []];
  try {
    names.forEach((n, i) => execFileSync('docker', ['create', '--name', n, ...labels[i], 'ubuntu:24.04', 'true'], { stdio: ['ignore', 'pipe', 'pipe'] }));
    const r = await defaultRun('docker', ['inspect', '--format', DD.INSPECT_FORMAT, ...names]);
    assert.equal(r.code, 0, r.stderr);
    const facts = DD.parseInspect(r.stdout);
    assert.deepEqual(names.map(n => facts.get(n).scope), ['', SANDBOX_TENANT, null]);
  } finally {
    try { execFileSync('docker', ['rm', '-f', ...names], { stdio: ['ignore', 'pipe', 'pipe'] }); } catch (_) {}
  }
});

test('wake: docker start runs with the app\'s database ports held open, and the address is closed in after it', async () => {
  server('postgres', 45432);
  const id = mkApp('wk');
  row(id, 'postgres');
  setMode('enforce');
  const h = fakeHost({ containers: { 'appcrane-wk-production': { ips: ['172.18.0.9'] } } });
  // As the sleep left it: the address the container had before, since given back.
  h.kernel.v4 = [
    '-A APPCRANE-DB -s 172.18.0.3/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
  ];
  const order = [];
  const run = async (cmd, args, opts) => {
    if (cmd.endsWith('-restore') && cmd === 'iptables-restore') order.push(`write:${/ 45432 /.test(opts.input) ? 'closed' : 'open'}`);
    return h.run(cmd, args, opts);
  };
  DC.enableDbChain({ platform: 'linux', uid: 0, run, readFile: () => null });
  setSleepState(db, id, 'production', { state: 'sleeping' });
  wake._setWakeDepsForTests({
    db, admit: async () => {}, verifyTrust: async () => {}, audit: async () => {}, recoverSoon: async () => {}, invalidate: async () => {},
    probe: async () => true, sleep: async () => {},
    docker: async (args) => { order.push(`docker:${args.join(' ')}:${DC.getLastDbSync()?.plan?.[0]?.state}`); return ''; },
  });
  try {
    const r = await wake.wakeEnv({ id, slug: 'wk' }, 'production');
    assert.equal(r.ok, true, JSON.stringify(r));
  } finally { wake._setWakeDepsForTests(null); DC.disableDbChain(); }
  assert.deepEqual(order, ['write:open', 'docker:start appcrane-wk-production:open', 'write:closed']);
});

test('docker events reconnect: both chains are synced as soon as the stream is back, not at the 5-minute backstop', { timeout: 20_000 }, async () => {
  server('postgres', 45432);
  row(mkApp('rc'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-rc-production': { ips: ['172.18.0.5'] } } });
  const base = h.run;
  const run = async (cmd, args, opts) => {
    if (cmd === 'docker' && args[0] === 'ps' && !args.includes('-a')) return ok('');
    if (args.includes('APPCRANE-PUBLISH')) return ok('-N APPCRANE-PUBLISH\n');
    if (cmd === 'ip' || cmd === 'ss') return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    if (args.join(' ') === '-w -S') return ok('-P INPUT ACCEPT\n');
    return base(cmd, args, opts);
  };
  const children = [];
  const spawn = () => {
    const p = new EventEmitter();
    p.stdout = new PassThrough(); p.stderr = new PassThrough();
    p.kill = () => p.emit('close', 0);
    children.push(p);
    return p;
  };
  HF.startHostFirewall({ deps: { platform: 'linux', uid: 0, run, readFile: () => null, probeImds: async () => ({ status: 'not_measured', detail: 'test' }) }, spawn, backstopMs: 60 * 60_000 });
  try {
    await HF._waitForIdle();
    const inspects = () => h.calls.filter(c => c.cmd === 'docker' && c.args[0] === 'inspect').length;
    const before = inspects();
    children[0].emit('close', 1);
    const end = Date.now() + 9000;
    while (children.length < 2 && Date.now() < end) await new Promise(r => setTimeout(r, 50));
    assert.equal(children.length, 2, 'reconnected');
    const end2 = Date.now() + 1000;
    while (inspects() === before && Date.now() < end2) await new Promise(r => setTimeout(r, 20));
    assert.ok(inspects() > before, 'the DB chain was synced within 1 s of the reconnect, with no event on the new stream');
  } finally { HF.stopHostFirewall(); }
});

function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare("INSERT INTO users (name, email, username, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${tag}`, `u${tag}@t.test`, `u${tag}`, role, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return token;
}

test('route: GET /api/platform/host-network returns the allowlist with mode, enforcement and would-drops (platform admin only)', async () => {
  server('postgres', 45432);
  row(mkApp('rt'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-rt-production': { ips: ['172.18.0.5'] } }, counters: { v4: listing(45432, 1, 4, 4), v6: '' } });
  await DC.syncDbChain({ deps: root(h, { readFile: () => null }) });
  const postureRun = async (cmd, args, opts) => {
    if (cmd === 'ip' || cmd === 'ss') return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    if (cmd === 'docker') return ok('');
    if (args.join(' ') === '-w -S') return ok('-P INPUT ACCEPT\n');
    return ok('-N APPCRANE-PUBLISH\n');
  };
  const app = express();
  app.use(express.json());
  app.use('/api/platform', createHostNetworkRouter({ platform: 'linux', uid: 0, run: postureRun, readFile: () => null }));
  app.use(errorHandler);
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const base = `http://127.0.0.1:${srv.address().port}/api/platform/host-network`;
    assert.equal((await fetch(base, { headers: { Authorization: `Bearer ${mkUser('user')}` } })).status, 403);
    const res = await fetch(base, { headers: { Authorization: `Bearer ${mkUser('platform_admin')}` } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.db.allowlist_mode, 'observe');
    assert.equal(body.db.enforcement.state, 'observing');
    assert.deepEqual(body.db.ports.map(p => [p.port, p.sources, p.would_drop]), [[45432, ['172.18.0.5'], 4]]);
  } finally { srv.closeAllConnections?.(); srv.close(); }
});

after(() => { HF.stopHostFirewall(); rmSync(DATA_DIR, { recursive: true, force: true }); });
