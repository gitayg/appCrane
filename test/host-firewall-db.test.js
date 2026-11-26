import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// APPCRANE-DB: per managed database port, the container addresses that may
// open a connection. Computed from real managed_databases / managed_db_servers
// rows; Docker and iptables are faked through the exec seam (every call is
// recorded as cmd, argv, stdin). The real kernel is in
// test/host-firewall-db-live.test.js, the start ordering in
// test/host-firewall-db-start.test.js.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-firewall-db-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { SANDBOX_TENANT, setSeparateSandboxDb } = await import('../server/services/sandboxDb.js');
const DR = await import('../server/services/hostFirewall/dbRules.js');
const DD = await import('../server/services/hostFirewall/dbDesired.js');
const DC = await import('../server/services/hostFirewall/dbChain.js');
const HF = await import('../server/services/hostFirewall/index.js');
const PO = await import('../server/services/hostFirewall/posture.js');
const JH = await import('../server/services/jobHealth.js');
initDb();
const db = getDb();
after(() => { HF.stopHostFirewall(); rmSync(DATA_DIR, { recursive: true, force: true }); });

beforeEach(() => {
  db.prepare('DELETE FROM managed_databases').run();
  db.prepare('DELETE FROM managed_db_servers').run();
  db.prepare('DELETE FROM app_settings').run();
  db.prepare('DELETE FROM apps').run();
  db.prepare("DELETE FROM settings WHERE key = 'db_allowlist_mode'").run();
  DC._resetDbChainForTests();
});

function mode(m) {
  db.prepare("INSERT INTO settings (key, value) VALUES ('db_allowlist_mode', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(m);
}
const JUMP = '-A DOCKER-USER -o docker0 -m conntrack --ctstate DNAT -j APPCRANE-DB';

let seq = 0;
function mkApp(slug) {
  seq += 1;
  return db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(slug, slug, 600 + seq).lastInsertRowid;
}
function server(engine, port) {
  db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES (?, ?, 'img', ?, 'x')")
    .run(engine, `appcrane-db-${engine}`, port);
}
function row(appId, engine, { tenant = '', port = null } = {}) {
  seq += 1;
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc, host_port, container_name)
              VALUES (?, ?, ?, ?, ?, 'x', ?, ?)`)
    .run(appId, tenant, engine, `db${seq}`, `u${seq}`, port, port ? `appcrane-db-redis-${seq}` : null);
}

// A fake host. docker: `ps -a` lists names; `inspect` answers from a table of
// {name: {id, status, mode, ips, scope}}. iptables keeps one APPCRANE-DB per
// family, DOCKER-USER (jump) and the counters `-L -v -x -n` prints (counters).
function fakeHost({ containers = {}, psFails = false, inspectFails = false, kernel = { v4: [], v6: [] }, sudo = null, restoreFails = null, jump = { v4: [JUMP], v6: [JUMP] }, counters = { v4: '', v6: '' }, v6Fails = null } = {}) {
  const calls = [];
  const famOf = (cmd) => (cmd.startsWith('ip6') ? 'v6' : 'v4');
  const run = async (cmd, args, opts = {}) => {
    calls.push({ cmd, args: [...args], input: opts.input ?? null });
    const ok = (stdout = '') => ({ code: 0, stdout, stderr: '', missing: false, error: null });
    if (cmd === 'docker' && args[0] === 'ps') {
      return psFails ? { code: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon\n', missing: false, error: null } : ok(Object.keys(containers).join('\n') + '\n');
    }
    if (cmd === 'docker' && args[0] === 'inspect') {
      if (inspectFails) return { code: 1, stdout: '', stderr: 'Error response from daemon: timeout\n', missing: false, error: null };
      const lines = args.slice(3).map((n) => {
        const c = containers[n];
        const nets = (c.ips || []).map(ip => (ip.includes(':') ? `invalid IP,${ip};` : `${ip},;`)).join('') || 'invalid IP,;';
        return `${c.id || `id-${n}`}|/${n}|${c.status || 'running'}|${c.mode || 'appcrane-apps'}|${nets}|${c.scope === undefined ? '' : `=${c.scope}`}`;
      });
      return ok(lines.join('\n') + '\n');
    }
    if (cmd.startsWith('ip6') && v6Fails) return { code: 3, stdout: '', stderr: v6Fails, missing: false, error: null };
    if ((cmd === 'iptables' || cmd === 'ip6tables') && args.includes('DOCKER-USER')) return ok(['-N DOCKER-USER', ...jump[famOf(cmd)]].join('\n') + '\n');
    if ((cmd === 'iptables' || cmd === 'ip6tables') && args.includes('-L')) return ok(counters[famOf(cmd)]);
    if (cmd === 'iptables' || cmd === 'ip6tables') {
      const lines = kernel[famOf(cmd)];
      if (lines === null) return { code: 1, stdout: '', stderr: `${cmd}: No chain/target/match by that name.\n`, missing: false, error: null };
      return ok([`-N ${DR.DB_CHAIN}`, ...lines].join('\n') + '\n');
    }
    if (cmd.endsWith('-restore')) {
      if (restoreFails) return { code: 4, stdout: '', stderr: restoreFails, missing: false, error: null };
      kernel[famOf(cmd)] = opts.input.split('\n').filter(l => l.startsWith(`-A ${DR.DB_CHAIN} `));
      return ok();
    }
    if (cmd === 'sudo' && sudo) return { missing: false, error: null, stdout: '', stderr: '', ...sudo };
    throw new Error(`unexpected command ${cmd} ${args.join(' ')}`);
  };
  return { run, calls, kernel };
}

const root = (h) => ({ platform: 'linux', uid: 0, run: h.run });

test('desired list from real rows: scopes, separate sandbox, the production sandbox peer, per-scope Redis, other tenants', () => {
  server('postgres', 45432);
  server('mariadb', 43306);
  server('mongo', 47017);
  const shared = mkApp('shared');           // '' postgres: production and sandbox
  row(shared, 'postgres');
  const sep = mkApp('sep');                 // '' postgres with Separate sandbox database: production only
  row(sep, 'postgres');
  setSeparateSandboxDb(db, sep, true);
  const peer = mkApp('peer');               // sandbox mariadb: sandbox, and production through sandbox_url_env
  row(peer, 'mariadb', { tenant: SANDBOX_TENANT });
  const mg = mkApp('mg');                   // sandbox mongo: sandbox only (no peer URL on mongo)
  row(mg, 'mongo', { tenant: SANDBOX_TENANT });
  const rd = mkApp('rd');                   // two per-scope Redis instances, one per scope
  row(rd, 'redis', { port: 46380 });
  row(rd, 'redis', { tenant: SANDBOX_TENANT, port: 46381 });
  const tn = mkApp('tn');                   // a tenant scope no container is ever given
  row(tn, 'postgres', { tenant: 'acme/u1' });

  const specs = DD.dbPortSpecs(db);
  const view = Object.fromEntries(specs.map(s => [s.port, `${s.engine}:${DD.resolveContainers(s, new Map()).map(c => c.name).join(',')}`]));
  assert.deepEqual(view, {
    43306: 'mariadb:appcrane-peer-production,appcrane-peer-sandbox',
    45432: 'postgres:appcrane-sep-production,appcrane-shared-production,appcrane-shared-sandbox',
    46380: 'redis:appcrane-rd-production,appcrane-rd-sandbox',
    46381: 'redis:appcrane-rd-sandbox',
    47017: 'mongo:appcrane-mg-sandbox',
  });
});

test('a redis row without a port, and a shared engine with no server row, give no port', () => {
  const a = mkApp('np');
  row(a, 'redis');
  row(a, 'postgres');
  assert.deepEqual(DD.dbPortSpecs(db), []);
});

test('plan: running containers are allowed, stopped and absent ones are not, an unknown address or a pending start leaves the port open', () => {
  const c = (name) => ({ name, tenant: '', fallback: [''], peer: false });
  const specs = [
    { port: 45432, engine: 'postgres', kind: 'shared', owner: null, candidates: [c('a'), c('b'), c('c')] },
    { port: 46380, engine: 'redis', kind: 'redis', owner: null, candidates: [c('d')] },
    { port: 46381, engine: 'redis', kind: 'redis', owner: null, candidates: [c('e')] },
    { port: 47017, engine: 'mongo', kind: 'shared', owner: null, candidates: [c('f')] },
  ];
  const addrs = new Map([
    ['a', { state: 'ip', ips: ['172.18.0.5'] }],
    ['b', { state: 'stopped', ips: [] }],
    ['c', { state: 'absent', ips: [] }],
    ['d', { state: 'unknown', ips: [], why: 'docker inspect failed' }],
    ['e', { state: 'ip', ips: ['172.18.0.9', 'fd00:1::9'] }],
    ['f', { state: 'ip', ips: ['172.18.0.7'] }],
  ]);
  const plan = DD.computeDbPlan(specs, addrs, new Set(['f']));
  assert.deepEqual(plan.map(p => [p.port, p.state, p.allow.join(' '), p.allowed_containers]), [
    [45432, 'closed', '172.18.0.5', 1],
    [46380, 'open', '', 0],
    [46381, 'closed', '172.18.0.9 fd00:1::9', 1],
    [47017, 'open', '', 0],
  ]);
  assert.equal(plan[1].open_because[0].why, 'docker inspect failed');
  assert.equal(plan[3].open_because[0].why, 'starting');
});

test('root: exact argv, the rule text on stdin per family, and an unchanged chain is not rewritten', async () => {
  mode('enforce');
  server('postgres', 45432);
  const a = mkApp('fa');
  row(a, 'postgres');
  row(a, 'redis', { port: 46380 });
  const h = fakeHost({ containers: {
    'appcrane-fa-production': { ips: ['172.18.0.5'] },
    'appcrane-fa-sandbox': { ips: ['172.18.0.6', 'fd00:1::6'] },
  } });
  const r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.status, 'ok', r.reason);
  assert.deepEqual(h.calls.map(c => [c.cmd, ...c.args]), [
    ['docker', 'ps', '-a', '--no-trunc', '--format', '{{.Names}}'],
    ['docker', 'inspect', '--format', DD.INSPECT_FORMAT, 'appcrane-fa-production', 'appcrane-fa-sandbox'],
    ['iptables', '-w', '-S', 'APPCRANE-DB'],
    ['iptables-restore', '-w', '--noflush'],
    ['iptables', '-w', '-S', 'APPCRANE-DB'],
    ['ip6tables', '-w', '-S', 'APPCRANE-DB'],
    ['ip6tables-restore', '-w', '--noflush'],
    ['ip6tables', '-w', '-S', 'APPCRANE-DB'],
    ['iptables', '-w', '-S', 'DOCKER-USER'],
    ['ip6tables', '-w', '-S', 'DOCKER-USER'],
  ]);
  assert.equal(r.allowlist_mode, 'enforce');
  assert.deepEqual(r.enforcement, { state: 'enforced', why: null });
  assert.equal(h.calls[3].input, [
    '*filter',
    ':APPCRANE-DB - [0:0]',
    '-A APPCRANE-DB -s 172.18.0.5/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -s 172.18.0.6/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
    '-A APPCRANE-DB -s 172.18.0.5/32 -p tcp -m conntrack --ctorigdstport 46380 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -s 172.18.0.6/32 -p tcp -m conntrack --ctorigdstport 46380 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 46380 --ctdir ORIGINAL -j DROP',
    'COMMIT', '',
  ].join('\n'));
  assert.equal(h.calls[6].input, [
    '*filter',
    ':APPCRANE-DB - [0:0]',
    '-A APPCRANE-DB -s fd00:1::6/128 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
    '-A APPCRANE-DB -s fd00:1::6/128 -p tcp -m conntrack --ctorigdstport 46380 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 46380 --ctdir ORIGINAL -j DROP',
    'COMMIT', '',
  ].join('\n'));
  assert.deepEqual(r.ports, [
    { port: 45432, engine: 'postgres', state: 'closed', allowed: 2 },
    { port: 46380, engine: 'redis', state: 'closed', allowed: 2 },
  ]);

  h.calls.length = 0;
  const again = await DC.syncDbChain({ deps: root(h) });
  assert.equal(again.families.v4.state, 'unchanged');
  assert.equal(again.families.v6.state, 'unchanged');
  assert.equal(h.calls.filter(c => c.cmd.endsWith('-restore')).length, 0);
});

test('not root: the helper through sudo -n with allow:<port>:<ip> then close:<port>, and nothing touches iptables', async () => {
  mode('enforce');
  server('postgres', 45432);
  const a = mkApp('hp');
  row(a, 'postgres');
  const h = fakeHost({ containers: { 'appcrane-hp-production': { ips: ['172.18.0.5', 'fd00:1::5'] } }, sudo: { code: 0 } });
  const r = await DC.syncDbChain({ deps: { platform: 'linux', uid: 1000, exists: (p) => p === DR.DB_HELPER, run: h.run } });
  assert.equal(r.status, 'ok', r.reason);
  assert.equal(r.mode, 'helper');
  const sudo = h.calls.filter(c => c.cmd === 'sudo');
  assert.deepEqual(sudo.map(c => c.args), [['-n', '/usr/local/lib/appcrane/appcrane-db-chain.sh', 'allow:45432:172.18.0.5', 'allow:45432:fd00:1::5', 'close:45432']]);
  assert.equal(h.calls.filter(c => c.cmd.startsWith('ip')).length, 0);

  const missing = await DC.syncDbChain({ deps: { platform: 'linux', uid: 1000, exists: () => false, run: h.run } });
  assert.equal(missing.status, 'not_applicable');
  assert.match(missing.reason, /appcrane-db-chain\.sh is not installed/);
  const refused = await DC.syncDbChain({ deps: { platform: 'linux', uid: 1000, exists: () => true, run: fakeHost({ containers: { 'appcrane-hp-production': { ips: ['172.18.0.5'] } }, sudo: { code: 2, stderr: 'bad argument\n' } }).run } });
  assert.equal(refused.status, 'failed');
  assert.match(refused.reason, /helper refused the allowlist/);
});

test('fail open: Docker unreadable or an address unknown writes no DROP for that port; others still close', async () => {
  mode('enforce');
  server('postgres', 45432);
  const a = mkApp('fo');
  row(a, 'postgres');
  row(a, 'redis', { port: 46380 });
  const b = mkApp('fo2');
  row(b, 'redis', { port: 46381 });
  const down = fakeHost({ containers: { 'appcrane-fo-production': { ips: ['172.18.0.5'] } }, inspectFails: true });
  const r = await DC.syncDbChain({ deps: root(down) });
  assert.equal(r.status, 'ok', r.reason);
  assert.deepEqual(down.kernel.v4, ['-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 46381 --ctdir ORIGINAL -j DROP'], 'fo\'s ports open: no RETURN, no DROP for them');
  assert.deepEqual(r.ports.map(p => p.state), ['open', 'open', 'closed'], 'fo2 has no container at all, so its redis is closed to everyone');

  const noIp = fakeHost({ containers: {
    'appcrane-fo-production': { ips: [] },
    'appcrane-fo2-production': { ips: ['172.18.0.8'] },
  } });
  const r2 = await DC.syncDbChain({ deps: root(noIp) });
  assert.equal(r2.status, 'ok');
  assert.ok(!noIp.kernel.v4.some(l => / 45432 | 46380 /.test(l)), noIp.kernel.v4.join('\n'));
  assert.ok(noIp.kernel.v4.includes('-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 46381 --ctdir ORIGINAL -j DROP'));

  const psDown = fakeHost({ containers: {}, psFails: true });
  const r3 = await DC.syncDbChain({ deps: root(psDown) });
  assert.deepEqual(r3.ports.map(p => p.state), ['open', 'open', 'open']);
});

test('an egress-enforced app connects from its anchor\'s address; a stopped container drops off', async () => {
  mode('enforce');
  server('postgres', 45432);
  const a = mkApp('eg');
  row(a, 'postgres');
  const h = fakeHost({ containers: {
    'appcrane-eg-production': { mode: 'container:abc123', ips: [] },
    'crane-egress-anchor.eg.production': { id: 'abc123', mode: 'appcrane-apps-egress', ips: ['172.30.0.4'] },
    'appcrane-eg-sandbox': { status: 'exited', ips: [] },
  } });
  const r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.status, 'ok', r.reason);
  assert.deepEqual(h.kernel.v4, [
    '-A APPCRANE-DB -s 172.30.0.4/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
    '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
  ]);
});

test('a rule AppCrane did not write is removed, and a failed restore is a failure', async () => {
  server('postgres', 45432);
  const a = mkApp('fr');
  row(a, 'postgres');
  const containers = { 'appcrane-fr-production': { ips: ['172.18.0.5'] } };
  const h = fakeHost({ containers, kernel: { v4: ['-A APPCRANE-DB -j ACCEPT'], v6: [] } });
  const r = await DC.syncDbChain({ deps: root(h) });
  assert.equal(r.families.v4.state, 'applied');
  assert.ok(!h.kernel.v4.includes('-A APPCRANE-DB -j ACCEPT'));
  const bad = await DC.syncDbChain({ deps: root(fakeHost({ containers, restoreFails: 'iptables-restore: line 3 failed\n' })) });
  assert.equal(bad.status, 'failed');
  assert.match(bad.reason, /line 3 failed/);
});

test('validation: the renderer and the helper argv refuse anything that is not a port and an address', () => {
  assert.throws(() => DR.dbRuleLines('v4', [{ port: 45432, state: 'closed', allow: ['172.18.0.5; rm'] }]), /refusing/);
  assert.throws(() => DR.dbHelperArgs([{ port: 0, state: 'closed', allow: [] }]), /refusing/);
  assert.throws(() => DR.dbHelperArgs([{ port: 45432, state: 'closed', allow: ['01.2.3.4'] }]), /refusing/);
  const many = Array.from({ length: 2100 }, (_, i) => `10.${Math.floor(i / 250)}.${i % 250}.1`);
  assert.throws(() => DR.dbHelperArgs([{ port: 45432, state: 'closed', allow: many }]), /more than the helper takes/);
  assert.equal(DR.familyOf('invalid IP'), null);
  assert.deepEqual(DR.parseDbChain('-N APPCRANE-DB\n-A APPCRANE-DB -s 172.18.0.5/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN\n-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN\n').foreign.length, 1,
    'a RETURN with no source would admit everyone: it is not one of ours');
});

test('start wrapper: off, it only starts; on, a failing sync never blocks or fails the start', async () => {
  let started = 0;
  assert.equal(await DC.withDbAccessDuringStart('appcrane-x-production', async () => { started += 1; return 'id1'; }), 'id1');
  server('postgres', 45432);
  const a = mkApp('x');
  row(a, 'postgres');
  DC.enableDbChain({ platform: 'linux', uid: 0, run: async () => { throw new Error('exec exploded'); } });
  assert.equal(await DC.withDbAccessDuringStart('appcrane-x-production', async () => { started += 1; return 'id2'; }), 'id2');
  assert.equal(started, 2);
  assert.equal(DC.getLastDbSync().status, 'failed');
  await assert.rejects(DC.withDbAccessDuringStart('appcrane-x-production', async () => { throw new Error('docker run failed'); }), /docker run failed/);
});

test('scheduler: the DB chain is synced with the publish chain, Job Health carries per-port counts, posture carries the allowlist', async () => {
  mode('enforce');
  JH._resetJobHealthForTests();
  server('postgres', 45432);
  const a = mkApp('jh');
  row(a, 'postgres');
  row(a, 'redis', { port: 46380 });
  const h = fakeHost({ containers: { 'appcrane-jh-production': { ips: ['172.18.0.5'] } } });
  const base = h.run;
  const run = async (cmd, args, opts) => {
    if (cmd === 'docker' && args[0] === 'ps' && args.includes('{{.Names}}|{{.Label "appcrane"}}|{{.Label "slug"}}|{{.Label "env"}}|{{.Ports}}')) return { code: 0, stdout: '', stderr: '', missing: false, error: null };
    if ((cmd === 'iptables' || cmd === 'ip6tables') && args.includes('APPCRANE-PUBLISH')) return { code: 0, stdout: '-N APPCRANE-PUBLISH\n', stderr: '', missing: false, error: null };
    if (cmd === 'ip' || cmd === 'ss') return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    if ((cmd === 'iptables' || cmd === 'ip6tables') && args.join(' ') === '-w -S') return { code: 0, stdout: '-P INPUT ACCEPT\n', stderr: '', missing: false, error: null };
    return base(cmd, args, opts);
  };
  const out = await HF.runHostNetwork({ withPosture: true, d: { platform: 'linux', uid: 0, run, readFile: () => null, probeImds: async () => ({ status: 'not_measured', detail: 'test' }) } });
  assert.ok(out, 'the run succeeded');
  assert.equal(out.dbSync.status, 'ok', out.dbSync.reason);
  const job = JH.getJobHealth().find(j => j.id === 'host-network');
  assert.deepEqual(job.detail.db.ports, { 45432: 1, 46380: 1 }, JSON.stringify(job.detail));
  assert.equal(job.detail.db.allowlist_mode, 'enforce');
  assert.equal(job.detail.db.enforcement, 'enforced');
  assert.deepEqual(out.posture.db.ports.map(p => [p.port, p.state, p.allowed, p.sources.join(',')]), [[45432, 'closed', 1, '172.18.0.5'], [46380, 'closed', 1, '172.18.0.5']]);
  assert.deepEqual(PO.dbAllowlistView(null), null);
});

function publishOnly(base) {
  return async (cmd, args, opts) => {
    if (cmd === 'docker' && args[0] === 'ps' && args.includes('{{.Names}}|{{.Label "appcrane"}}|{{.Label "slug"}}|{{.Label "env"}}|{{.Ports}}')) return { code: 0, stdout: '', stderr: '', missing: false, error: null };
    if ((cmd === 'iptables' || cmd === 'ip6tables') && args.includes('APPCRANE-PUBLISH')) return { code: 0, stdout: '-N APPCRANE-PUBLISH\n', stderr: '', missing: false, error: null };
    if (cmd === 'ip' || cmd === 'ss') return { code: null, stdout: '', stderr: '', missing: true, error: 'spawn ENOENT' };
    return base(cmd, args, opts);
  };
}

test('scheduler: a failed DB chain write fails the Job Health run with its reason', async () => {
  JH._resetJobHealthForTests();
  server('postgres', 45432);
  row(mkApp('jf'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-jf-production': { ips: ['172.18.0.5'] } }, restoreFails: 'iptables-restore: line 3 failed\n' });
  const out = await HF.runHostNetwork({ withPosture: false, d: { platform: 'linux', uid: 0, run: publishOnly(h.run) } });
  assert.equal(out, null);
  const job = JH.getJobHealth().find(j => j.id === 'host-network');
  assert.match(JSON.stringify(job), /APPCRANE-DB/);
});

test('scheduler: a docker start event syncs the DB chain without waiting for the debounce', async () => {
  server('postgres', 45432);
  row(mkApp('ev'), 'postgres');
  const h = fakeHost({ containers: { 'appcrane-ev-production': { ips: ['172.18.0.5'] } } });
  const children = [];
  const spawn = (cmd, args) => {
    const p = new EventEmitter();
    p.stdout = new PassThrough(); p.stderr = new PassThrough();
    p.kill = () => p.emit('close', 0);
    children.push(p);
    return p;
  };
  HF.startHostFirewall({ deps: { platform: 'linux', uid: 0, run: publishOnly(h.run), probeImds: async () => ({ status: 'not_measured', detail: 'test' }) }, spawn, backstopMs: 60 * 60_000 });
  await HF._waitForIdle();
  const inspects = () => h.calls.filter(c => c.cmd === 'docker' && c.args[0] === 'inspect').length;
  const before = inspects();
  children[0].stdout.write('{"status":"start","id":"x"}\n');
  const end = Date.now() + 1000;
  while (inspects() === before && Date.now() < end) await new Promise(r => setTimeout(r, 20));
  assert.ok(inspects() > before, 'synced within 1 s of the event, well inside the 2 s debounce');
  HF.stopHostFirewall();
});

test('docker events: a start event triggers a DB chain sync at once', () => {
  assert.equal(HF.isStartEvent('{"status":"start","id":"x"}'), true);
  assert.equal(HF.isStartEvent('{"Action":"start","id":"x"}'), true);
  assert.equal(HF.isStartEvent('{"Action":"die","id":"x"}'), false);
  assert.equal(HF.isStartEvent('not json'), false);
});
