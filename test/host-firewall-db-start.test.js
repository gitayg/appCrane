import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, appendFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The app container start and APPCRANE-DB, through the real startApp(): a
// recording `docker` shim on PATH (as test/container-port.test.js uses) and
// the DB chain's exec seam, which sends docker to that shim and records
// iptables into the same log, so the log is the true order of events.
//
// Docker assigns an address only when the container starts (measured on
// 29.9.2: a created container inspects with no IP; a stopped one gives its
// address back and the next container gets it). So the start must hold the
// app's database ports open across `docker run` and close them once the new
// address is read: never a moment where the new container is refused.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-db-start-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'argv.log');
const RULES = join(process.env.DATA_DIR, 'rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, ["docker", ...argv].map(a => a + "\\n").join("") + "\\0");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) { process.stdout.write(r.stdout || ""); process.exit(r.code || 0); }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { startApp } = await import('../server/services/docker.js');
const DD = await import('../server/services/hostFirewall/dbDesired.js');
const DC = await import('../server/services/hostFirewall/dbChain.js');
after(() => { DC._resetDbChainForTests(); rmSync(process.env.DATA_DIR, { recursive: true, force: true }); });

const NAME = 'appcrane-dbs-production';
writeFileSync(RULES, JSON.stringify([
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['ps', '-a', '{{.Names}}'], stdout: `${NAME}\n` },
  { match: ['inspect', DD.INSPECT_FORMAT], stdout: `cid|/${NAME}|running|appcrane-apps|172.20.0.7,;\n` },
]));

const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, ingress_type) VALUES ('dbs', 'dbs', 870, 'managed', 'http')").run().lastInsertRowid;
db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES ('postgres', 'c', 'i', 45432, 'x')").run();
db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', 'crane_a1', 'crane_a1_u', 'x')").run(appId);
db.prepare("INSERT INTO settings (key, value) VALUES ('db_allowlist_mode', 'enforce')").run();

function shimDocker(args) {
  return new Promise((res) => {
    execFile('docker', args, (err, stdout, stderr) => res({ code: err ? (typeof err.code === 'number' ? err.code : null) : 0, stdout: String(stdout), stderr: String(stderr), missing: false, error: null }));
  });
}

function hostRun({ restoreFails = false, chain: initial = [] } = {}) {
  let chain = [...initial];
  return async (cmd, args, opts = {}) => {
    if (cmd === 'docker') return shimDocker(args);
    appendFileSync(LOG, [cmd, ...args, ...(opts.input ? [`stdin:${opts.input}`] : [])].map(a => a + '\n').join('') + '\0');
    if (cmd.endsWith('-restore')) {
      if (restoreFails) return { code: 4, stdout: '', stderr: 'iptables-restore: line 2 failed\n', missing: false, error: null };
      chain = opts.input.split('\n').filter(l => l.startsWith('-A APPCRANE-DB '));
      return { code: 0, stdout: '', stderr: '', missing: false, error: null };
    }
    return { code: 0, stdout: ['-N APPCRANE-DB', ...chain].join('\n') + '\n', stderr: '', missing: false, error: null };
  };
}

function events() {
  if (!existsSync(LOG)) return [];
  return readFileSync(LOG, 'utf8').split('\0').filter(r => r.trim()).map(r => r.split('\n').filter(Boolean));
}

beforeEach(() => { if (existsSync(LOG)) rmSync(LOG); DC._resetDbChainForTests(); });

const START = { slug: 'dbs', env: 'production', image: 'odoo:19', hostPort: 4870, memoryMb: 256, cpus: 0.5 };

// The chain as the previous container left it: its address, since given back.
const STALE = [
  '-A APPCRANE-DB -s 172.20.0.3/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN',
  '-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP',
];

test('start ordering: sync with the port held open, docker run, then sync with the new address and the DROP', async () => {
  DC.enableDbChain({ platform: 'linux', uid: 0, run: hostRun({ chain: STALE }) });
  await startApp(START);
  const ev = events();
  const runAt = ev.findIndex(e => e[0] === 'docker' && e[1] === 'run' && e.includes(NAME));
  assert.ok(runAt > 0, 'docker run happened');
  const v4Restores = ev.map((e, i) => ({ e, i })).filter(x => x.e[0] === 'iptables-restore');
  assert.equal(v4Restores.length, 2, JSON.stringify(ev.map(e => e.slice(0, 2))));
  const [before, afterRun] = v4Restores;
  assert.ok(before.i < runAt, 'the first sync is written before docker run');
  assert.ok(!before.e.join('\n').includes('--ctorigdstport 45432'), `while starting, the old allowlist and DROP for 45432 are gone (fail open): ${before.e.join(' ')}`);
  assert.ok(afterRun.i > runAt, 'the second sync is written after docker run');
  const stdin = afterRun.e.find(l => l.startsWith('stdin:')) ? afterRun.e.slice(afterRun.e.findIndex(l => l.startsWith('stdin:'))).join('\n') : '';
  assert.match(stdin, /-A APPCRANE-DB -s 172\.20\.0\.7\/32 -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j RETURN\n-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport 45432 --ctdir ORIGINAL -j DROP/);
  const inspectAfter = ev.findIndex((e, i) => i > runAt && e[1] === 'inspect' && e.includes(DD.INSPECT_FORMAT));
  assert.ok(inspectAfter > runAt && inspectAfter < afterRun.i, 'the address is read after the run and before the closing write');
});

test('start ordering: a sync that fails never blocks or fails the start', async () => {
  DC.enableDbChain({ platform: 'linux', uid: 0, run: hostRun({ restoreFails: true }) });
  const id = await startApp(START);
  assert.equal(id, '0123456789abcdef');
  assert.ok(events().some(e => e[0] === 'docker' && e[1] === 'run'), 'the container was started');
  assert.equal(DC.getLastDbSync().status, 'failed');
});

test('start: with the host firewall not running (tests, macOS), the start is exactly a docker run', async () => {
  await startApp(START);
  const ev = events();
  assert.equal(ev.filter(e => e[0].startsWith('ip')).length, 0);
  assert.equal(ev.filter(e => e.includes(DD.INSPECT_FORMAT)).length, 0);
});
