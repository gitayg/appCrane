import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The --add-host value every AppCrane container start emits, read from a
// recording `docker` shim that plays a Linux daemon: `docker info` is not
// Docker Desktop and the default bridge's gateway is 172.17.0.1. Before this
// change each start passed the literal host-gateway, which a dockerd reload in
// production turned into "invalid IP host.docker.internal".

const ROOT = mkdtempSync(join(tmpdir(), 'crane-hostgw-argv-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_PROC_SWAPS = '/nonexistent/proc-swaps';
delete process.env.HOST_GATEWAY_IP;

const SHIM_DIR = join(ROOT, 'bin');
const ARGV_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/bin/sh\n' +
  '{ for a in "$@"; do printf \'%s\\n\' "$a"; done; printf \'\\0\'; } >> "$CRANE_TEST_DOCKER_LOG"\n' +
  'if [ "$1" = info ]; then echo "Ubuntu 24.04.1 LTS"; exit 0; fi\n' +
  'if [ "$1" = network ] && [ "$2" = inspect ] && [ "$3" = bridge ]; then echo "172.17.0.1 "; exit 0; fi\n' +
  'echo 0123456789abcdef\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const calls = () => (existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, 'utf8').split('\0')
  .filter((r) => r.trim() !== '').map((r) => r.split('\n').filter((l) => l !== '')) : []);
const clear = () => { if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG); };

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { startApp } = await import('../server/services/docker.js');
const { crewTurnContainerOptions } = await import('../server/services/crewAppCoderRunner.js');
const hg = await import('../server/services/hostGateway.js');

after(() => rmSync(ROOT, { recursive: true, force: true }));

db.prepare('INSERT INTO apps (name,slug,slot,source_type,ingress_type) VALUES (?,?,?,?,?)')
  .run('hg-http', 'hg-http', 901, 'managed', 'http');
const BASE = { slug: 'hg-http', env: 'production', image: 'appcrane-x:abc123', hostPort: 4391, memoryMb: 512, cpus: 0.5, admission: false };

function runArgv() {
  const runs = calls().filter((c) => c[0] === 'run');
  assert.equal(runs.length, 1, `expected one docker run, saw ${runs.length}`);
  return runs[0];
}

test('an app container that asks for the host gets the bridge gateway, not host-gateway', async () => {
  hg._resetHostGatewayCacheForTests();
  clear();
  await startApp({ ...BASE, addHostGateway: true });
  const argv = runArgv();
  const i = argv.indexOf('--add-host');
  assert.ok(i >= 0, JSON.stringify(argv));
  assert.equal(argv[i + 1], 'host.docker.internal:172.17.0.1');
  assert.ok(!argv.some((a) => a.includes('host-gateway')), JSON.stringify(argv));
});

test('an app container that does not ask gets no --add-host at all', async () => {
  clear();
  await startApp({ ...BASE });
  assert.ok(!runArgv().includes('--add-host'));
});

test('HOST_GATEWAY_IP reaches the app container argv', async () => {
  process.env.HOST_GATEWAY_IP = '10.20.30.40';
  hg._resetHostGatewayCacheForTests();
  try {
    clear();
    await startApp({ ...BASE, addHostGateway: true });
    const argv = runArgv();
    assert.equal(argv[argv.indexOf('--add-host') + 1], 'host.docker.internal:10.20.30.40');
  } finally {
    delete process.env.HOST_GATEWAY_IP;
    hg._resetHostGatewayCacheForTests();
  }
});

test('a Crew coder turn gets the same mapping', () => {
  hg._resetHostGatewayCacheForTests();
  const opts = crewTurnContainerOptions({ slug: 'hg-http', taskId: 't1', workspaceDir: '/w', claudeHomeDir: '/h', containerName: 'c' });
  assert.deepEqual(opts.addHosts, ['host.docker.internal:172.17.0.1']);
});
