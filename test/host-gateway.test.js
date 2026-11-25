import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// services/hostGateway.js through its docker seam: which --add-host value a
// container gets (Linux bridge gateway, Docker Desktop, unreadable gateway,
// HOST_GATEWAY_IP), and the Job Health check that finds containers whose
// /etc/hosts maps host.docker.internal to "invalid IP" (measured in production
// after a dockerd reload left host-gateway-ips empty).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-hostgw-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.HOST_GATEWAY_IP;

const logger = (await import('../server/utils/logger.js')).default;
const warns = [];
logger.warn = (m) => warns.push(String(m));

const { initDb } = await import('../server/db.js');
initDb();
const hg = await import('../server/services/hostGateway.js');
const jh = await import('../server/services/jobHealth.js');

after(() => { hg._setHostGatewayExecForTests(null); rmSync(ROOT, { recursive: true, force: true }); });

beforeEach(() => {
  delete process.env.HOST_GATEWAY_IP;
  warns.length = 0;
  hg._setHostGatewayExecForTests(null);
  jh._resetJobHealthForTests();
});

// A fake daemon: answers by subcommand and records every argv.
function fakeDocker({ os = 'Ubuntu 22.04.4 LTS', gateway = '172.17.0.1 ', gatewayError = null, containers = {}, noCat = [] } = {}) {
  const calls = [];
  const fn = (args) => {
    calls.push(args);
    if (args[0] === 'info') return `${os}\n`;
    if (args[0] === 'network' && args[1] === 'inspect' && args[2] === 'bridge') {
      if (gatewayError) { const e = new Error('Command failed'); e.stderr = gatewayError; throw e; }
      return `${gateway}\n`;
    }
    if (args[0] === 'ps') return Object.keys(containers).concat(noCat).join('\n') + '\n';
    if (args[0] === 'exec') {
      if (noCat.includes(args[1])) {
        const e = new Error('Command failed');
        e.stderr = 'OCI runtime exec failed: exec failed: unable to start container process: exec: "cat": executable file not found in $PATH: unknown';
        throw e;
      }
      return containers[args[1]];
    }
    throw new Error(`unexpected docker ${args.join(' ')}`);
  };
  return { fn, calls };
}

const HOSTS_OK = '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n172.17.0.1\thost.docker.internal\n172.18.0.5\tabc123\n';
const HOSTS_BROKEN = '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\ninvalid IP\thost.docker.internal\n172.18.0.7\tdef456\n';
const HOSTS_NONE = '127.0.0.1\tlocalhost\n172.18.0.9\tghi789\n';

test('Linux: the --add-host is the default bridge gateway, read with docker network inspect bridge', async () => {
  const d = fakeDocker({ gateway: '172.17.0.1 ' });
  hg._setHostGatewayExecForTests(d.fn);
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:172.17.0.1');
  assert.ok(d.calls.some((a) => a.join(' ').startsWith('network inspect bridge')), JSON.stringify(d.calls));
  assert.deepEqual(warns, []);
});

test('Linux: an IPv6 gateway next to the IPv4 one does not corrupt the value', async () => {
  hg._setHostGatewayExecForTests(fakeDocker({ gateway: 'fd00:dead::1 172.17.0.1 ' }).fn);
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:172.17.0.1');
});

test('the sync twin gives the same answer (coder and Crew containers start synchronously)', () => {
  hg._setHostGatewayExecForTests(fakeDocker({ gateway: '172.17.0.1 ' }).fn);
  assert.equal(hg.resolveHostGatewayAddHostSync(), 'host.docker.internal:172.17.0.1');
});

test('Docker Desktop keeps host-gateway, and never reads the bridge (its gateway is in the VM)', async () => {
  const d = fakeDocker({ os: 'Docker Desktop', gateway: '172.17.0.1 ' });
  hg._setHostGatewayExecForTests(d.fn);
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:host-gateway');
  assert.ok(!d.calls.some((a) => a[0] === 'network'), JSON.stringify(d.calls));
  hg._resetHostGatewayCacheForTests();
  assert.equal(hg.resolveHostGatewayAddHostSync(), 'host.docker.internal:host-gateway');
  assert.equal(hg.decideAddHost({ os: 'Docker Desktop' }).source, 'docker-desktop');
  assert.deepEqual(warns, [], 'Desktop is the intended value, not a fallback');
});

test('Linux with an unreadable gateway falls back to host-gateway and warns', async () => {
  hg._setHostGatewayExecForTests(fakeDocker({ gatewayError: 'Error response from daemon: network bridge not found' }).fn);
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:host-gateway');
  assert.equal(warns.length, 1, JSON.stringify(warns));
  assert.match(warns[0], /network bridge not found/);
  hg._setHostGatewayExecForTests(fakeDocker({ gateway: '' }).fn);
  assert.equal(hg.resolveHostGatewayAddHostSync(), 'host.docker.internal:host-gateway');
  assert.equal(warns.length, 2);
});

test('the answer is cached: a second container start runs no docker command', async () => {
  const d = fakeDocker();
  hg._setHostGatewayExecForTests(d.fn);
  await hg.resolveHostGatewayAddHost();
  const n = d.calls.length;
  await hg.resolveHostGatewayAddHost();
  hg.resolveHostGatewayAddHostSync();
  assert.equal(d.calls.length, n);
});

test('HOST_GATEWAY_IP overrides both paths without asking docker; a non-IPv4 value is ignored with a warning', async () => {
  const d = fakeDocker({ os: 'Docker Desktop' });
  hg._setHostGatewayExecForTests(d.fn);
  process.env.HOST_GATEWAY_IP = '10.9.8.7';
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:10.9.8.7');
  hg._resetHostGatewayCacheForTests();
  assert.equal(hg.resolveHostGatewayAddHostSync(), 'host.docker.internal:10.9.8.7');
  assert.deepEqual(d.calls, []);
  hg._resetHostGatewayCacheForTests();
  process.env.HOST_GATEWAY_IP = '10.9.8.7; rm -rf /';
  assert.equal(await hg.resolveHostGatewayAddHost(), 'host.docker.internal:host-gateway');
  assert.match(warns.join('\n'), /HOST_GATEWAY_IP/);
});

test('parseHostsMapping: a valid address, "invalid IP", and no mapping at all', () => {
  assert.deepEqual(
    { ...hg.parseHostsMapping(HOSTS_OK), line: undefined },
    { mapped: true, address: '172.17.0.1', valid: true, line: undefined });
  const b = hg.parseHostsMapping(HOSTS_BROKEN);
  assert.equal(b.mapped, true);
  assert.equal(b.valid, false);
  assert.equal(b.line, 'invalid IP\thost.docker.internal');
  assert.deepEqual(hg.parseHostsMapping(HOSTS_NONE), { mapped: false });
  assert.equal(hg.parseHostsMapping('fd00::1 host.docker.internal\n').valid, true);
  assert.equal(hg.parseHostsMapping('# 1.2.3.4 host.docker.internal\n').mapped, false);
  assert.equal(hg.parseHostsMapping('0.0.0.0 host.docker.internal.example.test\n').mapped, false);
});

test('checkContainerGateways names the broken containers and lists the ones it could not read', async () => {
  const d = fakeDocker({
    containers: {
      'appcrane-good-production': HOSTS_OK,
      'appcrane-outlink-voip-production': HOSTS_BROKEN,
      'appcrane-db-postgres': HOSTS_NONE,
    },
    noCat: ['appcrane-distroless-sandbox'],
  });
  const r = await hg.checkContainerGateways({ exec: d.fn });
  assert.equal(r.checked, 4);
  assert.equal(r.ok, 1);
  assert.equal(r.unmapped, 1);
  assert.deepEqual(r.broken.map((b) => b.name), ['appcrane-outlink-voip-production']);
  assert.deepEqual(r.skipped, [{ name: 'appcrane-distroless-sandbox', reason: 'no cat in the image' }]);
  const execs = d.calls.filter((a) => a[0] === 'exec');
  assert.ok(execs.every((a) => a.length === 4 && a[2] === 'cat' && a[3] === '/etc/hosts'), JSON.stringify(execs));
  assert.deepEqual(d.calls.find((a) => a[0] === 'ps'), ['ps', '--filter', 'name=^appcrane-', '--format', '{{.Names}}']);
});

test('the Job Health run fails, names the containers and says how to fix it', async () => {
  const d = fakeDocker({ containers: { 'appcrane-outlink-voip-production': HOSTS_BROKEN, 'appcrane-ok-sandbox': HOSTS_OK } });
  hg._setHostGatewayExecForTests(d.fn);
  jh.jobStarted('host-gateway', { cadenceMs: 3_600_000 });
  await assert.rejects(jh.trackJob('host-gateway', () => hg.runHostGatewayCheck()), /outlink-voip-production/);
  const job = jh.getJobHealth().find((j) => j.id === 'host-gateway');
  assert.equal(job.status, 'failing');
  assert.match(job.last_error, /outlink-voip-production/, job.last_error);
  assert.match(job.detail.message, /appcrane-outlink-voip-production/);
  assert.match(job.detail.message, /Restart on the app page stops, removes and starts a new container/);
  assert.match(job.detail.message, /plain docker restart/);
  assert.doesNotMatch(job.detail.message, /appcrane-ok-sandbox/);
});

test('the Job Health run passes when every mapping is an address', async () => {
  hg._setHostGatewayExecForTests(fakeDocker({ containers: { 'appcrane-ok-sandbox': HOSTS_OK } }).fn);
  jh.jobStarted('host-gateway', { cadenceMs: 3_600_000 });
  await jh.trackJob('host-gateway', () => hg.runHostGatewayCheck());
  const job = jh.getJobHealth().find((j) => j.id === 'host-gateway');
  assert.equal(job.status, 'ok');
  assert.match(job.detail.message, /1 running container\(s\) checked: 1 map/);
  assert.match(job.detail.message, /host\.docker\.internal:172\.17\.0\.1/);
});
