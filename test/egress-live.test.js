import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import net from 'net';

// LIVE: an egress-enforced app container, started through the real
// docker.js startApp, against a real Docker daemon. Skipped with the reason
// when there is no daemon, or when a container on the shared app network
// cannot reach this host (a CI runner where host-gateway does not route back;
// see scripts/check-test-portability.sh).
//
// The "internet" here is a server on this host reached by a name the egress
// proxy resolves to it (APPCRANE_EGRESS_PRIVATE_HOSTS + the resolver seam), so
// the allowed/blocked verdicts do not depend on the runner's network. The
// direct-IP checks dial real public addresses: with no route they fail with
// "Network is unreachable" whatever the runner's internet is, and the control
// container on the ordinary network shows the same dial is not refused there.

const execFileAsync = promisify(execFile);
const ROOT = mkdtempSync(join(tmpdir(), 'crane-egress-live-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_PROC_SWAPS = '/nonexistent/proc-swaps';
process.env.APPCRANE_EGRESS_PRIVATE_HOSTS = 'allowed.t.test,blocked.t.test';

const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

let docker = false;
try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' }); docker = true; } catch (_) {}

const { HELPER_IMAGE } = await import('../server/services/volumeHelper.js');
const SLUG = `egrlive${process.pid}`;
const ENV = 'sandbox';
const APP = `appcrane-${SLUG}-${ENV}`;
let skip = docker ? false : 'no reachable Docker daemon on this host';

const target = http.createServer((req, res) => res.end(`TARGET_OK ${req.url}`));
const crane = http.createServer((req, res) => res.end('CRANE_OK'));
let TPORT; let HOST_PORT; let CRANE_PORT;
let db; let startApp; let stopApp; let proxyMod; let policy;

if (!skip) {
  TPORT = await freePort(); HOST_PORT = await freePort(); CRANE_PORT = await freePort();
  process.env.PORT = String(CRANE_PORT);
  process.env.APPCRANE_EGRESS_PROXY_PORT = String(await freePort());
  await new Promise((r) => target.listen(TPORT, '127.0.0.1', r));
  await new Promise((r) => crane.listen(CRANE_PORT, '0.0.0.0', r));
  try { execFileSync('docker', ['image', 'inspect', HELPER_IMAGE], { stdio: 'pipe' }); } catch (_) { execFileSync('docker', ['pull', HELPER_IMAGE], { stdio: 'pipe', timeout: 300000 }); }
  // Reachability probe: can a container on the ordinary app network reach this host at all?
  try {
    const { stdout } = await execFileAsync('docker', ['run', '--rm', '--add-host', 'host.docker.internal:host-gateway', HELPER_IMAGE,
      'wget', '-T', '5', '-q', '-O-', `http://host.docker.internal:${CRANE_PORT}/`], { timeout: 60000 });
    if (!stdout.includes('CRANE_OK')) skip = 'a container cannot reach this host through host-gateway';
  } catch (_) { skip = 'a container cannot reach this host through host-gateway (probe failed)'; }
}
if (!skip) {
  const dbm = await import('../server/db.js');
  dbm.initDb();
  db = dbm.getDb();
  const { getNextSlot } = await import('../server/services/portAllocator.js');
  ({ startApp, stopApp } = await import('../server/services/docker.js'));
  proxyMod = await import('../server/services/egress/proxy.js');
  policy = await import('../server/services/egress/policy.js');
  proxyMod._setEgressResolverForTests(async () => [{ address: '127.0.0.1', family: 4 }]);
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(SLUG, SLUG, getNextSlot(db)).lastInsertRowid;
  db.prepare('INSERT INTO app_egress (app_id, enforced) VALUES (?, 1)').run(id);
  db.prepare(`INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
    VALUES (?, 'egress', 'request', 'approved', ?, ?, 'live test')`).run(id, JSON.stringify({ hosts: [`allowed.t.test:${TPORT}`] }), JSON.stringify({ hosts: [`allowed.t.test:${TPORT}`] }));
  await startApp({
    slug: SLUG, env: ENV, image: HELPER_IMAGE, hostPort: HOST_PORT, admission: false, addHostGateway: true,
    command: ['sh', '-c', 'mkdir -p /tmp/w && echo APP_OK > /tmp/w/index.html && exec httpd -f -p 3000 -h /tmp/w'],
    envVars: { CRANE_INTERNAL_URL: `http://host.docker.internal:${CRANE_PORT}` },
    memoryMb: 64, cpus: 0.25,
  });
}

after(async () => {
  if (db) {
    await stopApp(SLUG, ENV).catch(() => {});
    await proxyMod.stopEgressProxy();
    await execFileAsync('docker', ['rm', '-f', 'crane-egress-relay']).catch(() => {});
    await execFileAsync('docker', ['network', 'rm', 'appcrane-apps-egress']).catch(() => {});
  }
  target.close(); crane.close();
  rmSync(ROOT, { recursive: true, force: true });
});

const inApp = async (script) => {
  try {
    const { stdout, stderr } = await execFileAsync('docker', ['exec', APP, 'sh', '-c', script], { timeout: 60000 });
    return stdout + stderr;
  } catch (e) { return `${e.stdout || ''}${e.stderr || ''}EXIT=${e.code}`; }
};

test('LIVE: the enforced app is served through its publish as before', { skip }, async () => {
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}/`);
  assert.equal((await r.text()).trim(), 'APP_OK');
  const net = execFileSync('docker', ['inspect', APP, '--format', '{{.HostConfig.NetworkMode}}'], { encoding: 'utf8' }).trim();
  assert.match(net, /^container:/);
  const anchorId = execFileSync('docker', ['inspect', `crane-egress-anchor.${SLUG}.${ENV}`, '--format', '{{.Id}}'], { encoding: 'utf8' }).trim();
  assert.equal(net, `container:${anchorId}`);
});

test('LIVE: the allow-listed host is reachable through the proxy the container was given', { skip }, async () => {
  const out = await inApp(`wget -T 10 -q -O- http://allowed.t.test:${TPORT}/through-proxy`);
  assert.match(out, /TARGET_OK \/through-proxy/);
  const tok = policy.egressToken(db.prepare('SELECT id FROM apps WHERE slug = ?').get(SLUG).id, ENV);
  const b64 = Buffer.from(`egress:${tok}`).toString('base64');
  const port = process.env.APPCRANE_EGRESS_PROXY_PORT;
  const tunnel = await inApp(`printf 'CONNECT allowed.t.test:${TPORT} HTTP/1.1\\r\\nProxy-Authorization: Basic ${b64}\\r\\n\\r\\nGET /tunnel HTTP/1.0\\r\\n\\r\\n' | nc -w 5 host.docker.internal ${port}`);
  assert.match(tunnel, /200 Connection Established[^]*TARGET_OK \/tunnel/);
});

test('LIVE: any other host is blocked, by name through the proxy and by IP directly', { skip }, async () => {
  assert.match(await inApp(`wget -T 10 -q -O- http://blocked.t.test:${TPORT}/ 2>&1`), /403|Forbidden/);
  const direct = await inApp('wget -Y off -T 5 -q -O- http://1.1.1.1/ 2>&1; nc -w 3 8.8.8.8 53 </dev/null 2>&1; echo done');
  assert.match(direct, /Network is unreachable/);
  assert.doesNotMatch(direct, /<html|Moved/i);
  assert.match(await inApp('wget -T 10 -q -O- http://1.1.1.1/ 2>&1'), /403|Forbidden/, 'the proxy refuses an IP literal too');
  assert.match(await inApp('nslookup -timeout=3 example.com 2>&1'), /SERVFAIL|can't|timed out|EXIT=/);
  assert.match(await inApp('ip route add default via 1.1.1.1 2>&1'), /Operation not permitted|EXIT=/);
  assert.doesNotMatch(await inApp('ip route'), /^default/m);
});

test('LIVE: AppCrane itself (CRANE_INTERNAL_URL) is still reachable from the enforced container', { skip }, async () => {
  // busybox wget ignores NO_PROXY (which the container is given), so it is told directly.
  assert.match(await inApp('wget -Y off -T 10 -q -O- "$CRANE_INTERNAL_URL/"'), /CRANE_OK/);
  assert.match(await inApp('echo "$NO_PROXY"'), /host\.docker\.internal/);
});

test('LIVE control: the same direct dial from a container on the ordinary app network is not refused for want of a route', { skip }, async () => {
  let out;
  try {
    out = (await execFileAsync('docker', ['run', '--rm', '--network', 'appcrane-apps', HELPER_IMAGE, 'sh', '-c', 'wget -T 5 -q -O /dev/null http://1.1.1.1/ 2>&1; echo rc=$?'], { timeout: 60000 })).stdout;
  } catch (e) { out = `${e.stdout}${e.stderr}`; }
  assert.doesNotMatch(out, /Network is unreachable/);
});
