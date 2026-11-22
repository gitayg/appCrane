import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import http from 'http';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The egress proxy (services/egress/proxy.js) and the argv rewrite for an
// enforced container (services/egress/container.js), without Docker. The live
// container behaviour is test/egress-live.test.js.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-egress-proxy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_EGRESS_PRIVATE_HOSTS = 'allowed.t.test,a.wild.t.test,wild.t.test,evilwild.t.test,other.t.test';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const proxyMod = await import('../server/services/egress/proxy.js');
const policy = await import('../server/services/egress/policy.js');
const { applyEgressPlan, egressPlan } = await import('../server/services/egress/container.js');

proxyMod._setEgressResolverForTests(async () => [{ address: '127.0.0.1', family: 4 }]);

const target = http.createServer((req, res) => res.end(`TARGET_OK ${req.method} ${req.url} auth=${req.headers['proxy-authorization'] || 'none'}`));
await new Promise((r) => target.listen(0, '127.0.0.1', r));
const TPORT = target.address().port;
const running = await proxyMod.ensureEgressProxy('127.0.0.1', 0);
const PPORT = running.server.address().port;

after(async () => {
  target.close();
  await proxyMod.stopEgressProxy();
  rmSync(ROOT, { recursive: true, force: true });
});

function mkApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(slug, slug, getNextSlot(db)).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function grantHosts(app, hosts) {
  return db.prepare(`INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
    VALUES (?, 'egress', 'request', 'approved', ?, ?, 'test')`).run(app.id, JSON.stringify({ hosts }), JSON.stringify({ hosts })).lastInsertRowid;
}

const appA = mkApp('egr-a');
const appB = mkApp('egr-b');
const tokA = policy.egressToken(appA.id, 'production');
const tokB = policy.egressToken(appB.id, 'production');
const grantA = grantHosts(appA, [`allowed.t.test:${TPORT}`, `*.wild.t.test:${TPORT}`, `rebind.t.test:${TPORT}`]);
const basic = (t) => `Basic ${Buffer.from(`egress:${t}`).toString('base64')}`;

/** Raw CONNECT then a GET through the tunnel. Resolves the whole reply text. */
function connectThrough(hostPort, token) {
  return new Promise((resolve, reject) => {
    const s = net.connect(PPORT, '127.0.0.1', () => {
      s.write(`CONNECT ${hostPort} HTTP/1.1\r\nHost: ${hostPort}\r\n${token ? `Proxy-Authorization: ${basic(token)}\r\n` : ''}\r\n`);
    });
    let buf = '';
    let sent = false;
    s.on('data', (d) => {
      buf += d.toString();
      if (!sent && buf.startsWith('HTTP/1.1 200')) { sent = true; s.write('GET /through HTTP/1.0\r\nHost: x\r\n\r\n'); }
    });
    s.on('end', () => resolve(buf));
    s.on('error', reject);
    setTimeout(() => { s.destroy(); resolve(buf); }, 3000);
  });
}

function plainThrough(url, token) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: PPORT, method: 'GET', path: url, headers: token ? { 'proxy-authorization': basic(token) } : {} }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    r.on('error', reject);
    r.end();
  });
}

test('CONNECT to an allow-listed host tunnels; wildcards match subdomains only', async () => {
  const ok = await connectThrough(`allowed.t.test:${TPORT}`, tokA);
  assert.match(ok, /^HTTP\/1\.1 200 Connection Established/);
  assert.match(ok, /TARGET_OK GET \/through/);
  assert.match(await connectThrough(`a.wild.t.test:${TPORT}`, tokA), /TARGET_OK/);
  assert.match(await connectThrough(`wild.t.test:${TPORT}`, tokA), /^HTTP\/1\.1 403[^]*allow-list/);
  assert.match(await connectThrough(`evilwild.t.test:${TPORT}`, tokA), /^HTTP\/1\.1 403[^]*allow-list/);
});

test('a host not on the list, another port, or an IP literal is refused', async () => {
  assert.match(await connectThrough(`other.t.test:${TPORT}`, tokA), /^HTTP\/1\.1 403[^]*not on this app's egress allow-list/);
  assert.match(await connectThrough('allowed.t.test:22', tokA), /^HTTP\/1\.1 403/);
  assert.match(await connectThrough(`127.0.0.1:${TPORT}`, tokA), /^HTTP\/1\.1 403[^]*IP address targets are refused/);
  assert.match(await connectThrough(`[::1]:${TPORT}`, tokA), /^HTTP\/1\.1 403/);
});

test('an allow-listed name that resolves to a private address is refused at connect time', async () => {
  const r = await connectThrough(`rebind.t.test:${TPORT}`, tokA);
  assert.match(r, /^HTTP\/1\.1 403[^]*private, loopback or link-local/);
  assert.doesNotMatch(r, /TARGET_OK/);
});

test('no token, a bad token, or another app\'s token (without the grant) is refused', async () => {
  assert.match(await connectThrough(`allowed.t.test:${TPORT}`, null), /^HTTP\/1\.1 407/);
  assert.match(await connectThrough(`allowed.t.test:${TPORT}`, 'aceg_not-a-real-token'), /^HTTP\/1\.1 407/);
  assert.match(await connectThrough(`allowed.t.test:${TPORT}`, tokB), /^HTTP\/1\.1 403/);
});

test('plain http through the proxy: allowed host forwarded without the proxy credential, others refused', async () => {
  const ok = await plainThrough(`http://allowed.t.test:${TPORT}/plain?q=1`, tokA);
  assert.equal(ok.status, 200);
  assert.equal(ok.body, 'TARGET_OK GET /plain?q=1 auth=none');
  assert.equal((await plainThrough(`http://other.t.test:${TPORT}/`, tokA)).status, 403);
  assert.equal((await plainThrough(`http://127.0.0.1:${TPORT}/`, tokA)).status, 403);
  assert.equal((await plainThrough(`http://allowed.t.test:${TPORT}/`, null)).status, 407);
});

test('a revoked grant applies to the next connection; refusals and first use are in the event store', async () => {
  db.prepare("UPDATE capability_requests SET status = 'revoked' WHERE id = ?").run(grantA);
  assert.match(await connectThrough(`allowed.t.test:${TPORT}`, tokA), /^HTTP\/1\.1 403/);
  const kinds = db.prepare("SELECT kind, data FROM events WHERE app_id = ? AND kind LIKE 'egress.%'").all(appA.id);
  assert.ok(kinds.some((k) => k.kind === 'egress.allowed' && JSON.parse(k.data).host === 'allowed.t.test'));
  assert.ok(kinds.some((k) => k.kind === 'egress.refused' && JSON.parse(k.data).host === 'other.t.test'));
  assert.ok(!JSON.stringify(kinds).includes(tokA), 'no token in the log');
});

test('enforcement is off by default (no plan, no docker), and the argv rewrite moves publishes and add-host to the anchor', async () => {
  assert.equal(await egressPlan({ slug: appA.slug, env: 'production' }), null);
  const args = ['run', '-d', '--name', 'appcrane-egr-a-production', '--network', 'appcrane-apps', '--cap-drop', 'NET_RAW',
    '-p', '127.0.0.1:41000:3000', '-p', '0.0.0.0:31000:3000', '--add-host', 'host.docker.internal:172.20.0.1', '-e', 'A=1'];
  const { appArgs, publish } = applyEgressPlan(args, { anchor: 'crane-egress-anchor.egr-a.production' });
  assert.deepEqual(appArgs, ['run', '-d', '--name', 'appcrane-egr-a-production', '--network', 'container:crane-egress-anchor.egr-a.production', '--cap-drop', 'NET_RAW', '-e', 'A=1']);
  assert.deepEqual(publish, ['-p', '127.0.0.1:41000:3000', '-p', '0.0.0.0:31000:3000']);
});

test('the egress capability scope: names, wildcards and ports only', async () => {
  const { capabilityOf } = await import('../server/services/capabilities/registry.js');
  const c = capabilityOf('egress');
  assert.deepEqual(c.normalizeScope({ hosts: ['API.Example.test', '*.example.test:8443'] }), { hosts: ['*.example.test:8443', 'api.example.test'] });
  for (const hosts of [['1.2.3.4'], ['http://x.test'], ['x.test:0'], ['x.test:70000'], []]) assert.throws(() => c.normalizeScope({ hosts }), { status: 400 });
  assert.equal(c.covers([{ hosts: ['a.test'] }], { hosts: ['b.test'] }), false);
});
