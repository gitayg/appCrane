import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import http from 'http';
import express from 'express';

// Production on a custom domain (custom_domain_auth = 1) sleeps and is woken by
// a request to that domain, through a real caddy:2 running the Caddyfile
// AppCrane generates and a real container. Real: forward_auth into the real
// /api/identity/verify from the custom-domain block (which records the
// activity), its handle_errors rewrite with the wake token, the wake handler,
// `docker stop` / `docker start`, and the 307 back to the path on the domain.
// Faked: only the clock the sleeper decides with. Same pattern as
// env-sleep-live.test.js.

let noDocker = false;
try { execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 15000 }); } catch { noDocker = true; }
try { if (!noDocker) execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'ignore' }); } catch { noDocker = true; }
try { if (!noDocker) execFileSync('docker', ['image', 'inspect', 'python:3.12-alpine'], { stdio: 'ignore' }); } catch { noDocker = true; }

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-env-sleep-cd-live-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const DAY = 24 * 60 * 60_000;
const SLUG = `cdsleep${process.pid % 100000}`;
const DOMAIN = `${SLUG}.example.test`;
const SLOT = 800 + (process.pid % 150);
const containers = [];
const cleanup = [];
after(() => {
  for (const c of containers) { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'ignore', timeout: 30000 }); } catch { /* gone */ } }
  for (const f of cleanup) { try { f(); } catch { /* best effort */ } }
});

const APP_PY = `
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"from": "app", "path": self.path}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 3000), H).serve_forever()
`;

function request(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET', headers: { Host: DOMAIN, ...headers } }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}
const state = (name) => execFileSync('docker', ['inspect', '-f', '{{.State.Status}}', name], { encoding: 'utf8' }).trim();

test('production on a signed-in custom domain sleeps and a request to the domain wakes it', { skip: noDocker && 'docker, caddy:2 or python:3.12-alpine unavailable', timeout: 240_000 }, async (t) => {
  const { initDb, getDb } = await import('../server/db.js');
  const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
  initDb();
  const db = getDb();
  const policy = await import('../server/services/sleepPolicy.js');
  const sleeper = await import('../server/services/envSleeper.js');
  const { flushActivity, activityOf } = await import('../server/services/envActivity.js');
  const { sleepRow } = await import('../server/services/envSleepState.js');
  const { getPortsForSlot } = await import('../server/services/portAllocator.js');
  const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
  setAccessLogDirCheck(() => false);

  const key = generateApiKey('dhk_user');
  const userId = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('cdowner','cdowner@t.test','user',?,1,'human')").run(hashApiKey(key)).lastInsertRowid);
  const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,domain,custom_domain_auth) VALUES (?,?,?,'managed','authenticated',?,1)")
    .run('CD Sleep', SLUG, SLOT, DOMAIN).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, userId);
  db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, 'production', 'live', datetime('now','-30 days'), datetime('now','-30 days'))").run(appId);
  policy.setAppPolicy(db, appId, { inactive_days: 7 }, userId);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  assert.deepEqual(policy.sleepBlockers(db, app, 'production'), []);
  const ports = getPortsForSlot(SLOT);

  const name = `appcrane-${SLUG}-production`;
  containers.push(name);
  execFileSync('docker', ['run', '-d', '--name', name, '--label', 'appcrane=true', '--restart=on-failure:2',
    '-p', `127.0.0.1:${ports.prod_be}:3000`, 'python:3.12-alpine', 'python', '-c', APP_PY], { stdio: 'pipe', timeout: 120000 });

  const identityRoutes = (await import('../server/routes/identity.js')).default;
  const { handleSleepingRequest, _setWaitsForTests } = await import('../server/services/sleepWakeHandler.js');
  _setWaitsForTests({ api: 90_000, browser: 5_000 });
  cleanup.push(() => _setWaitsForTests({ api: 25_000, browser: 5_000 }));
  const crane = express();
  crane.use('/api/identity', identityRoutes);
  crane.all('/api/_crashed/*splat', async (req, res) => {
    if (await handleSleepingRequest(req, res)) return;
    res.status(503).type('text').send('crash page');
  });
  const craneSrv = await new Promise(r => { const s = crane.listen(0, '127.0.0.1', () => r(s)); });
  cleanup.push(() => { craneSrv.closeAllConnections?.(); craneSrv.close(); });
  const cranePort = craneSrv.address().port;

  const cf = generateCaddyfile();
  assert.match(cf, new RegExp(`\\n${DOMAIN.replace(/\./g, '\\.')} \\{\\n[\\s\\S]*?rewrite \\* /api/_crashed/${SLUG}\\{uri\\}\\n {12}request_header X-AppCrane-Wake "[A-Za-z0-9_-]{43}"`), 'the custom-domain block has no wake rewrite');
  const live = cf
    .replace(/^import .*$/m, '')
    .replace(/^(\S.*) \{$/gm, (_m, addr) => `http://${addr} {`)
    .replace(/127\.0\.0\.1:5001/g, `host.docker.internal:${cranePort}`)
    .replace(/127\.0\.0\.1:(\d+)/g, 'host.docker.internal:$1');
  const scratch = mkdtempSync(join(tmpdir(), 'crane-cd-sleep-caddy-'));
  writeFileSync(join(scratch, 'Caddyfile'), live);
  const caddyName = `appcrane-cd-sleep-caddy-${process.pid}`;
  containers.push(caddyName);
  const caddyPort = 21000 + (process.pid % 20000);
  execFileSync('docker', ['run', '-d', '--rm', '--name', caddyName, '--add-host', 'host.docker.internal:host-gateway',
    '-p', `127.0.0.1:${caddyPort}:80`, '-v', `${join(scratch, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe', timeout: 90000 });

  const auth = { 'X-API-Key': key };
  async function first(path) {
    for (let i = 0; i < 80; i++) {
      try {
        const r = await request(caddyPort, path, auth);
        if (r.status === 200) return r;
      } catch { /* caddy or the app still starting */ }
      await new Promise(r => setTimeout(r, 250));
    }
    return null;
  }
  const warm = await first('/hello');
  if (!warm) { t.skip('caddy container cannot reach the host upstreams (host-gateway networking unavailable)'); return; }
  assert.deepEqual(JSON.parse(warm.body), { from: 'app', path: '/hello' });
  const anon = await request(caddyPort, '/hello', { Accept: 'application/json' });
  assert.notEqual(anon.status, 200, 'the custom domain served the app without sign-in');

  // AppCrane saw the domain's request at forward_auth.
  flushActivity(db);
  assert.ok(activityOf(db, appId, 'production').lastRequestAt, 'a request on the custom domain was not counted');

  const r = await sleeper.runSleeper({ now: () => Date.now() + 8 * DAY, processStart: 0 });
  assert.ok(r.slept.some(s => s.name === name && s.reason === 'inactive'), JSON.stringify(r));
  assert.equal(state(name), 'exited');
  assert.equal(sleepRow(db, appId, 'production').state, 'sleeping');

  const woke = await request(caddyPort, '/page/1?q=2', auth);
  assert.equal(woke.status, 307, `${woke.status} ${woke.body.slice(0, 300)}`);
  assert.equal(woke.headers.location, '/page/1?q=2', 'the 307 did not go back to the path on the custom domain');
  assert.equal(state(name), 'running');
  assert.equal(sleepRow(db, appId, 'production').state, 'awake');
  const landed = await request(caddyPort, woke.headers.location, auth);
  assert.equal(landed.status, 200);
  assert.deepEqual(JSON.parse(landed.body), { from: 'app', path: '/page/1?q=2' });
});
