import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import http from 'http';
import express from 'express';

// Environment sleep end to end, with real containers and a real caddy:2 running
// the Caddyfile AppCrane generates. Real here: forward_auth into the real
// /api/identity/verify (which records the activity), the real handle_errors
// rewrite with the wake token, the real wake handler, `docker stop` and
// `docker start` of the app container, and the 307 back into the app. Faked:
// only the clock the sleeper decides with.

let noDocker = false;
try { execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 15000 }); } catch { noDocker = true; }
try { if (!noDocker) execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'ignore' }); } catch { noDocker = true; }
try { if (!noDocker) execFileSync('docker', ['image', 'inspect', 'python:3.12-alpine'], { stdio: 'ignore' }); } catch { noDocker = true; }

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-env-sleep-live-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const MIN = 60_000, DAY = 24 * 60 * MIN;
const SLUG = `sleeplive${process.pid % 100000}`;
const SLOT = 600 + (process.pid % 200);
const containers = [];
const cleanup = [];
after(() => {
  for (const c of containers) { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'ignore', timeout: 30000 }); } catch { /* gone */ } }
  for (const f of cleanup) { try { f(); } catch { /* best effort */ } }
});

const APP_PY = `
import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"from": "app", "env": os.environ.get("APP_ENV"), "path": self.path}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 3000), H).serve_forever()
`;

function request(port, path, headers = {}, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: 'crane.test.local', ...headers } }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}
const state = (name) => execFileSync('docker', ['inspect', '-f', '{{.State.Status}}', name], { encoding: 'utf8' }).trim();

test('sleep and wake through real Caddy and real containers', { skip: noDocker && 'docker, caddy:2 or python:3.12-alpine unavailable', timeout: 240_000 }, async (t) => {
  const { initDb, getDb } = await import('../server/db.js');
  const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
  initDb();
  const db = getDb();
  const policy = await import('../server/services/sleepPolicy.js');
  const sleeper = await import('../server/services/envSleeper.js');
  const wake = await import('../server/services/envWake.js');
  const { sleepRow } = await import('../server/services/envSleepState.js');
  const { getPortsForSlot } = await import('../server/services/portAllocator.js');
  const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
  setAccessLogDirCheck(() => false);

  const key = generateApiKey('dhk_user');
  const userId = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('liveowner','liveowner@t.test','user',?,1,'human')").run(hashApiKey(key)).lastInsertRowid);
  const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode) VALUES (?,?,?,'managed','authenticated')").run('Sleep Live', SLUG, SLOT).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, userId);
  for (const env of ['sandbox', 'production']) {
    db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, ?, 'live', datetime('now','-30 days'), datetime('now','-30 days'))").run(appId, env);
  }
  policy.setAppPolicy(db, appId, { sandbox_idle_minutes: 10, inactive_days: 7 }, userId);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  const ports = getPortsForSlot(SLOT);

  for (const [env, port] of [['sandbox', ports.sand_be], ['production', ports.prod_be]]) {
    const name = `appcrane-${SLUG}-${env}`;
    containers.push(name);
    execFileSync('docker', ['run', '-d', '--name', name, '--label', 'appcrane=true', '--restart=on-failure:2',
      '-e', `APP_ENV=${env}`, '-p', `127.0.0.1:${port}:3000`, 'python:3.12-alpine', 'python', '-c', APP_PY], { stdio: 'pipe', timeout: 120000 });
  }

  // AppCrane: the real identity router and the crash route exactly as index.js mounts it.
  const identityRoutes = (await import('../server/routes/identity.js')).default;
  const { handleSleepingRequest, _setWaitsForTests } = await import('../server/services/sleepWakeHandler.js');
  // The API wait is 25 s in production. A busy Docker daemon on a shared test
  // host has taken longer than that to start one container, which would turn
  // this into a test of the host; the bound itself is covered in env-sleep.test.js.
  _setWaitsForTests({ api: 90_000, browser: 5_000 });
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
  assert.match(cf, /request_header X-AppCrane-Wake "[A-Za-z0-9_-]{43}"/, 'the crash rewrite carries no wake token');
  const live = cf
    .replace(/^import .*$/m, '')
    .replace(/^(\S.*) \{$/gm, (_m, addr) => `http://${addr} {`)
    .replace(/127\.0\.0\.1:5001/g, `host.docker.internal:${cranePort}`)
    .replace(/127\.0\.0\.1:(\d+)/g, 'host.docker.internal:$1');
  const scratch = mkdtempSync(join(tmpdir(), 'crane-sleep-caddy-'));
  writeFileSync(join(scratch, 'Caddyfile'), live);
  const caddyName = `appcrane-sleep-caddy-${process.pid}`;
  containers.push(caddyName);
  const caddyPort = 20000 + (process.pid % 20000);
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
  const warm = await first(`/${SLUG}-sandbox/hello`);
  if (!warm) { t.skip('caddy container cannot reach the host upstreams (host-gateway networking unavailable)'); return; }
  assert.equal(JSON.parse(warm.body).env, 'sandbox');
  assert.ok(await first(`/${SLUG}/hello`), 'production not reachable through caddy');

  // What the health checker does: probe the loopback port directly. None of it may count.
  for (let i = 0; i < 20; i++) {
    const r = await fetch(`http://127.0.0.1:${ports.sand_be}/api/health`);
    await r.text();
  }

  const t0 = Date.now();
  let r = await sleeper.runSleeper({ now: () => t0 + 9 * MIN, processStart: 0 });
  assert.equal(r.slept.length, 0, 'asleep before 10 idle minutes');
  r = await sleeper.runSleeper({ now: () => t0 + 11 * MIN, processStart: 0 });
  assert.deepEqual(r.slept.map(s => s.name), [`appcrane-${SLUG}-sandbox`], `expected only the sandbox asleep: ${JSON.stringify(r)}`);
  assert.equal(state(`appcrane-${SLUG}-sandbox`), 'exited', 'the sandbox container is still running');
  assert.equal(state(`appcrane-${SLUG}-production`), 'running', 'production was put to sleep by the minutes rule');
  assert.equal(sleepRow(db, appId, 'sandbox').state, 'sleeping');

  // Twelve requests at once while it sleeps: one docker start, every one answered.
  let startCalls = 0;
  wake._setWakeDepsForTests({
    docker: async (args, timeout) => {
      if (args[0] === 'start') startCalls++;
      return execFileSync('docker', args, { encoding: 'utf8', timeout });
    },
  });
  cleanup.push(() => wake._setWakeDepsForTests(null));
  const burst = await Promise.all(Array.from({ length: 12 }, (_, i) => request(caddyPort, `/${SLUG}-sandbox/item/${i}?q=${i}`, auth)));
  assert.equal(startCalls, 1, `${startCalls} docker starts for 12 concurrent requests`);
  for (const [i, b] of burst.entries()) {
    assert.equal(b.status, 307, `request ${i}: ${b.status} ${b.body.slice(0, 200)}`);
    assert.equal(b.headers.location, `/${SLUG}-sandbox/item/${i}?q=${i}`);
    const followed = await request(caddyPort, b.headers.location, auth);
    assert.equal(followed.status, 200, `request ${i} after the redirect: ${followed.status}`);
    assert.deepEqual(JSON.parse(followed.body), { from: 'app', env: 'sandbox', path: `/item/${i}?q=${i}` });
  }
  assert.equal(state(`appcrane-${SLUG}-sandbox`), 'running');
  assert.equal(sleepRow(db, appId, 'sandbox').state, 'awake');

  // Production: only after 7 days with no request and no deploy. Then a browser visit wakes it.
  r = await sleeper.runSleeper({ now: () => Date.now() + 8 * DAY, processStart: 0 });
  assert.ok(r.slept.some(s => s.name === `appcrane-${SLUG}-production` && s.reason === 'inactive'), JSON.stringify(r));
  assert.equal(state(`appcrane-${SLUG}-production`), 'exited');
  const mails = db.prepare("SELECT to_email FROM email_queue WHERE app_id = ? AND env = 'production'").all(appId);
  assert.deepEqual(mails.map(m => m.to_email), ['liveowner@t.test']);

  const browser = await request(caddyPort, `/${SLUG}/page`, { ...auth, Accept: 'text/html' });
  let landed;
  if (browser.status === 307) {
    landed = await request(caddyPort, browser.headers.location, auth);
  } else {
    assert.equal(browser.status, 503);
    assert.match(browser.body, /Waking up/);
    assert.match(browser.body, /http-equiv="refresh"/);
    landed = await first(`/${SLUG}/page`);
  }
  assert.equal(landed.status, 200);
  assert.deepEqual(JSON.parse(landed.body), { from: 'app', env: 'production', path: '/page' });
  assert.equal(sleepRow(db, appId, 'production').state, 'awake');
});
