import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'https';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The client metadata (CIMD) fetch and the IT setup connection test are
// reachable by people without an AppCrane account. A socket idle timeout does
// not bound a server that sends one byte just inside it, again and again: both
// need a wall-clock deadline that ends the request.

const dir = mkdtempSync(join(tmpdir(), 'crane-deadline-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
const key = readFileSync(join(dir, 'k.pem'));
const cert = readFileSync(join(dir, 'c.pem'));

const { fetchClientMetadata, configureCimdFetch } = await import('../server/services/oauthCimd.js');
const { testOidc, configureConnectionTestFetch } = await import('../server/services/itSetup/connectionTest.js');

let srv, port;
const timers = new Set();
before(async () => {
  srv = https.createServer({ key, cert }, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    const body = JSON.stringify({ client_id: `https://localhost:${port}/client.json`, issuer: 'x', padding: 'abcdefghij' });
    let i = 0;
    const t = setInterval(() => { if (i < body.length) res.write(body[i++]); else { clearInterval(t); timers.delete(t); res.end(); } }, 200);
    timers.add(t);
    res.on('close', () => { clearInterval(t); timers.delete(t); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  port = srv.address().port;
});
after(() => {
  for (const t of timers) clearInterval(t);
  srv.closeAllConnections?.();
  srv.close();
  rmSync(dir, { recursive: true, force: true });
});

const seams = () => ({ isBlocked: () => false, ca: cert, resolve: async () => [{ address: '127.0.0.1', family: 4 }], deadlineMs: 1000 });

test('CIMD: a document dripped one byte at a time is cut off at the deadline', async () => {
  configureCimdFetch(seams());
  const t0 = Date.now();
  const outcome = await fetchClientMetadata(`https://localhost:${port}/client.json`).then(() => 'resolved', (e) => e.message);
  const took = Date.now() - t0;
  configureCimdFetch({});
  assert.match(outcome, /no answer within|took longer/, `${outcome} after ${took} ms`);
  assert.ok(took < 3000, `took ${took} ms`);
});

test('IT setup connection test: a dripped discovery document is cut off at the deadline', async () => {
  configureConnectionTestFetch(seams());
  const t0 = Date.now();
  const r = await testOidc({ discovery_url: `https://localhost:${port}`, client_id: 'c' });
  const took = Date.now() - t0;
  configureConnectionTestFetch({});
  assert.equal(r.ok, false);
  assert.match(r.steps.find((s) => s.step === 'discovery').detail, /did not answer within/);
  assert.ok(took < 3000, `took ${took} ms`);
});
