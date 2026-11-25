import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// LIVE: a container started with the --add-host value hostGateway.js resolves
// reaches a listener on this host through host.docker.internal, and its
// /etc/hosts passes the Job Health check. Skips without a reachable daemon.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-hostgw-live-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.HOST_GATEWAY_IP;

let noDocker = false;
try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 15000, stdio: 'pipe' }); } catch (e) {
  noDocker = `no reachable Docker daemon (${String(e.stderr || e.message).trim().split('\n')[0]})`;
}

const { initDb } = await import('../server/db.js');
initDb();
const hg = await import('../server/services/hostGateway.js');
const NAME = `appcrane-hgwlive-${process.pid}`;

after(() => {
  if (!noDocker) { try { execFileSync('docker', ['rm', '-f', NAME], { stdio: 'pipe' }); } catch (_) {} }
  rmSync(ROOT, { recursive: true, force: true });
});

test('LIVE: the resolved mapping reaches the host and is not flagged as broken', { skip: noDocker }, async () => {
  const addHost = await hg.resolveHostGatewayAddHost();
  const srv = http.createServer((_q, s) => s.end('HOST-OK'));
  await new Promise((r) => srv.listen(0, '0.0.0.0', r));
  const port = srv.address().port;
  try {
    execFileSync('docker', ['run', '-d', '--name', NAME, '--add-host', addHost, 'alpine:latest', 'sleep', '120'], { stdio: 'pipe', timeout: 120000 });
    let body = '';
    for (let i = 0; i < 10 && body !== 'HOST-OK'; i++) {
      try {
        // async: a sync exec would block this process's event loop, so the listener above could never answer
        ({ stdout: body } = await execFileAsync('docker', ['exec', NAME, 'wget', '-T', '4', '-q', '-O', '-', `http://host.docker.internal:${port}/`], { encoding: 'utf8', timeout: 20000 }));
      } catch (_) { await new Promise((r) => setTimeout(r, 500)); }
    }
    assert.equal(body, 'HOST-OK', `a container with --add-host ${addHost} could not reach the host`);
    const r = await hg.checkContainerGateways();
    assert.ok(!r.broken.some((b) => b.name === NAME), JSON.stringify(r));
  } finally {
    srv.close();
  }
});
