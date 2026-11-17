import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import http from 'http';
import { tmpdir } from 'os';
import { join } from 'path';

// A kind='http' cron reads the app's answer into AppCrane's own process. The
// app chooses how big that answer is, so the read must stop at a fixed limit
// instead of buffering whatever the app sends.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cron-body-cap-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const { runHttpCron, BODY_READ_LIMIT_BYTES } = await import('../server/services/cronHttp.js');

after(() => rmSync(ROOT, { recursive: true, force: true }));

function listen(handler) {
  return new Promise((res) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => res(s));
  });
}

const app = { id: 999999, slug: 'cap', slot: 1 };
const job = { env: 'production', http_path: '/api/cron', schedule: '0 9 * * *', timeout_seconds: 60 };

test('an app that never stops answering is cut off at the read limit, not at the job timeout', async () => {
  let sent = 0;
  let closed = false;
  const chunk = Buffer.alloc(64 * 1024, 'x');
  const server = await listen((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    req.socket.on('close', () => { closed = true; });
    const pump = () => {
      while (!closed && res.write(chunk)) sent += chunk.length;
      if (!closed) res.once('drain', pump);
    };
    pump();
  });
  const { port } = server.address();
  const started = Date.now();
  const r = await runHttpCron(app, job, { fetchImpl: (_u, opts) => fetch(`http://127.0.0.1:${port}/`, opts) });
  const took = Date.now() - started;
  server.closeAllConnections();
  server.close();

  assert.equal(r.httpStatus, 200);
  assert.equal(r.exitCode, 0);
  assert.ok(took < 10000, `the read stopped on its own (took ${took} ms)`);
  assert.ok(sent < BODY_READ_LIMIT_BYTES * 16, `the app was not drained (${sent} bytes sent)`);
  const logged = r.log.split('\n').slice(1).join('\n');
  assert.ok(logged.length > 0 && logged.length <= 2048, `only the tail is kept (${logged.length})`);
});

test('a small answer is logged whole', async () => {
  const server = await listen((_req, res) => { res.writeHead(500); res.end('backup failed: disk full'); });
  const { port } = server.address();
  const r = await runHttpCron(app, job, { fetchImpl: (_u, opts) => fetch(`http://127.0.0.1:${port}/`, opts) });
  server.close();
  assert.equal(r.httpStatus, 500);
  assert.equal(r.exitCode, 1);
  assert.match(r.log, /HTTP 500\nbackup failed: disk full$/);
});
