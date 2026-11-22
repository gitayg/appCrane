import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';

import { probeBackoffMs } from '../server/services/probeBackoff.js';
import { __testables } from '../server/services/deployer.js';

test('probe backoff: 250 ms doubling to a 2 s cap', () => {
  assert.deepEqual(Array.from({ length: 8 }, (_, i) => probeBackoffMs(i)), [250, 500, 1000, 2000, 2000, 2000, 2000, 2000]);
});

test('a health endpoint that comes up after ~300 ms is seen well before the old 2 s sleep', async () => {
  let up = false;
  const server = http.createServer((req, res) => {
    if (!up) { res.writeHead(503); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '1' }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  setTimeout(() => { up = true; }, 300);
  const t0 = Date.now();
  try {
    const r = await __testables.probeHealthEndpoint(`http://127.0.0.1:${port}/api/health`, 10000);
    const took = Date.now() - t0;
    assert.equal(r.ok, true);
    assert.ok(took < 1500, `took ${took} ms`);
  } finally {
    server.close();
  }
});

test('the overall deadline is unchanged: a never-healthy endpoint times out at the deadline', async () => {
  const server = http.createServer((req, res) => { res.writeHead(503); res.end(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const t0 = Date.now();
  try {
    const r = await __testables.probeHealthEndpoint(`http://127.0.0.1:${port}/api/health`, 1200);
    const took = Date.now() - t0;
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'timeout');
    assert.ok(took >= 1200 && took < 3500, `took ${took} ms`);
  } finally {
    server.close();
  }
});
