import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'child_process';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { monitorEventLoopDelay } from 'perf_hooks';
import http from 'http';
import Database from 'better-sqlite3';

// A data export must not freeze AppCrane. While it runs, the same process
// answers the SSO forward_auth check every signed-in hosted app waits on, so a
// synchronous export is an outage for every app for its duration.
//
// Property, measured on a fixture of a few hundred MB (DB + /data):
//   - event-loop delay (perf_hooks) stays under a bound for the whole export;
//   - a lightweight HTTP route in the same process, probed from ANOTHER
//     process, keeps answering promptly (this is the one that catches a
//     blocking snapshot; the in-process histogram measurably does not);
//   - both bounds are fractions of a synchronous snapshot of the same DB timed
//     on the same host, so the test can fail wherever it runs;
//   - writes continue during the export, and the DB copy in the archive is a
//     valid point-in-time snapshot of them: two tables written in one
//     transaction agree row for row, ids are gapless, integrity_check is ok.

const PROBER = `
const http = require('http');
const url = process.argv[1];
let phase = 'warmup';
const during = [];
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => { if (d.includes('start')) phase = 'during'; if (d.includes('stop')) phase = 'stop'; });
(async () => {
  while (phase !== 'stop') {
    const counted = phase === 'during';
    const t0 = performance.now();
    await new Promise((r) => http.get(url, (res) => { res.resume(); res.on('end', r); }).on('error', r));
    if (counted) during.push(performance.now() - t0);
    await new Promise((r) => setTimeout(r, 20));
  }
  process.stdout.write(JSON.stringify({ during: during.length, max: during.length ? Math.max(...during) : null }));
})();
`;

const MB = 1024 * 1024;
// The property has to be able to FAIL on the host running it. A fixed bound
// did not: a synchronous VACUUM INTO of this 512 MB DB takes 1224 ms on one
// macOS box and 307 ms on node:22-bookworm, so a main-thread snapshot mutation
// went red on macOS and stayed green on Linux. The test now times that
// synchronous snapshot on the same DB first (the control), refuses a fixture too
// small to tell the difference, and bounds the export at a third of it. The rows
// are compressible so the gzip step does not dominate the run time.
const DB_MB = Number(process.env.BACKUP_LOOP_DB_MB || 512);
const DATA_MB = Number(process.env.BACKUP_LOOP_DATA_MB || 128);
const LOOP_BOUND_MS = 250;
const MIN_CONTROL_MS = 150;
const HTTP_BOUND_MS = 400;

const ROOT = mkdtempSync(join(tmpdir(), 'crane-loop-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { exportDataArchive } = await import('../server/services/configBackup.js');

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

test(`export of a ${DB_MB} MB DB + ${DATA_MB} MB /data keeps the event loop and HTTP responsive, and snapshots consistently under writes`, async () => {
  db.exec('CREATE TABLE filler (b BLOB); CREATE TABLE ledger_a (id INTEGER PRIMARY KEY, v INTEGER); CREATE TABLE ledger_b (id INTEGER PRIMARY KEY, v INTEGER);');
  const ins = db.prepare('INSERT INTO filler (b) VALUES (?)');
  db.transaction(() => { for (let i = 0; i < DB_MB; i++) ins.run(Buffer.alloc(MB, i & 255)); })();
  const dataDir = join(ROOT, 'apps', 'big', 'production', 'shared', 'data');
  mkdirSync(dataDir, { recursive: true });
  for (let i = 0; i < DATA_MB / 8; i++) writeFileSync(join(dataDir, `f${i}.bin`), randomBytes(8 * MB));

  const insA = db.prepare('INSERT INTO ledger_a (id, v) VALUES (?, ?)');
  const insB = db.prepare('INSERT INTO ledger_b (id, v) VALUES (?, ?)');
  let next = 1;
  const write = db.transaction(() => { insA.run(next, next * 3); insB.run(next, next * 3); next++; });
  for (let i = 0; i < 50; i++) write();
  const rowsAtStart = next - 1;

  // Control: what a main-thread snapshot of THIS database costs on THIS host.
  db.pragma('wal_checkpoint(TRUNCATE)');
  const controlFile = join(ROOT, 'control.db');
  const c0 = performance.now();
  db.exec(`VACUUM INTO '${controlFile}'`);
  const controlMs = performance.now() - c0;
  rmSync(controlFile);
  assert.ok(controlMs >= MIN_CONTROL_MS,
    `fixture too small to prove anything here: a synchronous snapshot of it blocks only ${controlMs.toFixed(0)} ms; raise BACKUP_LOOP_DB_MB`);
  const loopBound = Math.min(LOOP_BOUND_MS, controlMs / 3);
  // The HTTP bound is calibrated too, and it is the assertion that matters for
  // a snapshot on the main thread: measured on node:22-bookworm, a 363 ms
  // synchronous VACUUM INTO inside the export left monitorEventLoopDelay's max
  // at 12.3 ms while the out-of-process probe waited 369.7 ms (macOS: probe
  // 541 ms). A fixed 400 ms bound let that mutation pass on Linux.
  const httpBound = Math.min(HTTP_BOUND_MS, controlMs / 2);

  const server = http.createServer((_q, s) => s.end('ok'));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/`;

  // The HTTP client runs in ANOTHER PROCESS. An in-process prober shares the
  // blocked loop: measured against the old synchronous export it reported a
  // 5.2 ms worst case while the loop was blocked for 4154 ms, because its next
  // request simply was not sent until the block ended.
  const prober = spawn(process.execPath, ['-e', PROBER, url], { stdio: ['pipe', 'pipe', 'inherit'] });
  let proberOut = '';
  prober.stdout.on('data', (d) => { proberOut += d; });
  const proberDone = new Promise((r) => prober.on('close', r));
  await new Promise((r) => setTimeout(r, 400));
  const writer = setInterval(() => write(), 5);

  const h = monitorEventLoopDelay({ resolution: 10 });
  prober.stdin.write('start\n');
  h.enable();
  const t0 = performance.now();
  const out = await exportDataArchive({ version: 'loop-test' });
  const elapsed = performance.now() - t0;
  h.disable();
  clearInterval(writer);
  prober.stdin.end('stop\n');
  await proberDone;
  server.close();
  const rowsAtEnd = next - 1;
  const { max: httpMax, during } = JSON.parse(proberOut);

  const loopMax = h.max / 1e6;
  console.log(`# control: synchronous VACUUM INTO of the same DB blocks ${controlMs.toFixed(0)} ms -> loop bound ${loopBound.toFixed(0)} ms, HTTP bound ${httpBound.toFixed(0)} ms`);
  console.log(`# export ${elapsed.toFixed(0)} ms, archive ${out.bytes} bytes; event-loop delay max=${loopMax.toFixed(1)} ms p99=${(h.percentile(99) / 1e6).toFixed(1)} ms; ` +
    `HTTP probes during export (out of process)=${during} max=${httpMax.toFixed(1)} ms; ledger rows start=${rowsAtStart} end=${rowsAtEnd}`);
  assert.ok(loopMax < loopBound, `event loop blocked for ${loopMax.toFixed(1)} ms during export (bound ${loopBound.toFixed(0)} ms: a third of the ${controlMs.toFixed(0)} ms synchronous control)`);
  assert.ok(during >= 5, `only ${during} HTTP probes were sent during a ${elapsed.toFixed(0)} ms export`);
  assert.ok(httpMax < httpBound, `a lightweight route took ${httpMax.toFixed(1)} ms to answer during export (bound ${httpBound.toFixed(0)} ms: half of the ${controlMs.toFixed(0)} ms synchronous control)`);
  assert.ok(rowsAtEnd > rowsAtStart + 10, 'fixture: writes must actually continue during the export');

  const x = mkdtempSync(join(tmpdir(), 'crane-loop-x-'));
  try {
    execFileSync('tar', ['-xzf', out.path, '-C', x, 'deployhub.db']);
    const snap = new Database(join(x, 'deployhub.db'), { readonly: true });
    try {
      assert.equal(snap.pragma('integrity_check', { simple: true }), 'ok');
      const a = snap.prepare('SELECT COUNT(*) c, COALESCE(MAX(id),0) m, COALESCE(SUM(v),0) s FROM ledger_a').get();
      const b = snap.prepare('SELECT COUNT(*) c, COALESCE(MAX(id),0) m, COALESCE(SUM(v),0) s FROM ledger_b').get();
      const unmatched = snap.prepare('SELECT COUNT(*) c FROM ledger_a LEFT JOIN ledger_b USING (id) WHERE ledger_b.id IS NULL OR ledger_b.v != ledger_a.v').get().c;
      console.log(`# snapshot ledger: a=${JSON.stringify(a)} b=${JSON.stringify(b)} unmatched=${unmatched}`);
      assert.deepEqual(a, b, 'two tables written in one transaction disagree in the snapshot');
      assert.equal(unmatched, 0);
      assert.equal(a.c, a.m, 'ids are not gapless: the snapshot is not a single point in time');
      assert.ok(a.c >= rowsAtStart && a.c <= rowsAtEnd, `snapshot holds ${a.c} rows, outside [${rowsAtStart}, ${rowsAtEnd}]`);
      assert.equal(snap.prepare('SELECT COUNT(*) c FROM filler').get().c, DB_MB);
    } finally {
      snap.close();
    }
  } finally {
    rmSync(x, { recursive: true, force: true });
  }
});
