import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startBackupTrace, stopBackupTrace, traceBackup } from '../server/services/backupTrace.js';
import { summarize, hostFacts } from './backup-loop-diag.mjs';

test('backupTrace records marks only while a trace is running', () => {
  traceBackup('before');
  const sink = startBackupTrace();
  traceBackup('tar:start');
  traceBackup('snapshot:vacuum-in-worker', { start: 1, end: 2 });
  const marks = stopBackupTrace();
  traceBackup('after');
  assert.equal(marks, sink);
  assert.deepEqual(marks.map((m) => m.name), ['tar:start', 'snapshot:vacuum-in-worker']);
  assert.equal(marks[1].start, 1);
  assert.ok(marks[0].t > performance.timeOrigin);
  assert.deepEqual(stopBackupTrace(), []);
});

const T0 = 1_000_000;
const facts = { cpus: 2, parallelism: 2, loadavg: [1, 1, 1], fs: { type: 'ext4', freeMb: 1 }, blockDev: '8:0' };
const marks = [
  { t: T0 + 1, name: 'snapshot:start' }, { t: T0 + 100, name: 'snapshot:end' },
  { t: T0 + 101, name: 'tar:start' }, { t: T0 + 900, name: 'tar:end' },
];

function run(stall, extra = {}) {
  const ticks = [{ t: T0 + 200, lag: 1 }, { t: T0 + 500, lag: 290, intervalMs: 300, ...stall }];
  const raw = { ticks, writes: [], gcs: [], heapStart: process.memoryUsage(), heapEnd: process.memoryUsage(), ...extra };
  return summarize(raw, { marks, exportStart: T0, exportEnd: T0 + 1000, facts, bounds: {}, probe: { max: 5, worstAt: T0 + 210 } });
}

test('summarize: a stall off CPU inside a slow write names the write and the open phase', () => {
  const { report, human } = run({ mainRunMs: 3, mainWaitMs: 1 }, { writes: [{ t: T0 + 205, ms: 285 }, { t: T0 + 50, ms: 1 }] });
  assert.match(report.verdict, /OFF CPU/);
  assert.match(report.verdict, /inside a main-thread DB write/);
  assert.deepEqual(report.worstStall.openPhases, ['tar']);
  assert.deepEqual(report.worstStall.writes, [{ t: 205, ms: 285 }]);
  assert.equal(report.writes.slowest[0].ms, 285);
  assert.equal(report.probe.at, 210);
  assert.equal(human.length, 5);
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(report)));
});

test('summarize: on CPU, starved, GC-dominated and unknown are told apart', () => {
  assert.match(run({ mainRunMs: 280, mainWaitMs: 5 }).report.verdict, /ON CPU/);
  assert.match(run({ mainRunMs: 10, mainWaitMs: 250 }).report.verdict, /RUNNABLE but not scheduled/);
  assert.match(run({ mainRunMs: 280, mainWaitMs: 0 }, { gcs: [{ t: T0 + 210, ms: 200, kind: 4 }] }).report.verdict, /GC took 200 ms/);
  assert.match(run({ mainRunMs: null, mainWaitMs: null }).report.verdict, /unknown/);
});

test('summarize: kernel CPU and hypervisor steal are named, and carried into the report', () => {
  const kernel = run({ mainRunMs: 280, mainWaitMs: 0, mainUserMs: 20, mainSysMs: 260, machine: { busyPct: 60, idlePct: 5, iowaitPct: 0, stealPct: 35 } });
  assert.match(kernel.report.verdict, /ON CPU in the KERNEL/);
  assert.match(kernel.report.verdict, /hypervisor stole 35%/);
  assert.equal(kernel.report.worstStall.mainSysMs, 260);
  assert.equal(kernel.report.stalls[0].steal, 35);
  const js = run({ mainRunMs: 280, mainWaitMs: 0, mainUserMs: 270, mainSysMs: 10, machine: { busyPct: 50, idlePct: 50, iowaitPct: 0, stealPct: 0 } });
  assert.match(js.report.verdict, /ON CPU \(JS/);
  assert.doesNotMatch(js.report.verdict, /stole/);
});

test('summarize: no tick over 50 ms reports no stall', () => {
  const raw = { ticks: [{ t: T0 + 10, lag: 3 }], writes: [], gcs: [], heapStart: process.memoryUsage(), heapEnd: process.memoryUsage() };
  const { report } = summarize(raw, { marks, exportStart: T0, exportEnd: T0 + 1000, facts, bounds: {}, probe: null });
  assert.equal(report.verdict, 'no stall over 50 ms');
  assert.deepEqual(report.stalls, []);
});

test('hostFacts reports CPU count, parallelism and the filesystem of a directory', () => {
  const f = hostFacts(process.cwd());
  assert.ok(f.cpus >= 1 && f.parallelism >= 1);
  assert.equal(typeof f.fs.type, 'string');
  assert.ok(f.fs.freeMb >= 0);
});
