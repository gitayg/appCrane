// Diagnostics for test/backup-event-loop.test.js. When the export stalls the
// event loop on a machine nobody can attach a profiler to (the CI runner), the
// test prints what this collects: which export phase was running, what the
// main thread was doing during the worst stall (on CPU, waiting for a CPU, or
// off CPU in a syscall), the main-thread DB writes and GC pauses that overlap
// it, and the host facts that decide all of that.
//
// Every time is absolute ms (performance.timeOrigin + now) so marks from
// server/services/backupTrace.js, worker threads and the prober process line up.

import { PerformanceObserver } from 'perf_hooks';
import { readFileSync, statfsSync, statSync } from 'fs';
import os from 'os';

const nowAbs = () => performance.timeOrigin + performance.now();
const TICK_MS = 10;
const STALL_MS = 50;
const r1 = (n) => (n == null ? null : Math.round(n * 10) / 10);

function readText(p) {
  try { return readFileSync(p, 'utf8'); } catch (_) { return null; }
}

// Linux: main thread's on-CPU and run-queue-wait nanoseconds.
function schedstat() {
  const s = readText(`/proc/self/task/${process.pid}/schedstat`);
  if (!s) return null;
  const [run, wait] = s.trim().split(/\s+/).map(Number);
  return { run, wait };
}

// Linux: main thread's user and kernel CPU in clock ticks (USER_HZ, 100/s).
function taskTimes() {
  const s = readText(`/proc/self/task/${process.pid}/stat`);
  if (!s) return null;
  const f = s.slice(s.lastIndexOf(')') + 2).split(' ');
  return { user: Number(f[11]), sys: Number(f[12]) };
}

// Linux: whole-machine CPU ticks, to tell a busy or stolen CPU from a blocked thread.
function cpuTimes() {
  const s = readText('/proc/stat');
  if (!s) return null;
  const [, user, nice, system, idle, iowait, irq, softirq, steal] = s.slice(0, s.indexOf('\n')).trim().split(/\s+/).map(Number);
  return { busy: user + nice + system + irq + softirq, idle, iowait, steal: steal || 0 };
}

function shares(a, b) {
  if (!a || !b) return null;
  const d = { busy: b.busy - a.busy, idle: b.idle - a.idle, iowait: b.iowait - a.iowait, steal: b.steal - a.steal };
  const total = d.busy + d.idle + d.iowait + d.steal;
  if (!total) return null;
  const pct = (n) => Math.round((1000 * n) / total) / 10;
  return { busyPct: pct(d.busy), idlePct: pct(d.idle), iowaitPct: pct(d.iowait), stealPct: pct(d.steal) };
}

function meminfo() {
  const s = readText('/proc/meminfo');
  if (!s) return null;
  const pick = (k) => { const m = new RegExp(`^${k}:\\s+(\\d+)`, 'm').exec(s); return m ? Number(m[1]) : null; };
  return { dirtyKb: pick('Dirty'), writebackKb: pick('Writeback'), availKb: pick('MemAvailable') };
}

// PSI "some" totals in microseconds.
function pressure() {
  const one = (k) => { const s = readText(`/proc/pressure/${k}`); const m = s && /some .*total=(\d+)/.exec(s); return m ? Number(m[1]) : null; };
  return { cpu: one('cpu'), io: one('io'), memory: one('memory') };
}

const FS_TYPES = {
  0xef53: 'ext4', 0x01021994: 'tmpfs', 0x794c7630: 'overlayfs', 0x58465342: 'xfs',
  0x9123683e: 'btrfs', 0x6969: 'nfs', 0x65735546: 'fuse', 0x1a: 'apfs',
};

export function hostFacts(dir) {
  const facts = {
    platform: `${process.platform} ${os.release()}`,
    node: process.version,
    cpus: os.cpus().length,
    parallelism: os.availableParallelism(),
    loadavg: os.loadavg().map(r1),
    memMb: { total: Math.round(os.totalmem() / 1048576), free: Math.round(os.freemem() / 1048576) },
    testConcurrencyHint: process.env.NODE_TEST_CONTEXT ? 'child of node --test' : 'standalone',
  };
  try {
    const st = statfsSync(dir);
    facts.fs = { type: FS_TYPES[st.type] || `0x${st.type.toString(16)}`, freeMb: Math.round((st.bavail * st.bsize) / 1048576) };
  } catch (_) {}
  const cpuMax = readText('/sys/fs/cgroup/cpu.max');
  if (cpuMax) facts.cgroupCpuMax = cpuMax.trim();
  try {
    const dev = statSync(dir).dev;
    const maj = Math.floor(dev / 256) & 0xfff;
    const min = (dev & 0xff) | ((Math.floor(dev / 1048576) & 0xfff00) >> 8);
    const sched = readText(`/sys/dev/block/${maj}:${min}/queue/scheduler`) || readText(`/sys/dev/block/${maj}:${min}/../queue/scheduler`);
    facts.blockDev = `${maj}:${min}${sched ? ` ${sched.trim()}` : ''}`;
  } catch (_) {}
  const mi = meminfo();
  if (mi) facts.meminfo = mi;
  return facts;
}

/**
 * Start sampling. Returns { timeWrite(fn), stop() }. stop() returns the raw
 * record; summarize() turns it into the compact report.
 */
export function startLoopDiagnostics() {
  const ticks = [];
  const writes = [];
  const gcs = [];
  const obs = new PerformanceObserver((list) => {
    for (const e of list.getEntries()) {
      gcs.push({ t: performance.timeOrigin + e.startTime, ms: e.duration, kind: e.detail?.kind });
    }
  });
  obs.observe({ entryTypes: ['gc'] });

  let last = nowAbs();
  let lastSched = schedstat();
  let lastTask = taskTimes();
  let lastMachine = cpuTimes();
  let lastCpu = process.cpuUsage();
  let lastPsi = pressure();
  let n = 0;
  const timer = setInterval(() => {
    const t = nowAbs();
    const lag = t - last - TICK_MS;
    const sched = schedstat();
    const task = taskTimes();
    const machine = cpuTimes();
    const cpu = process.cpuUsage();
    const tick = { t, lag };
    if (lag > STALL_MS) {
      const psi = pressure();
      Object.assign(tick, {
        intervalMs: t - last,
        mainRunMs: sched && lastSched ? (sched.run - lastSched.run) / 1e6 : null,
        mainWaitMs: sched && lastSched ? (sched.wait - lastSched.wait) / 1e6 : null,
        mainUserMs: task && lastTask ? (task.user - lastTask.user) * 10 : null,
        mainSysMs: task && lastTask ? (task.sys - lastTask.sys) * 10 : null,
        machine: shares(lastMachine, machine),
        procCpuMs: (cpu.user - lastCpu.user + cpu.system - lastCpu.system) / 1e3,
        psiSomeMs: lastPsi.io == null ? null : {
          cpu: (psi.cpu - lastPsi.cpu) / 1e3, io: (psi.io - lastPsi.io) / 1e3, memory: (psi.memory - lastPsi.memory) / 1e3,
        },
        meminfo: meminfo(),
        rssMb: Math.round(process.memoryUsage.rss() / 1048576),
      });
    }
    if (++n % 10 === 0 || lag > STALL_MS) lastPsi = pressure();
    ticks.push(tick);
    last = t;
    lastSched = sched;
    lastTask = task;
    lastMachine = machine;
    lastCpu = cpu;
  }, TICK_MS);

  const heapStart = process.memoryUsage();
  return {
    timeWrite(fn) {
      const t0 = nowAbs();
      try { return fn(); } finally { writes.push({ t: t0, ms: nowAbs() - t0 }); }
    },
    stop() {
      clearInterval(timer);
      obs.disconnect();
      return { ticks, writes, gcs, heapStart, heapEnd: process.memoryUsage() };
    },
  };
}

/**
 * The compact report: one object for a JSON line, plus a few human lines.
 * `marks` are backupTrace marks; `probe` is the prober's { max, worstAt }.
 */
export function summarize(raw, { marks, exportStart, exportEnd, facts, bounds, probe }) {
  const rel = (t) => r1(t - exportStart);
  const worst = raw.ticks.reduce((a, b) => (b.lag > (a?.lag ?? -Infinity) ? b : a), null);
  const stallEnd = worst ? worst.t : exportStart;
  const stallStart = worst ? worst.t - worst.intervalMs : exportStart;
  const overlaps = (s, e) => s < stallEnd && e > stallStart;

  const phases = marks.map((m) => {
    const o = { t: rel(m.t), name: m.name };
    if (m.start != null) { o.start = rel(m.start); o.end = rel(m.end); }
    if (m.result) o.result = m.result;
    return o;
  });
  const openAtStall = [];
  const started = new Map();
  for (const m of marks) {
    const [phase, edge] = m.name.split(':');
    if (edge === 'start') started.set(phase, m.t);
    if (edge === 'end' && started.has(phase)) {
      if (overlaps(started.get(phase), m.t)) openAtStall.push(phase);
      started.delete(phase);
    }
    if (m.start != null && overlaps(m.start, m.end)) openAtStall.push(m.name);
  }
  for (const [phase, t] of started) if (t < stallEnd) openAtStall.push(`${phase} (never ended)`);

  const slowWrites = [...raw.writes].sort((a, b) => b.ms - a.ms).slice(0, 5).map((w) => ({ t: rel(w.t), ms: r1(w.ms) }));
  const stallWrites = raw.writes.filter((w) => overlaps(w.t, w.t + w.ms)).map((w) => ({ t: rel(w.t), ms: r1(w.ms) }));
  const exportGcs = raw.gcs.filter((g) => g.t >= exportStart && g.t <= exportEnd);
  const stallGcs = raw.gcs.filter((g) => overlaps(g.t, g.t + g.ms)).map((g) => ({ t: rel(g.t), ms: r1(g.ms), kind: g.kind }));
  const around = worst
    ? raw.ticks.filter((k) => Math.abs(k.t - worst.t) <= 300 && k.lag > 2).map((k) => [rel(k.t), r1(k.lag)])
    : [];
  const stalls = raw.ticks.filter((k) => k.lag > STALL_MS && k.t >= exportStart).map((k) => ({
    t: rel(k.t), lag: r1(k.lag), run: r1(k.mainRunMs), wait: r1(k.mainWaitMs), user: k.mainUserMs, sys: k.mainSysMs,
    cpu: r1(k.procCpuMs), steal: k.machine?.stealPct ?? null,
  }));

  let verdict = 'no stall over 50 ms';
  if (worst && worst.lag > STALL_MS) {
    const span = worst.intervalMs;
    if (worst.mainRunMs == null) verdict = 'main thread state unknown (no /proc schedstat on this OS)';
    else if (worst.mainRunMs >= 0.6 * span) {
      verdict = worst.mainSysMs != null && worst.mainSysMs >= 0.5 * worst.mainRunMs
        ? 'main thread was ON CPU in the KERNEL (syscall or page-fault work, not JS)'
        : 'main thread was ON CPU (JS, SQLite compute or GC)';
    } else if (worst.mainWaitMs >= 0.4 * span) verdict = 'main thread was RUNNABLE but not scheduled (CPU starvation)';
    else verdict = 'main thread was OFF CPU (blocked in a syscall: disk I/O, fsync or a lock)';
    if (worst.machine?.stealPct >= 10) verdict += `; the hypervisor stole ${worst.machine.stealPct}% of the machine's CPU`;
    if (stallWrites.some((w) => w.ms >= 0.5 * worst.lag)) verdict += '; inside a main-thread DB write';
    const gcMs = stallGcs.reduce((n, g) => n + g.ms, 0);
    if (gcMs >= 0.3 * worst.lag) verdict += `; GC took ${r1(gcMs)} ms of it`;
  }

  const report = {
    facts,
    bounds,
    exportStartIso: new Date(exportStart).toISOString(),
    exportMs: r1(exportEnd - exportStart),
    worstStall: worst && {
      endsAt: rel(worst.t), lagMs: r1(worst.lag), mainRunMs: r1(worst.mainRunMs), mainWaitMs: r1(worst.mainWaitMs),
      mainUserMs: worst.mainUserMs ?? null, mainSysMs: worst.mainSysMs ?? null, machine: worst.machine ?? null,
      procCpuMs: r1(worst.procCpuMs), psiSomeMs: worst.psiSomeMs && Object.fromEntries(Object.entries(worst.psiSomeMs).map(([k, v]) => [k, r1(v)])),
      meminfo: worst.meminfo, rssMb: worst.rssMb, openPhases: openAtStall, writes: stallWrites, gcs: stallGcs,
    },
    verdict,
    stalls,
    loopSamplesAroundWorst: around,
    probe: probe && { maxMs: r1(probe.max), at: probe.worstAt == null ? null : rel(probe.worstAt) },
    phases,
    writes: { count: raw.writes.length, over20ms: raw.writes.filter((w) => w.ms > 20).length, slowest: slowWrites },
    gc: {
      count: exportGcs.length, totalMs: r1(exportGcs.reduce((n, g) => n + g.ms, 0)), maxMs: r1(Math.max(0, ...exportGcs.map((g) => g.ms))),
      heapUsedMb: [raw.heapStart, raw.heapEnd].map((h) => Math.round(h.heapUsed / 1048576)),
      externalMb: [raw.heapStart, raw.heapEnd].map((h) => Math.round(h.external / 1048576)),
    },
  };
  const phaseLine = phases.map((p) => (p.start != null ? `${p.name}[${p.start}..${p.end}]` : `${p.name}@${p.t}`)).join(' ');
  const human = [
    `worst stall ${report.worstStall ? `${report.worstStall.lagMs} ms ending at +${report.worstStall.endsAt} ms` : 'none'}: ${verdict}`,
    `open phases at the stall: ${openAtStall.join(', ') || 'none'}; overlapping writes: ${JSON.stringify(stallWrites)}; GC: ${JSON.stringify(stallGcs)}`,
    `slowest main-thread writes (ms after export start): ${slowWrites.map((w) => `${w.ms}ms@+${w.t}`).join(' ')}`,
    `phases (ms after export start): ${phaseLine}`,
    `host: ${facts.cpus} cpus (parallelism ${facts.parallelism}), load ${facts.loadavg.join('/')}, ${facts.fs ? `${facts.fs.type} ${facts.fs.freeMb} MB free` : 'fs ?'}, dev ${facts.blockDev || '?'}`,
  ];
  return { report, human };
}
