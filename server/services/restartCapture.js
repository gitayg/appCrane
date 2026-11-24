// What a container looked like just before it was restarted: cgroup memory,
// Docker's exit state and the last log lines. Read BEFORE the restart, because
// a restart gives the container a fresh cgroup (memory.current and the
// memory.events counters start again from zero).
//
// Never throws and never holds a restart up for long: every step has its own
// deadline, the memory and log steps run side by side, and the whole capture
// has an overall deadline. A step that fails is listed in not_captured with the
// reason instead.
//
// Memory, in order: the host's cgroup v2 files (Linux, cgroupfs or systemd
// driver), then `docker stats`, then `docker exec <c> cat /sys/fs/cgroup/...`
// for the OOM counters only when stats shows the container well under its
// limit (see readMemory). What the exec path returns comes from inside the
// app's container, so the app could misreport it; that only misleads its own
// incident record.

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { scrubText } from './eventScrub.js';
import { parseMemUsage } from './memoryAdmission.js';

export const STEP_TIMEOUT_MS = 5000;
export const OVERALL_TIMEOUT_MS = 8000;
export const LOG_LINES = 50;
export const LOG_LINE_MAX = 500;
export const LOG_TOTAL_MAX = 16 * 1024;

const CGROUP_ROOT = process.env.APPCRANE_CGROUP_ROOT || '/sys/fs/cgroup';

function run(args, timeout = STEP_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout, maxBuffer: 4 << 20 }, (err, stdout, stderr) => {
      if (err) {
        const why = err.killed ? `timed out after ${timeout}ms` : (String(stderr || '').trim() || err.message);
        reject(new Error(why.slice(0, 300)));
        return;
      }
      resolve({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

function withDeadline(promise, ms, what) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, reject) => { t = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms); }),
  ]);
}

/** memory.current / memory.max / memory.events text -> numbers. max 'max' = no limit (null). */
export function parseCgroupMemory({ current, max, events }) {
  const cur = Number(String(current ?? '').trim());
  const maxText = String(max ?? '').trim();
  const out = {
    current: Number.isFinite(cur) && String(current ?? '').trim() !== '' ? cur : null,
    max: maxText === 'max' || maxText === '' ? null : (Number.isFinite(Number(maxText)) ? Number(maxText) : null),
    oom: null,
    oom_kill: null,
  };
  for (const line of String(events ?? '').split('\n')) {
    const [k, v] = line.trim().split(/\s+/);
    if (k === 'oom' || k === 'oom_kill') out[k] = Number(v);
  }
  return out;
}

async function hostCgroupMemory(id) {
  const dirs = [`${CGROUP_ROOT}/system.slice/docker-${id}.scope`, `${CGROUP_ROOT}/docker/${id}`];
  let last;
  for (const dir of dirs) {
    try {
      const [current, max, events] = await Promise.all(['memory.current', 'memory.max', 'memory.events']
        .map(f => readFile(`${dir}/${f}`, 'utf8')));
      return { ...parseCgroupMemory({ current, max, events }), source: 'host-cgroup' };
    } catch (e) { last = e; }
  }
  throw new Error(`no host cgroup v2 files for the container (${last?.code || last?.message})`);
}

async function execCgroupMemory(name) {
  // Three files in one exec; `cat` prints them in order and a marker splits them.
  const { stdout } = await run(['exec', name, 'sh', '-c',
    'cat /sys/fs/cgroup/memory.current; echo ---; cat /sys/fs/cgroup/memory.max; echo ---; cat /sys/fs/cgroup/memory.events']);
  const [current, max, events] = stdout.split('---\n');
  const parsed = parseCgroupMemory({ current, max, events });
  if (parsed.current == null) throw new Error('memory.current unreadable inside the container');
  return { ...parsed, source: 'docker-exec' };
}

async function statsMemory(name, limitBytes) {
  const { stdout } = await run(['stats', '--no-stream', '--format', '{{.MemUsage}}', name]);
  const [used, limit] = stdout.trim().split('/');
  const current = parseMemUsage(used);
  if (current == null) throw new Error(`docker stats gave no memory figure (${stdout.trim().slice(0, 80)})`);
  // A container that is already shutting down reads "0B / <limit>".
  if (current === 0) throw new Error('docker stats read 0 B (the container was already stopping)');
  return { current, max: limitBytes || parseMemUsage(limit), oom: null, oom_kill: null, source: 'docker-stats' };
}

export const EXEC_SAFE_RATIO = 0.9;

export async function readMemory({ name, id, limitBytes, running }) {
  if (!running) throw new Error('container was not running');
  const reasons = [];
  if (id) {
    try { return await hostCgroupMemory(id); } catch (e) { reasons.push(`host cgroup: ${e.message}`); }
  }
  // docker stats before docker exec: an exec starts a process inside a
  // container that may be at its limit, and measured on a 64 MB container
  // filled to 62 MB the exec was OOM-killed itself ("procReady not received")
  // and set State.OOMKilled. The kernel could as well pick the app's process.
  // So exec only runs, for memory.events, when stats shows room for it.
  let stats = null;
  try { stats = await statsMemory(name, limitBytes); } catch (e) { reasons.push(`docker stats: ${e.message}`); }
  if (stats && !(stats.max && stats.current / stats.max < EXEC_SAFE_RATIO)) return stats;
  try { return await execCgroupMemory(name); } catch (e) { reasons.push(`docker exec: ${e.message}`); }
  if (stats) return stats;
  throw new Error(reasons.join('; '));
}

export async function readState(name) {
  const { stdout } = await run(['inspect', name, '--format', '{{json .State}}|{{.Id}}|{{.HostConfig.Memory}}|{{.RestartCount}}']);
  const [stateJson, id, mem, restarts] = stdout.trim().split('|');
  const s = JSON.parse(stateJson);
  return {
    id,
    limitBytes: Number(mem) || null,
    state: {
      status: s.Status, exit_code: s.ExitCode, oom_killed: !!s.OOMKilled, error: s.Error || null,
      started_at: s.StartedAt || null, finished_at: s.FinishedAt && !s.FinishedAt.startsWith('0001') ? s.FinishedAt : null,
      restart_count: Number(restarts) || 0,
      limit_bytes: Number(mem) || null,
    },
  };
}

/** docker logs output (both streams, --timestamps) -> the last lines, in time order, scrubbed and capped. */
export function tailLines(stdout, stderr, n = LOG_LINES) {
  const lines = [...String(stdout).split('\n'), ...String(stderr).split('\n')].filter(l => l.trim() !== '');
  lines.sort((a, b) => (a.slice(0, 35) < b.slice(0, 35) ? -1 : a.slice(0, 35) > b.slice(0, 35) ? 1 : 0));
  const out = [];
  let total = 0;
  for (const raw of lines.slice(-n).reverse()) {
    let line = scrubText(raw);
    if (line.length > LOG_LINE_MAX) line = line.slice(0, LOG_LINE_MAX - 3) + '...';
    if (total + line.length > LOG_TOTAL_MAX) break;
    total += line.length;
    out.unshift(line);
  }
  return out;
}

export async function readLogTail(name, n = LOG_LINES) {
  const { stdout, stderr } = await run(['logs', '--tail', String(n), '--timestamps', name]);
  return tailLines(stdout, stderr, n);
}

/**
 * Everything at once. Returns { container_id, state, memory, log_tail, not_captured[] }.
 * `memory: false` skips the memory step (the container is already gone or dying).
 */
export async function captureContainer(name, { memory = true, timeoutMs = OVERALL_TIMEOUT_MS } = {}) {
  const out = { container_id: null, state: null, memory: null, log_tail: null, not_captured: [] };
  const work = (async () => {
    let info = null;
    try {
      info = await readState(name);
      out.container_id = info.id;
      out.state = info.state;
    } catch (e) {
      out.not_captured.push(`exit state: ${e.message}`);
    }
    const steps = [
      readLogTail(name).then(l => { out.log_tail = l; }, e => out.not_captured.push(`log tail: ${e.message}`)),
    ];
    if (memory) {
      steps.push(readMemory({ name, id: info?.id, limitBytes: info?.limitBytes, running: info ? info.state.status === 'running' : true })
        .then(m => { out.memory = m; }, e => out.not_captured.push(`memory: ${e.message}`)));
    } else {
      out.not_captured.push('memory: the container had already stopped, so its cgroup was gone');
    }
    await Promise.all(steps);
  })();
  try {
    await withDeadline(work, timeoutMs, 'capture');
  } catch (e) {
    out.not_captured.push(e.message);
  }
  return { ...out, not_captured: [...out.not_captured] };
}
