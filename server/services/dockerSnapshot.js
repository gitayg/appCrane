// One shared, short-lived view of the Docker host for the background jobs and
// the admission checks: `docker info` (cores, RAM, data root) and every running
// container's state, limits and labels from one `docker ps` + one batched
// `docker inspect`. Memory admission, CPU admission, the host-resource monitor
// and the metrics sampler all read the same snapshot, so a host check costs
// three docker processes instead of seven, and the sampler one inspect instead
// of one per app-env.
//
// Concurrent callers share one in-flight read. invalidateDockerSnapshot() drops
// the cached rows and makes a read already in flight not cache its answer, so a
// container started after the read began is never hidden behind it; the memory
// admission release after every container start calls it. A container stopped
// by something that does not invalidate counts for at most SNAPSHOT_TTL_MS
// longer, which over-counts and so errs toward caution.

import { execFile } from 'child_process';

export const SNAPSHOT_TTL_MS = 10_000;
// Cores, RAM and the data root change only when the daemon is reconfigured.
export const INFO_TTL_MS = 60_000;
export const INFO_FORMAT = '{{.NCPU}}\t{{.MemTotal}}\t{{.DockerRootDir}}';
// The image comes last: labels are JSON, whose strings never hold a raw tab.
export const SNAPSHOT_INSPECT_FORMAT = '{{.Name}}\t{{.State.Status}}\t{{.State.Pid}}\t{{.State.StartedAt}}\t{{.RestartCount}}'
  + '\t{{.HostConfig.Memory}}\t{{.HostConfig.MemoryReservation}}'
  + '\t{{.HostConfig.NanoCpus}}\t{{.HostConfig.CpuQuota}}\t{{.HostConfig.CpuPeriod}}\t{{.HostConfig.CpuShares}}'
  + '\t{{json .Config.Labels}}\t{{.Config.Image}}';
export const STATS_FORMAT = '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}';

const MiB = 1024 * 1024;

function docker(args) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: 10_000, maxBuffer: 16 * MiB }, (err, stdout, stderr) => {
      if (err) { err.message = `${err.message}${stderr ? `: ${String(stderr).trim()}` : ''}`; reject(err); return; }
      resolve(String(stdout));
    });
  });
}

let gen = 0;

// One cached value with a shared in-flight read. A read that began before the
// last invalidation still answers its own callers but is not cached.
function sharedRead(ttl, read) {
  let value = null;
  let flight = null;
  return {
    async get(fresh) {
      if (!fresh && value && Date.now() - value.at < ttl) return value.data;
      if (!fresh && flight && flight.gen === gen) return flight.promise;
      const g = gen;
      const promise = read().then((data) => {
        if (g === gen) value = { at: Date.now(), data };
        return data;
      });
      flight = { gen: g, promise };
      try { return await promise; } finally { if (flight?.promise === promise) flight = null; }
    },
    clear() { value = null; },
  };
}

/** Lines in SNAPSHOT_INSPECT_FORMAT -> container rows. */
export function parseSnapshotInspect(out) {
  const rows = [];
  for (const line of String(out || '').split('\n')) {
    const p = line.split('\t');
    if (p.length < 12) continue;
    const name = p[0].replace(/^\//, '').trim();
    if (!name) continue;
    let labels = {};
    try { labels = JSON.parse(p[11]) || {}; } catch (_) { labels = {}; }
    rows.push({
      name, status: p[1].trim(), pid: Number(p[2]) || 0, startedAt: p[3].trim(), restarts: Number(p[4]) || 0,
      memory: Number(p[5]), memoryReservation: Number(p[6]),
      nanoCpus: Number(p[7]), cpuQuota: Number(p[8]), cpuPeriod: Number(p[9]), cpuShares: Number(p[10]),
      labels, image: (p[12] || '').trim() || null,
    });
  }
  return rows;
}

/** Every running container (as `docker ps` lists them), from one ps + one inspect. Throws when Docker does not answer. */
const containers = sharedRead(SNAPSHOT_TTL_MS, async () => {
  const ids = String(await docker(['ps', '-q', '--no-trunc'])).split('\n').map((s) => s.trim()).filter(Boolean);
  return ids.length ? parseSnapshotInspect(await docker(['inspect', '--format', SNAPSHOT_INSPECT_FORMAT, ...ids])) : [];
});

export function runningContainers({ fresh = false } = {}) {
  return containers.get(fresh);
}

/** { ncpu, memTotal, rootDir } from one `docker info`; a field Docker did not give is NaN / null. Throws when Docker does not answer. */
const daemonInfo = sharedRead(INFO_TTL_MS, async () => {
  const [ncpu, memTotal, rootDir] = String(await docker(['info', '--format', INFO_FORMAT])).replace(/\s+$/, '').split('\t');
  const dir = String(rootDir || '').trim();
  return { ncpu: Number(ncpu), memTotal: Number(memTotal), rootDir: dir.startsWith('/') ? dir : null };
});

export function dockerInfo({ fresh = false } = {}) {
  return daemonInfo.get(fresh);
}

/** CPU % and the raw memory-usage text of every running container, one `docker stats` call. Map<name, { cpuPerc, memUsage }>. */
export async function statsAll() {
  const map = new Map();
  const out = await docker(['stats', '--no-stream', '--format', STATS_FORMAT]);
  for (const line of out.split('\n')) {
    const [n, cpuPerc, memUsage] = line.split('\t');
    if (n && n.trim()) map.set(n.trim(), { cpuPerc: cpuPerc || '', memUsage: memUsage || '' });
  }
  return map;
}

export function invalidateDockerSnapshot() {
  gen++;
  containers.clear();
}

export function _resetDockerSnapshotForTests() {
  invalidateDockerSnapshot();
  daemonInfo.clear();
}
