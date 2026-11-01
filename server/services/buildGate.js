// Image builds and image prunes never overlap on one Docker host.
//
// Every deploy ends with `docker image prune` (and the build-leftover sweep,
// the weekly build-cache prune and old-image removal do the same kind of
// thing). A prune that lands while another app's classic-builder build is
// between steps deletes the lease that build is exporting its next layer
// under, and the build dies:
//
//   failed to export layer: NotFound: lease does not exist: not found
//
// Measured 1 Nov 2026 on Docker 29.6.1 (containerd image store): a 51-step
// DOCKER_BUILDKIT=0 build with `docker image prune -f` in a loop beside it
// failed on the 26th prune. On a host, two deploys overlapping was enough:
// every failed build had another app's deploy finishing beside it, and the
// retry with nothing else building went through.
//
// So builds take a shared hold (any number at once) and prunes an exclusive
// one: a prune waits until no build is running, and a build waits while a
// prune is running. Prunes asked for while builds run are coalesced by key, so
// ten deploys finishing during a long build queue one prune, not ten.

let builds = 0;
let pruning = null;
let drained = [];
const queued = new Map();

export function buildsInFlight() { return builds; }

export async function withBuild(fn) {
  while (pruning) await pruning.catch(() => {});
  builds += 1;
  try {
    return await fn();
  } finally {
    builds -= 1;
    if (builds === 0) {
      const waiting = drained;
      drained = [];
      for (const wake of waiting) wake();
    }
  }
}

export function withPrune(key, fn) {
  if (queued.has(key)) return queued.get(key);
  // Deferred a tick, so queued.set below runs before the body can delete the key.
  const p = Promise.resolve().then(async () => {
    for (;;) {
      if (builds > 0) await new Promise((r) => drained.push(r));
      else if (pruning) await pruning.catch(() => {});
      else break;
    }
    queued.delete(key);
    pruning = Promise.resolve().then(fn);
    try { return await pruning; } finally { pruning = null; }
  });
  queued.set(key, p);
  return p;
}
