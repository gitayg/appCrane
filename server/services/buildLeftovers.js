// Leftovers of interrupted classic-builder (DOCKER_BUILDKIT=0) image builds.
//
// The classic builder runs every Dockerfile step in a container and removes it
// when the step ends. A build cut off at the wrong moment (a daemon restart or
// an OOM kill mid-build; killing the client does not do it, measured) leaves
// those step containers behind in the `created` state, forever. Each one keeps
// its untagged parent image in use, so the `docker image prune` that runs after
// every deploy cannot remove those images either. Measured on one host
// (31 Oct 2026): 91 such containers pinning 105 untagged images, 13.5 GB.
//
// A failed RUN step leaves its container too, `exited` with that step's
// filesystem changes (an `npm install` worth of layers), because the builder's
// default --rm only removes step containers after a step succeeds. Measured on
// one host: 285 stopped containers holding 47.9 GB. buildImage() now passes
// --force-rm so new builds leave none; this sweep removes the ones already there.
//
// A step container is recognisable without labels. Its image is a bare image id
// (`sha256:<64 hex>`): the builder starts each step from the previous step's id,
// while every container AppCrane or a person starts records the name or digest
// ref it was given. Or its command is the builder's `/bin/sh -c #(nop)`
// metadata step, which nothing else uses. Only stopped ones (created or exited)
// older than MIN_AGE_MS are removed, so a build that is running right now keeps
// its own. Then untagged images that nothing uses any more are pruned.

import { runDocker, parseReclaimed } from './buildCachePrune.js';
import { withPrune } from './buildGate.js';

export const MIN_AGE_MS = 6 * 60 * 60 * 1000;

const BARE_IMAGE_ID = /^sha256:[0-9a-f]{64}$/;

export function isBuildStepLeftover(cmd, image = '') {
  if (BARE_IMAGE_ID.test(String(image))) return true;
  return Array.isArray(cmd) && cmd[0] === '/bin/sh' && cmd[1] === '-c' && String(cmd[2] ?? '').startsWith('#(nop)');
}

/** Parse `docker inspect` lines of "<id>\t<created ISO>\t<cmd json>\t<image>". */
export function leftoversFrom(inspectOut, now = Date.now()) {
  const ids = [];
  for (const line of String(inspectOut || '').split('\n')) {
    const [id, created, cmdJson, image] = line.split('\t');
    if (!id || !created) continue;
    let cmd = null;
    try { cmd = JSON.parse(cmdJson); } catch (_) { continue; }
    const age = now - Date.parse(created);
    if (isBuildStepLeftover(cmd, image) && age >= MIN_AGE_MS) ids.push(id);
  }
  return ids;
}

export function pruneBuildLeftovers(opts = {}) {
  return withPrune('build-leftovers', () => sweep(opts));
}

async function sweep({ run = runDocker, now = Date.now() } = {}) {
  const list = await run(['ps', '-a', '-q', '--no-trunc', '--filter', 'status=created', '--filter', 'status=exited']);
  if (list.code !== 0) throw new Error(`docker ps failed: ${list.stderr.trim().slice(0, 300)}`);
  const candidates = list.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
  let ids = [];
  if (candidates.length) {
    const info = await run(['inspect', '--format', '{{.Id}}\t{{.Created}}\t{{json .Config.Cmd}}\t{{.Config.Image}}', ...candidates]);
    ids = leftoversFrom(info.stdout, now);
  }
  let removed = 0;
  for (const id of ids) {
    const r = await run(['rm', id]);
    if (r.code === 0) removed += 1;
  }
  const prune = await run(['image', 'prune', '-f']);
  return { removed, reclaimed: prune.code === 0 ? parseReclaimed(prune.stdout) : null };
}
