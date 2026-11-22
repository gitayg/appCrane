// A pre-flight check creates a container it never starts, and removes it when
// the check ends. If AppCrane is killed mid-check, nothing removes it: it stays
// Created, with any anonymous volume the image declares, for good.
//
// Only containers carrying the pre-flight label, in the Created state, older
// than any check can run, are removed. Age is what protects a check still in
// flight, here or in another AppCrane on the same Docker daemon: one check is
// four docker calls of at most 15 s. `docker rm` without -f refuses a container
// that has somehow been started. A crash followed by a quick restart leaves a
// container too young for the boot pass, so a second pass runs once it is old
// enough.

import { runDocker } from './buildCachePrune.js';
import { PREFLIGHT_LABEL } from './preflightCheck.js';
import log from '../utils/logger.js';

export const MIN_AGE_MS = 10 * 60 * 1000;
const DOCKER_TIMEOUT_MS = 30_000;
const [LABEL_KEY, LABEL_VALUE] = PREFLIGHT_LABEL.split('=');

/** Parse `docker inspect` lines of "<id>\t<created ISO>\t<status>\t<label value>". */
export function preflightLeftoversFrom(inspectOut, now = Date.now()) {
  const ids = [];
  for (const line of String(inspectOut || '').split('\n')) {
    const [id, created, status, label] = line.split('\t');
    if (!id || status !== 'created' || label !== LABEL_VALUE) continue;
    if (now - Date.parse(created) >= MIN_AGE_MS) ids.push(id);
  }
  return ids;
}

export async function sweepPreflightLeftovers({ run = (args) => runDocker(args, DOCKER_TIMEOUT_MS), now = Date.now() } = {}) {
  const list = await run(['ps', '-a', '-q', '--no-trunc', '--filter', `label=${PREFLIGHT_LABEL}`, '--filter', 'status=created']);
  if (list.code !== 0) throw new Error(`docker ps failed: ${list.stderr.trim().slice(0, 300)}`);
  const candidates = list.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
  if (!candidates.length) return { removed: 0, failed: 0 };

  const info = await run(['inspect', '--format', `{{.Id}}\t{{.Created}}\t{{.State.Status}}\t{{index .Config.Labels "${LABEL_KEY}"}}`, ...candidates]);
  let removed = 0;
  let failed = 0;
  for (const id of preflightLeftoversFrom(info.stdout, now)) {
    const r = await run(['rm', '-v', id]);
    if (r.code === 0) removed += 1;
    else failed += 1;
  }
  return { removed, failed };
}

async function pass(sweep) {
  try {
    const { removed, failed } = await sweep();
    if (removed) log.info(`pre-flight sweep: removed ${removed} container(s) left by a check that was killed`);
    if (failed) log.warn(`pre-flight sweep: could not remove ${failed} leftover container(s)`);
  } catch (e) {
    log.warn(`pre-flight sweep skipped: ${e.message}`);
  }
}

/** Boot: one pass now, one when anything left just before this boot is old enough. */
export function startPreflightSweep({ sweep = sweepPreflightLeftovers, followUpMs = MIN_AGE_MS + 5000 } = {}) {
  const first = pass(sweep);
  setTimeout(() => pass(sweep), followUpMs).unref();
  return first;
}
