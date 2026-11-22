import { execFile } from 'child_process';
import { promisify } from 'util';
import { createHash } from 'crypto';
import { lstatSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';

// Deploy integrity: the tree that gets built, and the tree still on disk when
// the container is swapped, must be exactly the commit this deploy resolved.
// An attacker who can write into a release directory between the clone and the
// build (or during the build) would otherwise ship bytes nobody committed.

const execFileAsync = promisify(execFile);

const FULL_SHA = /^[0-9a-f]{40}$/;
const ABBREV_SHA = /^[0-9a-f]{7,40}$/;

// Lockfiles in the order one is picked when several sit at the release root.
export const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'poetry.lock', 'Pipfile.lock', 'requirements.txt', 'composer.lock', 'Gemfile.lock', 'go.sum'];
export const NO_LOCKFILE = '(none)';

// Files the deploy pipeline itself writes into the release directory before
// the build: the generated (or base-path-patched) Dockerfile and the generated
// .dockerignore. Restored .env files are added per deploy by the caller.
export const PIPELINE_WRITTEN = ['Dockerfile', '.dockerignore'];

/** Does the commit this deploy resolved satisfy the commit the caller asked for? */
export function checkRequestedCommit(requested, resolvedSha) {
  if (!requested || requested === 'unknown') return { ok: true };
  const want = String(requested).toLowerCase();
  if (!ABBREV_SHA.test(want)) return { ok: false, message: `requested commit ${JSON.stringify(requested)} is not a commit SHA` };
  if (!resolvedSha || !FULL_SHA.test(resolvedSha)) return { ok: false, message: `requested commit ${want}, but the checkout's HEAD could not be read` };
  const ok = want.length === 40 ? resolvedSha === want : resolvedSha.startsWith(want);
  return ok ? { ok: true } : { ok: false, message: `requested commit ${want}, but the checkout resolved to ${resolvedSha}` };
}

/** Parse `git status --porcelain=v1 -z` output into [{ code, path }]. */
export function parseStatusZ(stdout) {
  const tokens = String(stdout).split('\0');
  const entries = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.length < 4) continue;
    const code = t.slice(0, 2);
    entries.push({ code, path: t.slice(3) });
    if (code[0] === 'R' || code[0] === 'C') i++;
  }
  return entries;
}

/**
 * Judge a tree state. `pinned` (from the earlier check) maps each allowed
 * pipeline-written path to the sha256 it had then; a later check requires the
 * same bytes, so an allowed path cannot be swapped after the build started.
 */
export function judgeTree({ expectedSha, headSha, entries, allowed, contentOf, pinned = null }) {
  const problems = [];
  if (!headSha || !FULL_SHA.test(headSha)) problems.push('HEAD could not be read');
  else if (headSha !== expectedSha) problems.push(`HEAD is ${headSha}, expected ${expectedSha}`);
  const allowedSet = new Set(allowed);
  const snapshot = {};
  for (const e of entries) {
    if (!allowedSet.has(e.path)) {
      problems.push(`${e.code.trim() || e.code} ${e.path}`);
      continue;
    }
    snapshot[e.path] = contentOf(e.path);
  }
  if (pinned) {
    for (const path of new Set([...Object.keys(pinned), ...Object.keys(snapshot)])) {
      if (pinned[path] !== snapshot[path]) problems.push(`${path} changed after the pre-build check`);
    }
  }
  return { ok: problems.length === 0, problems, snapshot };
}

function gitEnv() {
  return {
    ...process.env,
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.fsmonitor',
    GIT_CONFIG_VALUE_0: 'false',
  };
}

function sha256OfFile(path) {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (!st || !st.isFile()) return st ? `not-a-regular-file:${st.mode}` : 'missing';
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** HEAD and the porcelain status of `dir`, ignored and untracked files listed one by one. */
export async function readTreeState(dir, run = execFileAsync) {
  const opts = { timeout: 30000, env: gitEnv(), maxBuffer: 16 * 1024 * 1024 };
  let headSha = null;
  try {
    headSha = (await run('git', ['-C', dir, 'rev-parse', 'HEAD'], opts)).stdout.trim();
  } catch (_) { /* judged as unreadable */ }
  const { stdout } = await run('git', ['-C', dir, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=traditional'], opts);
  return { headSha, entries: parseStatusZ(stdout) };
}

/**
 * Verify `dir` is exactly `expectedSha` with no change beyond `allowed`.
 * Throws (the deploy fails, nothing is swapped) on any mismatch; returns the
 * snapshot of the allowed paths to pin for the next check.
 */
export async function verifyReleaseTree({ dir, expectedSha, allowed, stage, pinned = null, run }) {
  let state;
  try {
    state = await readTreeState(dir, run);
  } catch (e) {
    throw new Error(`Deploy integrity (${stage}): could not read the release tree's git state: ${e.message.split('\n')[0]}`);
  }
  const verdict = judgeTree({
    expectedSha, headSha: state.headSha, entries: state.entries, allowed, pinned,
    contentOf: (p) => sha256OfFile(join(dir, p)),
  });
  if (!verdict.ok) {
    const shown = verdict.problems.slice(0, 20);
    const more = verdict.problems.length > shown.length ? ` (+${verdict.problems.length - shown.length} more)` : '';
    throw new Error(
      `Deploy integrity (${stage}): the release tree is not commit ${expectedSha}: ${shown.join('; ')}${more}. `
      + 'The deploy was stopped and the running container was not touched.',
    );
  }
  return verdict.snapshot;
}

/** { name, sha256 } of the release root's lockfile, or { name: NO_LOCKFILE, sha256: null }. */
export function fingerprintLockfile(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch (_) {
    names = [];
  }
  const extraReqs = names.filter((n) => /^requirements.*\.txt$/.test(n) && n !== 'requirements.txt').sort();
  for (const name of [...LOCKFILE_NAMES, ...extraReqs]) {
    const path = join(dir, name);
    const st = lstatSync(path, { throwIfNoEntry: false });
    if (!st || !st.isFile()) continue;
    return { name, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') };
  }
  return { name: NO_LOCKFILE, sha256: null };
}

/** The deploy-log line comparing this deploy's lockfile with the previous successful deploy's. */
export function describeLockfileChange(current, previous) {
  const cur = current.sha256 ? `${current.name} sha256 ${current.sha256.slice(0, 12)}…` : 'no lockfile';
  if (!previous) return `Lockfile: ${cur} (no earlier successful deploy with a recorded lockfile to compare).`;
  const prevDesc = previous.lockfile_sha256 ? `${previous.lockfile_name} ${previous.lockfile_sha256.slice(0, 12)}…` : 'no lockfile';
  if (previous.lockfile_name === current.name && (previous.lockfile_sha256 ?? null) === (current.sha256 ?? null)) {
    return `Lockfile: ${cur}, unchanged since deploy #${previous.id}.`;
  }
  const which = previous.lockfile_name === current.name ? current.name : `${previous.lockfile_name} → ${current.name}`;
  return `Lockfile CHANGED since deploy #${previous.id} (${which}): was ${prevDesc}, now ${cur}. Reported, not blocked.`;
}

/** The newest successful deploy of this app/env before `deployId` that recorded a lockfile fingerprint. */
export function previousLockfile(db, appId, env, deployId) {
  return db.prepare(
    "SELECT id, lockfile_name, lockfile_sha256 FROM deployments WHERE app_id = ? AND env = ? AND id < ?"
    + " AND status IN ('live', 'rolled_back') AND lockfile_name IS NOT NULL ORDER BY id DESC LIMIT 1",
  ).get(appId, env, deployId) || null;
}

/** Record this deploy's lockfile and return the log line. */
export function recordLockfile(db, { appId, env, deployId, dir }) {
  const current = fingerprintLockfile(dir);
  const line = describeLockfileChange(current, previousLockfile(db, appId, env, deployId));
  db.prepare('UPDATE deployments SET lockfile_name = ?, lockfile_sha256 = ? WHERE id = ?').run(current.name, current.sha256, deployId);
  return line;
}

/** Carry the lockfile fingerprint onto a deployment row that reuses another row's release (rollback, promote). */
export function copyLockfile(db, fromId, toId) {
  db.prepare(
    'UPDATE deployments SET lockfile_name = (SELECT lockfile_name FROM deployments WHERE id = ?),'
    + ' lockfile_sha256 = (SELECT lockfile_sha256 FROM deployments WHERE id = ?) WHERE id = ?',
  ).run(fromId, fromId, toId);
}
