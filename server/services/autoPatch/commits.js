// Which full commit does a recorded deployment hash name? Auto-patch decides
// "the branch tip is what production runs" and "sandbox built the bump" by
// exact 40-hex equality, never by prefix: deployments.commit_hash is an
// abbreviated SHA, and a commit sharing its first 8 hex digits can be
// brute-forced in minutes, so a prefix match would let anyone with push access
// pass unreviewed code off as the production commit.
//
// deployments.commit_sha (migration 150) carries the full SHA for releases
// built since. Older rows only have the short hash, which is resolved against
// the app's own bare repository and accepted only when exactly one object in
// that repository has that prefix and it is a commit.

import { execFile } from 'child_process';
import { repoPath, localRepoExists, isolatedGitArgs, isolatedGitEnv } from '../localGit.js';

const FULL = /^[0-9a-f]{40}$/;
const SHORT = /^[0-9a-f]{4,40}$/;

function git(gitDir, args) {
  return new Promise((res, rej) => {
    execFile('git', isolatedGitArgs(gitDir, args), { env: isolatedGitEnv(), timeout: 15000, maxBuffer: 1024 * 1024 }, (err, stdout) => (err ? rej(err) : res(String(stdout))));
  });
}

/** The one commit `hash` names in the app's repository, or null (missing, ambiguous, not a commit). */
export async function resolveCommitExact(slug, hash) {
  const h = String(hash || '').toLowerCase();
  if (!SHORT.test(h) || !localRepoExists(slug)) return null;
  const gitDir = repoPath(slug);
  let matches;
  try {
    matches = (await git(gitDir, ['rev-parse', `--disambiguate=${h}`])).split('\n').map((s) => s.trim()).filter(Boolean);
  } catch (_) {
    return null;
  }
  if (matches.length !== 1 || !FULL.test(matches[0])) return null;
  try {
    const sha = (await git(gitDir, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${matches[0]}^{commit}`])).trim();
    return sha === matches[0] ? sha : null;
  } catch (_) {
    return null;
  }
}

/** Full SHA of a deployments row: commit_sha when recorded, else the resolved commit_hash. */
export async function deploymentCommit(slug, row, resolve = resolveCommitExact) {
  if (!row) return null;
  const full = String(row.commit_sha || '').toLowerCase();
  if (FULL.test(full)) return full;
  return resolve(slug, row.commit_hash);
}

export const isFullSha = (s) => FULL.test(String(s || ''));
