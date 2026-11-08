import { execFile } from 'child_process';
import { promisify } from 'util';

// The GitHub-source clone of a deploy, run without blocking the event loop.
// A clone or fetch may take up to 120 s; execFileSync held the whole server
// (API, health checks, other deploys) for that long.
const execFileAsync = promisify(execFile);

/**
 * Shallow-clone `branch` of `cloneUrl` into `releaseDir`, then, when
 * `targetCommit` is set, fetch it and check it out detached.
 * `gitOpts(ms)` gives the execFile options; `scrubGit(msg)` removes credentials from error text.
 */
export async function cloneGitRelease({ cloneUrl, branch, releaseDir, targetCommit, gitOpts, scrubGit, appendLog }) {
  // Rows from before the write paths refused these still reach this point.
  if (String(branch).startsWith('-')) throw new Error(`refusing branch ${JSON.stringify(branch)}: it would read as a git option`);
  if (targetCommit && String(targetCommit).startsWith('-')) throw new Error(`refusing commit ${JSON.stringify(targetCommit)}: it would read as a git option`);
  try {
    await execFileAsync('git', [
      'clone', '--depth', '1',
      '--branch', branch,
      '--', cloneUrl, releaseDir,
    ], gitOpts(120000));
  } catch (err) {
    throw new Error(scrubGit(err.message));
  }

  // v2.7.12: pin to an exact commit when asked (promote ships the EXACT
  // release tested in sandbox, not the branch tip which may have moved).
  // GitHub serves reachable full SHAs directly; fall back to deepening the
  // branch history so an abbreviated SHA (deployments.commit_hash is short)
  // still resolves, then check it out detached.
  if (targetCommit && targetCommit !== 'unknown') {
    appendLog(`Pinning to commit ${targetCommit} (exact sandbox release)…`);
    let fetched = false;
    try {
      await execFileAsync('git', ['-C', releaseDir, 'fetch', '--depth', '1', '--', 'origin', targetCommit], gitOpts(120000));
      fetched = true;
    } catch (_) { /* abbreviated SHA or not directly fetchable — deepen below */ }
    if (!fetched) {
      try {
        await execFileAsync('git', ['-C', releaseDir, 'fetch', '--depth', '200', '--', 'origin', branch], gitOpts(120000));
      } catch (_) { /* best effort; checkout will surface a clear error if the commit is unreachable */ }
    }
    try {
      await execFileAsync('git', ['-C', releaseDir, 'checkout', '--detach', targetCommit], gitOpts(30000));
    } catch (err) {
      throw new Error(`Failed to check out commit ${targetCommit} for promotion (is it on branch '${branch}' within the last 200 commits?): ${scrubGit(err.message)}`);
    }
  }
}

/** { commitHash, commitSha, commitMessage } of HEAD in releaseDir; fields stay null when git cannot answer. */
export async function readReleaseCommit(releaseDir) {
  let commitHash = null;
  let commitSha = null;
  let commitMessage = null;
  try {
    commitHash = (await execFileAsync('git', ['-C', releaseDir, 'rev-parse', '--short', 'HEAD'], { timeout: 5000 })).stdout.trim();
    const full = (await execFileAsync('git', ['-C', releaseDir, 'rev-parse', 'HEAD'], { timeout: 5000 })).stdout.trim();
    if (/^[0-9a-f]{40}$/.test(full)) commitSha = full;
  } catch (e) {}
  try {
    const raw = (await execFileAsync('git', ['-C', releaseDir, 'log', '-1', '--format=%B'], { timeout: 5000 })).stdout.trim();
    if (raw) commitMessage = raw.slice(0, 2000);
  } catch (e) { /* commitMessage stays null */ }
  return { commitHash, commitSha, commitMessage };
}
