import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { getDb } from '../../db.js';
import { decrypt } from '../encryption.js';
import { tokenGitEnv, scrubToken } from '../githubGitAuth.js';
import { usesLocalRepo } from '../managedRepo.js';
import log from '../../utils/logger.js';

/**
 * The app behind a coder/studio session workspace. Both callers (routes/coder.js
 * and routes/agents.js) pass session.workspace_dir, so the session row names the
 * app whose credential the push needs -- the workspace's origin is the plain URL.
 */
function appForWorkspace(workspaceDir) {
  return getDb().prepare(`
    SELECT a.slug, a.source_type, a.repo_backend, a.github_url, a.github_token_encrypted
    FROM coder_sessions s
    JOIN apps a ON a.slug = s.app_slug
    WHERE s.workspace_dir = ? LIMIT 1
  `).get(workspaceDir);
}

/**
 * Stage all changes, commit, regenerate package-lock if needed, and push.
 * Returns { pushed: true } or { pushed: false, reason } if nothing to commit.
 */
export async function commitAndPush({ workspaceDir, branchName, commitMsg, onLog }) {
  // Hard gate (Phase 1): a Crane-hosted app's source lives in a bare repo on
  // this host, not behind a GitHub `origin`. Everything below this line is the
  // GitHub push path -- credential lookup by github_url, `git push origin`.
  // Refuse BEFORE staging, so a refused ship leaves no commit in the workspace
  // for a later run to push by accident. Releasing a Crane-hosted session to
  // sandbox is Phase 4; until it lands there is nothing honest to do here.
  const sessionApp = appForWorkspace(workspaceDir);
  if (sessionApp && usesLocalRepo(sessionApp)) {
    const err = new Error(
      `'${sessionApp.slug}' is a Crane-hosted app: its source lives on this host, not on GitHub, so there is no remote to push to. Nothing was committed. Shipping a Crane-hosted Builder session is not available yet.`,
    );
    err.status = 400;
    err.code = 'LOCAL_REPO_NO_PUSH';
    throw err;
  }

  const git = (args, opts = {}) =>
    execFileSync('git', ['-c', `safe.directory=${workspaceDir}`, '-C', workspaceDir, ...args], {
      stdio: 'pipe', timeout: 60000, ...opts,
    });

  onLog?.('[builder:git] Staging all changes…');
  git(['add', '-A']);

  const diffOut = (() => { try { return git(['diff', '--cached', '--name-only']).toString().trim(); } catch (_) { return ''; } })();
  const changed = diffOut ? diffOut.split('\n').filter(Boolean) : [];

  if (changed.length === 0) {
    onLog?.('[builder:git] No file changes to commit');
    return { pushed: false, reason: 'no_changes' };
  }

  if (changed.includes('package.json') && existsSync(`${workspaceDir}/package.json`)) {
    onLog?.('[builder:git] package.json changed — regenerating package-lock.json…');
    try {
      execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts'], {
        cwd: workspaceDir, stdio: 'pipe', timeout: 120000,
      });
      git(['add', 'package-lock.json']);
      onLog?.('[builder:git] package-lock.json updated');
    } catch (err) {
      onLog?.(`[builder:git] Warning: could not regenerate package-lock.json: ${err.message}`);
    }
  }

  onLog?.(`[builder:git] ${changed.length} file(s) staged`);
  git(['commit', '-m', commitMsg]);
  onLog?.('[builder:git] Committed');

  onLog?.(`[builder:git] Pushing ${branchName}…`);
  // No --force fallback (v1.27.69). Force-pushing was destroying prior
  // coder commits and rewriting open PR histories. The caller is now
  // responsible for cloning from the existing remote branch (when one
  // exists) so the push fast-forwards. If push still fails here, it
  // means the branch genuinely diverged — surface the error instead of
  // overwriting.
  let token = null;
  let pushEnv = null;
  if (sessionApp?.github_url && sessionApp.github_token_encrypted) {
    try {
      token = decrypt(sessionApp.github_token_encrypted);
      pushEnv = tokenGitEnv(sessionApp.github_url, token);
    } catch (_) { pushEnv = null; }
  }
  try {
    git(['push', '-u', 'origin', branchName], pushEnv ? { env: pushEnv } : {});
  } catch (err) {
    throw new Error(scrubToken(err.message, token));
  }
  onLog?.(`[builder:git] Branch ${branchName} pushed`);
  log.info(`Coder: pushed branch ${branchName}`);
  return { pushed: true };
}
