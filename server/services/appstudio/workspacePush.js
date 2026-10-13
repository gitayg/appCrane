import { execFileSync } from 'child_process';
import { chmodSync, closeSync, mkdirSync, mkdtempSync, openSync, readSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { runWorkspaceGit, runInWorkspace } from '../builder/workspaceRunner.js';

// ---------------------------------------------------------------------------
// AppStudio: the post-coding git and npm, out of the host
// ---------------------------------------------------------------------------
//
// The AppStudio workspace (generator.cloneForCode) is chmod 777 and mounted
// read-write into the coding container, exactly like a coder workspace. When
// the agent finished, worker.js used to run, ON THE HOST and with no config
// check at all: `git add/commit` (so a planted filter driver or hook ran as the
// AppCrane user), `git push origin` with the GitHub token in its environment
// (origin being a URL the agent could rewrite), and `npm install` / `npm run
// build` in whichever subfolder the agent touched (its package.json scripts ran
// as the AppCrane user — the harness's finding H1). Now:
//
//   - git add/commit run in a helper container (builder/workspaceRunner.js):
//     no network, no capabilities, only the workspace mounted.
//   - npm runs in a helper too. `npm install` is given the default bridge
//     network because it has to reach the registry; `npm run build` gets none.
//     The only other mount is a per-app npm cache AppCrane owns — per app so
//     one app's install scripts cannot seed another app's cache.
//   - the push leaves the workspace as a bundle of the new commits. The HOST
//     loads it into a fresh bare repo it just created (its own config, hooks
//     off), fetches the bundle's prerequisite commits from GitHub there, and
//     pushes to `app.github_url` from that repo. The token never enters a
//     container and never meets a config file the agent wrote.

const STUDIO_ENV = {
  GIT_AUTHOR_NAME: 'AppStudio',
  GIT_AUTHOR_EMAIL: 'appstudio@appcrane.local',
  GIT_COMMITTER_NAME: 'AppStudio',
  GIT_COMMITTER_EMAIL: 'appstudio@appcrane.local',
};

/** git in the AppStudio workspace, in a helper (the coding container has exited). */
export function studioGit(workspaceDir, args, opts = {}) {
  return runWorkspaceGit(workspaceDir, args, { ...opts, env: { ...STUDIO_ENV, ...(opts.env || {}) } });
}

/** Paths staged in the workspace, from `git diff --cached -z` (paths with newlines stay whole). */
export function stagedFiles(workspaceDir) {
  return studioGit(workspaceDir, ['diff', '--cached', '--name-only', '-z']).toString('utf8').split('\0').filter(Boolean);
}

const NPM_CACHE_MOUNT = '/npm-cache';

/**
 * The npm cache a helper may write: one per app, under DATA_DIR, never inside
 * the workspace. 0777 + a best-effort chown to the studio uid for the same
 * reason the transcript dir gets them (appContainer.prepareTranscriptDir): the
 * helper runs as uid 100, not as whoever AppCrane runs as.
 */
export function studioNpmCacheDir(slug) {
  if (!/^[a-z0-9][a-z0-9-]{0,99}$/.test(String(slug))) throw new Error(`invalid app slug ${JSON.stringify(slug)}`);
  const dir = join(resolve(process.env.DATA_DIR || './data'), 'appstudio-npm-cache', slug);
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777);
  try { execFileSync('chown', ['100:101', dir], { stdio: 'pipe' }); } catch (_) {}
  return dir;
}

/** A top-level directory name from the agent's change list, safe to hand npm as --prefix. */
export function assertTopDir(dir) {
  if (typeof dir !== 'string' || !/^[A-Za-z0-9_@][A-Za-z0-9._@-]*$/.test(dir) || dir === '.' || dir === '..') {
    throw new Error(`refusing to run npm in ${JSON.stringify(dir)}`);
  }
  return dir;
}

/**
 * npm in a helper container. `network` is 'bridge' only for an install, which
 * has to reach the registry; everything else runs with none. `cacheDir` is a
 * host directory AppCrane owns, per app.
 */
export function studioNpm(workspaceDir, npmArgs, { cacheDir, network = 'none', timeout = 300000 } = {}) {
  return runInWorkspace(workspaceDir, ['npm', ...npmArgs], {
    network,
    mounts: cacheDir ? [{ host: cacheDir, target: NPM_CACHE_MOUNT }] : [],
    env: { npm_config_cache: NPM_CACHE_MOUNT, npm_config_update_notifier: 'false', npm_config_fund: 'false' },
    memory: '2g',
    timeout,
  });
}

/**
 * Which of `dirs` hold a package.json with a `build` script. Read inside a
 * helper, not on the host: a package.json the agent turned into a symlink
 * would otherwise make the host read whatever it points at.
 */
const BUILD_DIRS_SCRIPT = `
const fs = require('fs');
for (const d of process.argv.slice(1)) {
  try {
    const st = fs.lstatSync(d + '/package.json');
    if (!st.isFile()) continue;
    const pkg = JSON.parse(fs.readFileSync(d + '/package.json', 'utf8')); // in-container: this script runs in a helper
    if (pkg && pkg.scripts && pkg.scripts.build) process.stdout.write(d + '\\0');
  } catch (_) {}
}`;
export function dirsWithBuildScript(workspaceDir, dirs) {
  const safe = dirs.filter((d) => { try { assertTopDir(d); return true; } catch (_) { return false; } });
  if (!safe.length) return [];
  return runInWorkspace(workspaceDir, ['node', '-e', BUILD_DIRS_SCRIPT, ...safe])
    .toString('utf8').split('\0').filter(Boolean);
}

/**
 * generator.syncDeployhubVersion, in a helper: copy package.json's version
 * into deployhub.json. Written on the host, a deployhub.json the agent had
 * made a symlink would have been a write to any file the AppCrane user owns.
 */
const SYNC_VERSION_SCRIPT = `
const fs = require('fs');
const reg = (p) => { try { return fs.lstatSync(p).isFile(); } catch (_) { return false; } };
if (reg('package.json') && reg('deployhub.json')) {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); // in-container: this script runs in a helper
  const dh = JSON.parse(fs.readFileSync('deployhub.json', 'utf8')); // in-container: this script runs in a helper
  if (pkg && pkg.version && dh.version !== pkg.version) {
    const before = dh.version;
    dh.version = pkg.version;
    fs.writeFileSync('deployhub.json', JSON.stringify(dh, null, 2) + '\\n');
    process.stdout.write(String(before) + ' -> ' + pkg.version);
  }
}`;
export function syncDeployhubVersionInWorkspace(workspaceDir) {
  return runInWorkspace(workspaceDir, ['node', '-e', SYNC_VERSION_SCRIPT]).toString('utf8').trim();
}

// --- the push ---------------------------------------------------------------

const SHA_RE = /^[0-9a-f]{40}$/;

function hostGitEnv(extra = {}) {
  return {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    LC_ALL: 'C',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    ...extra,
  };
}

const HOST_GIT_BASE = ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0'];

/** Prerequisite commits named in a v2 bundle header ("-<sha> <comment>" lines before the blank line). */
export function bundlePrerequisites(file) {
  const fd = openSync(file, 'r'); // host-read-ok: the bundle in AppCrane's own mkdtemp dir, written from the container's stdout
  try {
    const buf = Buffer.alloc(64 * 1024);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const header = buf.subarray(0, n).toString('latin1');
    const end = header.indexOf('\n\n');
    if (!header.startsWith('# v2 git bundle\n') || end < 0) throw new Error('not a v2 git bundle');
    return header.slice(0, end).split('\n').slice(1)
      .filter((l) => l.startsWith('-')).map((l) => l.slice(1, 41)).filter((s) => SHA_RE.test(s));
  } finally {
    closeSync(fd);
  }
}

/**
 * Commit the workspace's new commits to `branchName` on GitHub, from a host
 * repo AppCrane builds for the purpose. Throws on any failure; the worker
 * treats a failed push as the re-plan signal it always did.
 *
 * `gitEnv` is tokenGitEnv's environment (the http.extraHeader for this one
 * origin) or null for a public repo.
 */
export function pushWorkspaceCommits({ workspaceDir, url, branchName, gitEnv = null }) {
  if (!/^[A-Za-z0-9._/-]{1,200}$/.test(branchName) || branchName.startsWith('-')) {
    throw new Error(`invalid branch ${JSON.stringify(branchName)}`);
  }
  const head = studioGit(workspaceDir, ['rev-parse', '--verify', 'HEAD^{commit}']).toString('utf8').trim();
  if (!SHA_RE.test(head)) throw new Error('workspace HEAD is not a commit id');

  const dir = mkdtempSync(join(tmpdir(), 'appcrane-studio-push-'));
  try {
    const file = join(dir, 'work.bundle');
    const fd = openSync(file, 'w', 0o600); // host-read-ok: a write fd in AppCrane's own mkdtemp dir
    try {
      // Only what the agent added on top of what it cloned.
      studioGit(workspaceDir, ['bundle', 'create', '-', 'HEAD', '--not', '--remotes=origin'], { stdout: fd, timeout: 300000 });
    } finally {
      closeSync(fd);
    }
    const prereqs = bundlePrerequisites(file);

    const repo = join(dir, 'push.git');
    const authEnv = hostGitEnv(gitEnv ? pick(gitEnv, /^GIT_CONFIG_(COUNT|KEY_\d+|VALUE_\d+)$/) : {});
    const g = (args, env = hostGitEnv(), timeout = 120000) =>
      execFileSync('git', [...HOST_GIT_BASE, `--git-dir=${repo}`, ...args], { env, stdio: 'pipe', timeout }); // host-git-ok: AppCrane's own temp bare repo
    execFileSync('git', [...HOST_GIT_BASE, 'init', '-q', '--bare', repo], { env: hostGitEnv(), stdio: 'pipe' }); // host-git-ok: AppCrane's own temp bare repo
    if (prereqs.length) g(['fetch', '-q', '--no-tags', '--depth=1', url, ...prereqs], authEnv);
    const listed = g(['bundle', 'unbundle', file]).toString('utf8').trim();
    if (!listed.startsWith(`${head} `)) throw new Error(`bundle tip ${listed.slice(0, 40)} is not workspace HEAD ${head}`);
    g(['update-ref', `refs/heads/${branchName}`, head]);
    g(['push', '-q', url, `refs/heads/${branchName}:refs/heads/${branchName}`], authEnv, 60000);
    return { head };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function pick(obj, re) {
  return Object.fromEntries(Object.entries(obj).filter(([k]) => re.test(k)));
}
