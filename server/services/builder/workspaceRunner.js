import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';
import { isAbsolute } from 'path';
import { assertSafeWorkspaceGit, HARDENED_GIT_ARGS } from './workspaceGitGuard.js';
import { OOM_APP_FLAG } from '../oomPriority.js';

// ---------------------------------------------------------------------------
// Running git (and npm) in an agent-writable workspace — never on the host
// ---------------------------------------------------------------------------
//
// A coder or AppStudio workspace is bind-mounted read-write into the agent's
// container and chmod 777'd, so everything in it, .git/ included, is the
// agent's to rewrite. v2.97.8 made the HOST check .git/config against an
// allowlist before each git it ran there (workspaceGitGuard.js). That check and
// git's own read of the config are two separate moments, and the agent's
// container keeps running in between: a background loop that swaps .git/config
// (a `filter.<name>.clean` driver plus a `* filter=<name>` .gitattributes, an
// include.path, a .git/commondir) can land its version after the check passed
// and before git opened the file. The `-c` overrides close hooks and fsmonitor,
// but not an attacker-named filter driver — so a well-timed swap made the host
// run a command as the AppCrane user. No check done from outside the file can
// close that window; only not running git on the host can.
//
// So every git in a workspace runs INSIDE a container, as the studio user
// (uid 100 — the same uid the agent already runs as), with /workspace the only
// thing of the host it can see:
//
//   - the session's own container, through `docker exec`, when it is running.
//     Whatever the agent planted then runs as the agent, in the agent's own
//     sandbox: nothing it could not already do with its Bash tool.
//   - otherwise a throwaway helper from the same studio image: --rm, no
//     network, every capability dropped, no-new-privileges, a read-only root
//     filesystem, pids/memory/cpu limits, and ONLY the workspace mounted.
//
// assertSafeWorkspaceGit and HARDENED_GIT_ARGS stay as defence in depth — they
// keep a planted driver from running even inside the sandbox in the common,
// un-raced case, and they cost one `git config --file` read.

/** Where every runner mounts the workspace. The coder container mounts it here too. */
export const WORKSPACE_MOUNT = '/workspace';

/**
 * The studio image's user, pinned to 100:101 in infra/studio.Dockerfile (and
 * mirrored as appContainer.STUDIO_UID/STUDIO_GID). The agent writes its files
 * as this uid, so it is the one uid that can always read and write the
 * workspace — and it is never root, so a sandbox escape attempt starts from
 * the same place the agent already is.
 */
export const RUNNER_USER = '100:101';

export const STUDIO_IMAGE = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';

/** Every helper carries it, so an orphan left by a killed AppCrane is findable. */
export const HELPER_LABEL = 'appcrane.container.type=workspace-helper';

/**
 * The confinement of a helper container. 512m is plenty for git; the AppStudio
 * frontend build asks for the 2g its agent container already had. Asserted by
 * the guard test from the argv a helper is actually started with.
 */
export function helperConfinement({ memory = '512m' } = {}) {
  if (!/^[0-9]+[mg]$/.test(memory)) throw new Error(`bad helper memory limit ${memory}`);
  return [
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '256',
    '--memory', memory,
    '--cpus', '1',
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m',
  ];
}

/**
 * The git config every workspace git gets, as `-c` pairs. safe.directory is
 * needed because the workspace is owned by whoever cloned it, not by uid 100;
 * core.fileMode=false because cloneWorkspace's `chmod -R 777` otherwise makes
 * every tracked file look modified (see appContainer.js).
 */
export const WORKSPACE_GIT_ARGS = [
  '-c', `safe.directory=${WORKSPACE_MOUNT}`,
  '-c', 'core.fileMode=false',
  ...HARDENED_GIT_ARGS,
];

/**
 * The same config as an environment, so it also reaches every git a fixed
 * AppCrane script starts — `-c` on one command line does not. System and
 * global config are cut off too: inside the coder container HOME is the
 * agent's, and its ~/.gitconfig is the agent's to write.
 */
export function workspaceGitEnv(extra = {}) {
  const env = {
    HOME: '/tmp',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    LC_ALL: 'C',
    // The commits AppCrane makes here (the rescue snapshot, the release
    // bookkeeping) are AppCrane's, whatever user.* the agent left in
    // .git/config — and with global config cut off, a deleted user.email
    // would otherwise fail the commit.
    GIT_AUTHOR_NAME: 'AppCrane Builder',
    GIT_AUTHOR_EMAIL: 'builder@appcrane.local',
    GIT_COMMITTER_NAME: 'AppCrane Builder',
    GIT_COMMITTER_EMAIL: 'builder@appcrane.local',
  };
  const pairs = [];
  for (let i = 0; i < WORKSPACE_GIT_ARGS.length; i += 2) {
    const kv = WORKSPACE_GIT_ARGS[i + 1];
    const eq = kv.indexOf('=');
    pairs.push([kv.slice(0, eq), kv.slice(eq + 1)]);
  }
  env.GIT_CONFIG_COUNT = String(pairs.length);
  pairs.forEach(([k, v], i) => { env[`GIT_CONFIG_KEY_${i}`] = k; env[`GIT_CONFIG_VALUE_${i}`] = v; });
  return { ...env, ...extra };
}

function envFlags(env) {
  const out = [];
  for (const [k, v] of Object.entries(env)) out.push('-e', `${k}=${v}`);
  return out;
}

/** A path that would re-split a `-v` argument is a programming error here, not input. */
function assertMountable(p, what) {
  if (typeof p !== 'string' || !p || !isAbsolute(p)) throw new Error(`${what} must be an absolute path, got ${JSON.stringify(p)}`);
  if (p.includes(':') || p.includes(',')) throw new Error(`${what} contains a docker -v separator: ${p}`);
}

/**
 * argv for a throwaway helper. `network` is 'none' unless a caller names
 * another (only the AppStudio npm install does, and says why). `mounts` are
 * extra host dirs AppCrane owns — never another part of the workspace's parent.
 */
export function helperRunArgs({ workspaceDir, name, argv, env = {}, network = 'none', mounts = [], memory, image = STUDIO_IMAGE }) {
  assertMountable(workspaceDir, 'the workspace');
  if (!Array.isArray(argv) || !argv.length) throw new Error('helperRunArgs needs a command');
  const args = [
    'run', '--rm', '-i',
    OOM_APP_FLAG,
    '--name', name,
    '--pull', 'never',
    '--label', HELPER_LABEL,
    '--user', RUNNER_USER,
    '--network', network,
    ...helperConfinement({ memory }),
    '-w', WORKSPACE_MOUNT,
    ...envFlags(workspaceGitEnv(env)),
    '-v', `${workspaceDir}:${WORKSPACE_MOUNT}`,
  ];
  for (const m of mounts) {
    assertMountable(m.host, 'a helper mount');
    if (!isAbsolute(m.target) || m.target.includes(':')) throw new Error(`bad helper mount target ${m.target}`);
    args.push('-v', `${m.host}:${m.target}${m.readOnly ? ':ro' : ''}`);
  }
  args.push('--entrypoint', argv[0], image, ...argv.slice(1));
  return args;
}

/** argv for running in the session's live container, as the studio user. */
export function execArgs({ container, argv, env = {} }) {
  if (typeof container !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(container)) {
    throw new Error(`refusing to exec into container ${JSON.stringify(container)}`);
  }
  return ['exec', '-i', '-u', RUNNER_USER, '-w', WORKSPACE_MOUNT, ...envFlags(workspaceGitEnv(env)), container, ...argv];
}

/** `docker exec` into a container that is gone fails like this; anything else is the command's own failure. */
const CONTAINER_GONE_RE = /No such container|is not running|is paused|is restarting/i;

/**
 * Run `argv` in the workspace, inside a container, and return stdout (Buffer).
 *
 * `container` is the session's live container name, or null. A container that
 * turns out to be gone falls back to a helper; any other failure is thrown as
 * execFileSync threw it (err.status, err.stdout, err.stderr intact), because
 * callers read `git diff`'s exit 1 and stdout from it.
 *
 * `stdout` may be a file descriptor to stream into instead of a buffer — the
 * rescue bundle uses it, so a large bundle never has to fit in memory.
 */
export function runInWorkspace(workspaceDir, argv, {
  container = null, env = {}, network = 'none', mounts = [], memory, timeout = 60000,
  maxBuffer = 64 * 1024 * 1024, stdout = 'pipe', input = '',
} = {}) {
  const stdio = [input === null ? 'ignore' : 'pipe', stdout, 'pipe'];
  const opts = { stdio, timeout, maxBuffer, ...(input === null ? {} : { input }) };
  if (container) {
    try {
      return execFileSync('docker', execArgs({ container, argv, env }), opts);
    } catch (err) {
      if (!CONTAINER_GONE_RE.test(String(err.stderr || ''))) throw err;
    }
  }
  const name = `appcrane-wshelper-${randomBytes(6).toString('hex')}`;
  try {
    return execFileSync('docker', helperRunArgs({ workspaceDir, name, argv, env, network, mounts, memory }), opts);
  } catch (err) {
    // A timeout kills the docker CLI, not the container it started.
    if (err.code === 'ETIMEDOUT' || err.signal) {
      try { execFileSync('docker', ['rm', '-f', name], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
    }
    throw err;
  }
}

/** git in the workspace: config allowlist first, then the hardened git, in a container. */
export function runWorkspaceGit(workspaceDir, args, opts = {}) {
  assertSafeWorkspaceGit(workspaceDir);
  return runInWorkspace(workspaceDir, ['git', ...WORKSPACE_GIT_ARGS, ...args], opts);
}

/**
 * A FIXED script shipped by AppCrane, with workspace-derived values passed as
 * positional arguments ("$1"...) — never interpolated into the script text.
 * Used where one container round trip per file would be the cost otherwise.
 */
export function runWorkspaceScript(workspaceDir, script, args = [], opts = {}) {
  assertSafeWorkspaceGit(workspaceDir);
  return runInWorkspace(workspaceDir, ['sh', '-c', script, 'appcrane-script', ...args], opts);
}
