import { execFileSync } from 'child_process';
import { existsSync, lstatSync } from 'fs';
import { join } from 'path';

// ---------------------------------------------------------------------------
// Host git inside an agent-writable workspace
// ---------------------------------------------------------------------------
//
// A coder workspace is bind-mounted into the agent's container and chmod 777'd
// (appContainer.cloneWorkspace), so everything under it — .git/ included — is
// the agent's to rewrite. The HOST then runs git there (the change list, the
// release bookkeeping commit, the eviction rescue commit). Git treats a repo's
// own config as trusted: `core.fsmonitor` runs a command on `git status`,
// `filter.<name>.clean` runs one on `git add`, `diff.external` / textconv on
// `git diff`, hooks on `git commit`, `include.path` pulls in any other file,
// and so on. `safe.directory` only waives the ownership check — it is what lets
// all of that in. Left alone, the agent could make the host run any command as
// the AppCrane user.
//
// Overriding known-bad keys with `-c` is a deny-list, and it cannot be complete:
// `filter.<anything>` and `diff.<anything>` are drivers named by the attacker.
// So the repo config is checked against an ALLOWLIST before every host git, and
// anything else refuses the operation. HARDENED_GIT_ARGS is defence in depth on
// top of that, not the fix.

/**
 * Keys a workspace config may carry, as `section.variable` for a plain key or
 * `section.*.variable` for one with a subsection. Git lowercases the section
 * and variable names it prints but not the subsection, so only those two parts
 * are compared, in lower case.
 *
 * Measured against what AppCrane itself writes (a `--no-local --depth 1` clone
 * of the managed bare repo, then `git config user.email/user.name`, then
 * `checkout -B builder/<slug>`): core.repositoryformatversion, core.filemode,
 * core.bare, core.logallrefupdates, core.ignorecase, core.precomposeunicode,
 * remote.origin.url, remote.origin.fetch, branch.main.remote,
 * branch.main.merge, user.email, user.name — all below. The rest are inert
 * settings git or the agent may legitimately add. None of them names a program.
 */
const ALLOWED_KEYS = new Set([
  'core.repositoryformatversion',
  'core.filemode',
  'core.bare',
  'core.logallrefupdates',
  'core.ignorecase',
  'core.precomposeunicode',
  'core.symlinks',
  'core.autocrlf',
  'core.safecrlf',
  'core.eol',
  'remote.*.url',
  'remote.*.fetch',
  'remote.*.pushurl',
  'branch.*.remote',
  'branch.*.merge',
  'branch.*.rebase',
  'user.name',
  'user.email',
  'init.defaultbranch',
  'pull.rebase',
  'extensions.objectformat',
]);

function isAllowedKey(key) {
  const first = key.indexOf('.');
  const last = key.lastIndexOf('.');
  if (first <= 0 || last === key.length - 1) return false;
  const section = key.slice(0, first).toLowerCase();
  const variable = key.slice(last + 1).toLowerCase();
  const shape = first === last ? `${section}.${variable}` : `${section}.*.${variable}`;
  return ALLOWED_KEYS.has(shape);
}

/**
 * Prepended to every host git run in a workspace. Each one was checked against
 * the host git: an EMPTY `diff.external=` is not "unset" — git tries to exec ""
 * and every diff dies — so external diff is turned off per invocation with
 * `--no-ext-diff` instead. `protocol.allow=never` + `protocol.file.allow=always`
 * matches localGit.js: the only remote this host ever talks to from a workspace
 * is the managed bare repo on local disk, so a `remote.origin.url` rewritten to
 * ssh:// or https:// cannot make the host dial out.
 */
export const HARDENED_GIT_ARGS = [
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.fsmonitor=false',
  '-c', 'core.untrackedCache=false',
  '-c', 'core.pager=cat',
  '-c', 'core.editor=false',
  '-c', 'commit.gpgSign=false',
  '-c', 'gc.auto=0',
  '-c', 'protocol.allow=never',
  '-c', 'protocol.file.allow=always',
];

/**
 * Files inside .git that redirect where git reads config or objects from, so an
 * allowlisted .git/config would not be the config git actually used:
 *
 *  - commondir: git takes the "common dir" — and its config — from the path in
 *    this file. Measured: with .git/commondir pointing at a bare repo whose
 *    config sets core.fsmonitor, `git status` in the workspace runs it while
 *    .git/config itself lists only allowlisted keys.
 *  - objects/info/alternates: borrows another repo's object store, which would
 *    let a rescue push carry objects out of a repository the agent cannot read.
 */
const REDIRECT_FILES = ['commondir', join('objects', 'info', 'alternates')];

function refuse(dir, why) {
  return new Error(
    `Refused to run git in workspace ${dir}: ${why}. The workspace is writable by the agent, ` +
    'and this could make the host run a command or read outside the workspace.',
  );
}

/**
 * Throws unless `<dir>/.git` is a plain repository whose config holds only
 * allowlisted keys. Runs nothing from the workspace: the config is listed by
 * pointing host git at the FILE (`--file`, `--no-includes`), from `/`, so no
 * repository discovery happens and no include is followed.
 */
export function assertSafeWorkspaceGit(dir) {
  const gitDir = join(dir, '.git');
  let st;
  try { st = lstatSync(gitDir); } catch (_) { throw refuse(dir, '.git does not exist'); }
  // A .git FILE (`gitdir: /elsewhere`) or a symlink would make the host operate
  // on, and trust the config of, some other repository on this machine.
  if (st.isSymbolicLink()) throw refuse(dir, '.git is a symlink');
  if (!st.isDirectory()) throw refuse(dir, '.git is not a directory (a gitdir: file points git at another repository)');

  for (const rel of REDIRECT_FILES) {
    if (existsSync(join(gitDir, rel)) || isLink(join(gitDir, rel))) {
      throw refuse(dir, `.git/${rel} exists`);
    }
  }

  const configPath = join(gitDir, 'config');
  let cst = null;
  try { cst = lstatSync(configPath); } catch (_) { cst = null; }
  if (!cst) return;
  if (!cst.isFile()) throw refuse(dir, '.git/config is not a regular file');

  const out = execFileSync('git', [
    '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
    'config', '--file', configPath, '--no-includes', '--null', '--list', '--name-only',
  ], {
    cwd: '/',
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
    stdio: 'pipe', timeout: 10000,
  }).toString('utf8');

  const bad = [...new Set(out.split('\0').filter(Boolean).filter((k) => !isAllowedKey(k)))];
  if (bad.length) {
    throw new Error(
      `Refused to run git in workspace ${dir}: the workspace git config was refused because ` +
      `it sets ${bad.map((k) => `'${k}'`).join(', ')}, which is not on the allowlist and could ` +
      'make the host run a command. The workspace is writable by the agent.',
    );
  }
}

function isLink(p) {
  try { return lstatSync(p).isSymbolicLink(); } catch (_) { return false; }
}
