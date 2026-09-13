/**
 * Host-local git storage for managed apps (phase 1 of moving AMC_<slug> repos
 * off GitHub). Bare repositories live at <DATA_DIR>/repos/<slug>.git.
 *
 * Callers reach it through services/managedRepo.js, which picks this module or
 * githubService.js from apps.repo_backend. It began as a transport swap: the three
 * GitHub functions a managed app uses are exported here under the SAME names,
 * with the same arguments, the same return shape and the same error codes
 * (REPO_EXISTS 409, REPO_NOT_FOUND 404, FILE_NOT_FOUND 404) — changing the
 * import path in a caller is the whole migration for that caller.
 *
 *   createAppRepo(slug, { description, autoInit })
 *   pushFilesToManagedRepo(slug, files, { branch, message })
 *   readManagedRepoFile(slug, path, { branch })
 *   getBranchHeadSha(slug, branch)          (what supplyChain.js asks GitHub)
 *
 * Deliberate differences from the GitHub versions, each forced by there being
 * no web host: `html_url` / `ssh_url` are null, `clone_url` is the absolute
 * path of the bare repo (git clones a path directly), `owner_type` is 'local'.
 *
 * Everything is git plumbing against the bare repo — hash-object, a temporary
 * GIT_INDEX_FILE, write-tree, commit-tree, update-ref. No worktree, no checkout.
 *
 * ISOLATION. A repo's contents, and the host's git configuration, must never
 * change what these commands do or run anything:
 *   - git gets an environment built from scratch (PATH + ours). Inherited
 *     GIT_DIR / GIT_INDEX_FILE / GIT_CONFIG_PARAMETERS / GIT_CONFIG_COUNT and
 *     friends cannot reach it.
 *   - GIT_CONFIG_NOSYSTEM=1 and GIT_CONFIG_GLOBAL=/dev/null: no system or user
 *     config (signing, hooksPath, init.defaultBranch, identity, fsmonitor).
 *     GIT_CONFIG_GLOBAL needs git >= 2.32; older git silently ignores it, so
 *     that version is enforced rather than assumed.
 *   - `-c core.hooksPath=/dev/null` on every call. Command-line config beats the
 *     repo's own config, so a restored repo cannot re-enable hooks (update-ref
 *     runs the reference-transaction hook).
 *   - the default branch is passed explicitly; commits are never signed.
 *
 * IDENTITY. GitHub attributes a service-account push to the token's account;
 * nothing names a person in code. Locally a commit needs an explicit author, so
 * every commit is authored AND committed by LOCAL_GIT_IDENTITY: the product
 * name and an address under the reserved `.invalid` TLD (RFC 2606) that can
 * never be delivered or belong to anyone.
 */

import { execFile, execFileSync, spawn } from 'child_process';
import { createHash, randomBytes } from 'crypto';
import {
  existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, statSync, writeFileSync, readdirSync, readFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(join(__dirname, '..', '..'));

export const MANAGED_REPO_PREFIX = 'AMC_';
export const LOCAL_GIT_IDENTITY = Object.freeze({ name: 'AppCrane', email: 'noreply@appcrane.invalid' });
export const DEFAULT_BRANCH = 'main';
export const MIN_GIT_VERSION = [2, 32];

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]{1,200}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const ZERO_SHA = '0'.repeat(40);

const dataDir = () => resolve(process.env.DATA_DIR || join(repoRoot, 'data'));
export const reposRoot = () => resolve(join(dataDir(), 'repos'));

function fail(code, status, message, body) {
  const err = new Error(`${code}: ${message}`);
  err.status = status;
  err.code = code;
  if (body) err.body = body;
  return err;
}

export function assertSlug(slug) {
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) {
    throw new Error(`localGit: refusing slug ${JSON.stringify(slug)}`);
  }
  return slug;
}

/** Absolute path of a slug's bare repo, range-checked to sit inside the repos root. */
export function repoPath(slug) {
  const root = reposRoot();
  const p = resolve(join(root, `${assertSlug(slug)}.git`));
  if (!p.startsWith(`${root}/`)) throw new Error(`localGit: repo path for ${JSON.stringify(slug)} escapes ${root}`);
  return p;
}

export function localRepoExists(slug) {
  const p = repoPath(slug);
  try { return statSync(p).isDirectory() && existsSync(join(p, 'HEAD')); } catch (_) { return false; }
}

/** Slugs with a repo on disk. Anything whose name is not <valid-slug>.git is ignored. */
export function listLocalRepoSlugs() {
  const root = reposRoot();
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .map((n) => /^([a-z0-9][a-z0-9-]{0,99})\.git$/.exec(n)?.[1])
    .filter((s) => s && localRepoExists(s))
    .sort();
}

function assertBranch(branch) {
  if (typeof branch !== 'string' || !BRANCH_RE.test(branch) || branch.startsWith('/') || branch.startsWith('-')
      || branch.endsWith('/') || branch.endsWith('.') || branch.endsWith('.lock')
      || branch.includes('..') || branch.includes('//') || branch.includes('/.') || branch.startsWith('.')) {
    throw new Error(`invalid branch name ${JSON.stringify(branch)}`);
  }
  return branch;
}

/**
 * Repo-relative path from an untrusted caller. The GitHub version's rule (no
 * "..", no leading slash) is kept verbatim so a path accepted there is accepted
 * here; on top of it, anything git would store wrongly or silently drop is
 * refused: empty / "." segments, a ".git" component in any case (git itself
 * prints "Ignoring path" and commits WITHOUT the file), and NUL.
 */
export function assertRepoFilePath(p) {
  if (typeof p !== 'string' || p.length === 0) throw new Error('path is required');
  if (p.includes('..') || p.startsWith('/')) {
    throw new Error(`invalid file path '${p}': must be repo-relative, no ".." or leading slash`);
  }
  if (p.includes('\0') || p.includes('\\')) throw new Error(`invalid file path '${p}': NUL or backslash`);
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') throw new Error(`invalid file path '${p}': empty or "." segment`);
    if (seg.toLowerCase() === '.git') throw new Error(`invalid file path '${p}': a ".git" component is not allowed`);
  }
  return p;
}

// ---------------------------------------------------------------------------
// Running git
// ---------------------------------------------------------------------------

function gitEnv(extra = {}) {
  return {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    LC_ALL: 'C',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GIT_LITERAL_PATHSPECS: '1',
    GIT_AUTHOR_NAME: LOCAL_GIT_IDENTITY.name,
    GIT_AUTHOR_EMAIL: LOCAL_GIT_IDENTITY.email,
    GIT_COMMITTER_NAME: LOCAL_GIT_IDENTITY.name,
    GIT_COMMITTER_EMAIL: LOCAL_GIT_IDENTITY.email,
    ...extra,
  };
}

function gitArgs(gitDir, args) {
  const base = [
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.fsmonitor=false',
    '-c', 'commit.gpgSign=false',
    '-c', 'gc.auto=0',
    '-c', 'protocol.allow=never',
  ];
  return gitDir ? [...base, `--git-dir=${gitDir}`, ...args] : [...base, ...args];
}

let versionChecked = false;
export function parseGitVersion(out) {
  const m = /git version (\d+)\.(\d+)/.exec(String(out));
  return m ? [Number(m[1]), Number(m[2])] : null;
}
function ensureGitVersion() {
  if (versionChecked) return;
  const out = execFileSync('git', ['--version'], { env: gitEnv(), stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  const v = parseGitVersion(out);
  if (!v || v[0] < MIN_GIT_VERSION[0] || (v[0] === MIN_GIT_VERSION[0] && v[1] < MIN_GIT_VERSION[1])) {
    throw fail('GIT_TOO_OLD', 500,
      `host git is '${out.trim()}'; local managed repos need git >= ${MIN_GIT_VERSION.join('.')} (GIT_CONFIG_GLOBAL isolation is ignored by older git)`);
  }
  versionChecked = true;
}

function gitAsync(gitDir, args, { input, env } = {}) {
  ensureGitVersion();
  return new Promise((resolveP, reject) => {
    const child = execFile('git', gitArgs(gitDir, args), {
      env: gitEnv(env), encoding: 'buffer', maxBuffer: 512 * 1024 * 1024, timeout: 120000,
    }, (err, stdout, stderr) => {
      if (err) {
        const e = new Error(`git ${args[0]} failed: ${String(stderr || err.message).trim()}`);
        e.exitCode = err.code;
        e.stderr = String(stderr || '');
        return reject(e);
      }
      resolveP(stdout);
    });
    // A command that exits without reading stdin (rev-parse) must not crash the
    // process with an unhandled EPIPE.
    child.stdin.on('error', () => {});
    child.stdin.end(input === undefined ? '' : input);
  });
}

function gitSync(gitDir, args, { input, env } = {}) {
  ensureGitVersion();
  try {
    return execFileSync('git', gitArgs(gitDir, args), {
      env: gitEnv(env), input: input === undefined ? '' : input, maxBuffer: 512 * 1024 * 1024,
      timeout: 600000, stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    const e = new Error(`git ${args[0]} failed: ${String(err.stderr || err.message).trim()}`);
    e.exitCode = err.status;
    throw e;
  }
}

const text = (buf) => buf.toString('utf8').trim();

async function resolveBranchCommit(gitDir, branch) {
  try {
    const sha = text(await gitAsync(gitDir, ['rev-parse', '--verify', '--quiet', `refs/heads/${branch}^{commit}`]));
    return SHA_RE.test(sha) ? sha : null;
  } catch (_) {
    return null;
  }
}

async function defaultBranchOf(gitDir) {
  try {
    const ref = text(await gitAsync(gitDir, ['symbolic-ref', '--quiet', 'HEAD']));
    if (ref.startsWith('refs/heads/')) return ref.slice('refs/heads/'.length);
  } catch (_) { /* detached or unreadable HEAD: fall through */ }
  return DEFAULT_BRANCH;
}

function initBareSync(dir, branch = DEFAULT_BRANCH) {
  mkdirSync(dirname(dir), { recursive: true });
  gitSync(null, ['init', '--quiet', '--bare', '--template=', '--object-format=sha1', `--initial-branch=${branch}`, dir]);
}

// ---------------------------------------------------------------------------
// The GitHub-shaped API
// ---------------------------------------------------------------------------

/**
 * Mirrors githubService.createAppRepo. A repo that already exists is never
 * touched; the call throws REPO_EXISTS exactly as the GitHub version does,
 * because appcrane_create_managed_app's repair path branches on that code.
 *
 * autoInit (default true) mirrors GitHub's auto_init: one "Initial commit"
 * holding README.md on the default branch. That commit is load-bearing — push
 * extends an existing branch and refuses a missing one, on GitHub and here.
 *
 * The repo is assembled in a sibling temp dir and renamed into place, so a
 * crash leaves either no repo or a complete one, never an empty branch.
 */
export async function createAppRepo(slug, { description = '', autoInit = true } = {}) {
  if (!slug || typeof slug !== 'string') throw new Error('slug is required');
  const final = repoPath(slug);
  const repoName = `${MANAGED_REPO_PREFIX}${slug}`;
  if (existsSync(final)) {
    throw fail('REPO_EXISTS', 409,
      `the managed repository '${repoName}' already exists. Pick a different app slug, or delete the existing repo if it's safe to do so.`,
      { code: 'REPO_EXISTS', existing: repoName });
  }

  const staging = join(reposRoot(), `.creating-${slug}-${randomBytes(6).toString('hex')}.git`);
  try {
    initBareSync(staging, DEFAULT_BRANCH);
    if (autoInit) {
      const readme = `# ${repoName}\n\n${description || `AppCrane-managed app: ${slug}`}\n`;
      const blob = text(await gitAsync(staging, ['hash-object', '-w', '--no-filters', '--stdin'], { input: readme }));
      const tree = text(await gitAsync(staging, ['mktree', '-z'], { input: `100644 blob ${blob}\tREADME.md\0` }));
      const commit = text(await gitAsync(staging, ['commit-tree', '--no-gpg-sign', tree], { input: 'Initial commit\n' }));
      await gitAsync(staging, ['update-ref', '-m', 'create', `refs/heads/${DEFAULT_BRANCH}`, commit, ZERO_SHA]);
    }
    try {
      renameSync(staging, final);
    } catch (e) {
      if (['EEXIST', 'ENOTEMPTY', 'EISDIR', 'ENOTDIR'].includes(e.code)) {
        throw fail('REPO_EXISTS', 409, `the managed repository '${repoName}' already exists.`,
          { code: 'REPO_EXISTS', existing: repoName });
      }
      throw e;
    }
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }

  return {
    full_name:      repoName,
    html_url:       null,
    clone_url:      final,
    ssh_url:        null,
    default_branch: DEFAULT_BRANCH,
    private:        true,
    visibility:     'private',
    owner_type:     'local',
  };
}

/**
 * Mirrors githubService.pushFilesToManagedRepo: same validation, same
 * `files: [{ path, content, encoding? }]` (utf-8 | base64), same options
 * ({ branch, message }), same return
 *   { commit: { sha, html_url }, branch, files: [{ path, sha, sha256, bytes, encoding }], message }.
 * One call = one commit whose parent is the branch tip. Like GitHub there is no
 * way to express a deletion, and mode is always 100644.
 *
 * RACES: THE NEWEST PUSH WINS, AND WHAT IT DISPLACES IS KEPT.
 *
 * Decided by the owner: when two pushes race, drop the oldest. The ref is still
 * moved with compare-and-swap (`update-ref <ref> <new> <old>`), so nothing is
 * ever overwritten by accident — but when the swap finds the branch has moved,
 * this push parks whatever landed first under
 * `refs/dropped/<branch>/<ms>-<displaced12>-by-<this12>` and then takes the tip.
 *
 * "Whole push" on purpose: this commit was built from the tree as it stood
 * before the other push landed, so taking the tip also removes files only the
 * other push changed. That is the accepted cost. The displaced commit is not
 * lost: it stays reachable from its refs/dropped ref, travels in the config
 * backup (bundles carry every ref), and is reported to the caller in `dropped`
 * so the drop is never silent.
 *
 * A push can therefore report success and later be displaced by a newer one.
 * That is what "newest wins" means; the refs/dropped ref is the record.
 */
/** How many times one push may displace a moving tip before giving up. */
const MAX_TAKEOVER_ATTEMPTS = 10;

export async function pushFilesToManagedRepo(slug, files, opts = {}) {
  if (!slug || typeof slug !== 'string') throw new Error('slug is required');
  if (!Array.isArray(files) || files.length === 0) throw new Error('files must be a non-empty array');
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') {
      throw new Error('each file needs { path: string, content: string }');
    }
    assertRepoFilePath(f.path);
    if (f.encoding && !['utf-8', 'base64'].includes(f.encoding)) {
      throw new Error(`invalid encoding '${f.encoding}': must be 'utf-8' or 'base64'`);
    }
  }

  const gitDir = repoPath(slug);
  const repoName = `${MANAGED_REPO_PREFIX}${slug}`;
  if (!localRepoExists(slug)) {
    throw fail('REPO_NOT_FOUND', 404, `the managed repository '${repoName}' doesn't exist yet. Did you call appcrane_create_managed_app first?`);
  }

  const branch = assertBranch(opts.branch || await defaultBranchOf(gitDir));
  const message = opts.message || `chore: scaffolding for ${slug}`;

  const parent = await resolveBranchCommit(gitDir, branch);
  if (!parent) {
    throw fail('BRANCH_NOT_FOUND', 404, `branch '${branch}' does not exist in the managed repository '${repoName}'.`);
  }

  const blobs = [];
  for (const f of files) {
    const encoding = f.encoding || 'utf-8';
    const decoded = encoding === 'base64' ? Buffer.from(f.content, 'base64') : Buffer.from(f.content, 'utf-8');
    const sha = text(await gitAsync(gitDir, ['hash-object', '-w', '--no-filters', '--stdin'], { input: decoded }));
    blobs.push({
      path: f.path,
      sha,
      sha256: createHash('sha256').update(decoded).digest('hex'),
      bytes: decoded.length,
      encoding,
    });
  }

  const idxDir = mkdtempSync(join(tmpdir(), 'appcrane-git-idx-'));
  let commit;
  try {
    const env = { GIT_INDEX_FILE: join(idxDir, 'index') };
    await gitAsync(gitDir, ['read-tree', `${parent}^{tree}`], { env });
    const entries = blobs.map((b) => `100644 blob ${b.sha}\t${b.path}\0`).join('');
    await gitAsync(gitDir, ['update-index', '-z', '--index-info'], { env, input: entries });
    const tree = text(await gitAsync(gitDir, ['write-tree'], { env }));
    commit = text(await gitAsync(gitDir, ['commit-tree', '--no-gpg-sign', tree, '-p', parent], { input: message }));
  } finally {
    rmSync(idxDir, { recursive: true, force: true });
  }

  const dropped = [];
  let expected = parent;
  for (let attempt = 0; ; attempt++) {
    try {
      await gitAsync(gitDir, ['update-ref', '-m', 'push', `refs/heads/${branch}`, commit, expected]);
      break;
    } catch (e) {
      const tip = await resolveBranchCommit(gitDir, branch);
      if (!tip) {
        throw fail('BRANCH_NOT_FOUND', 404, `branch '${branch}' was deleted while this push was being built.`);
      }
      if (attempt >= MAX_TAKEOVER_ATTEMPTS) {
        throw fail('BRANCH_MOVED', 409,
          `branch '${branch}' kept moving under ${MAX_TAKEOVER_ATTEMPTS} takeover attempts; nothing was committed. ${e.stderr || ''}`.trim());
      }
      // Park the displaced tip BEFORE taking the branch, so there is no moment
      // at which it is reachable from nothing. Created with the zero SHA as the
      // old value: an existing ref of that name is refused, never overwritten.
      const ref = `refs/dropped/${branch}/${Date.now()}-${tip.slice(0, 12)}-by-${commit.slice(0, 12)}`;
      await gitAsync(gitDir, ['update-ref', '-m', `dropped by ${commit}`, ref, tip, ZERO_SHA]);
      dropped.push({ sha: tip, ref });
      expected = tip;
    }
  }

  return {
    commit: { sha: commit, html_url: null },
    branch,
    files: blobs,
    message,
    dropped,
  };
}

/**
 * Mirrors githubService.readManagedRepoFile: { content (utf-8 text), sha (git
 * blob SHA), encoding, bytes }. Missing repo, branch or path all surface as
 * FILE_NOT_FOUND 404, the single code the GitHub version maps every 404 to.
 * `encoding` is 'base64' because that is what GitHub's contents API reports.
 */
export async function readManagedRepoFile(slug, path, opts = {}) {
  if (!slug || typeof slug !== 'string') throw new Error('slug is required');
  if (!path || typeof path !== 'string') throw new Error('path is required');
  assertRepoFilePath(path);
  const gitDir = repoPath(slug);
  const notFound = () => fail('FILE_NOT_FOUND', 404,
    `'${path}' does not exist in this app's managed repository${opts.branch ? ` on branch ${opts.branch}` : ''}.`);
  if (!localRepoExists(slug)) throw notFound();

  const branch = assertBranch(opts.branch || await defaultBranchOf(gitDir));
  const commit = await resolveBranchCommit(gitDir, branch);
  if (!commit) throw notFound();

  const listing = (await gitAsync(gitDir, ['ls-tree', '-z', '--full-tree', commit, '--', path])).toString('utf8');
  const entry = listing.split('\0').find((l) => l.endsWith(`\t${path}`));
  if (!entry) throw notFound();
  const [meta] = entry.split('\t');
  const [mode, type, sha] = meta.split(' ');
  if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) {
    throw new Error(`'${path}' is not a file (it is a ${type === 'tree' ? 'dir' : type === 'commit' ? 'submodule' : 'symlink'})`);
  }
  const buf = await gitAsync(gitDir, ['cat-file', 'blob', sha]);
  return { content: buf.toString('utf-8'), sha, encoding: 'base64', bytes: buf.length };
}

/**
 * The branch tip as a 40-hex SHA — what supplyChain.js compares a deploy's
 * clone HEAD against. Throws (with .status) rather than returning a sentinel,
 * matching the GitHub branch read it will replace.
 */
export async function getBranchHeadSha(slug, branch) {
  const gitDir = repoPath(slug);
  if (!localRepoExists(slug)) throw fail('REPO_NOT_FOUND', 404, `no managed repository for '${slug}'.`);
  const b = assertBranch(branch || await defaultBranchOf(gitDir));
  const sha = await resolveBranchCommit(gitDir, b);
  if (!sha) throw fail('BRANCH_NOT_FOUND', 404, `branch '${b}' does not exist for '${slug}'.`);
  return sha;
}

// ---------------------------------------------------------------------------
// Deploy clones (phase 2)
// ---------------------------------------------------------------------------

/**
 * git for a deploy's working tree. Same isolation as every other call here,
 * because the ambient environment is not harmless for a clone: measured, a
 * plain `git clone` with core.hooksPath set in ~/.gitconfig or in
 * GIT_CONFIG_COUNT/KEY/VALUE runs that directory's post-checkout hook. The
 * source repo's own config and hooks/ are NOT consulted by the clone (also
 * measured), but the host's are — so the host's are cut off.
 *
 * `protocol.file.allow=always` re-opens only the file transport that the
 * shared base (`protocol.allow=never`) closes; later `-c` wins for that one
 * protocol, every other transport stays refused.
 */
function deployGitSync(label, args, slug) {
  ensureGitVersion();
  try {
    return execFileSync('git', gitArgs(null, ['-c', 'protocol.file.allow=always', ...args]), {
      env: gitEnv(), input: '', maxBuffer: 64 * 1024 * 1024, timeout: 120000, stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    // The deploy log is read by app owners; the host's DATA_DIR layout is not
    // theirs to see. Name the repo the way every other message does.
    const detail = String(err.stderr || err.message).trim().replaceAll(repoPath(slug), `${MANAGED_REPO_PREFIX}${slug}`);
    const e = new Error(`git ${label} failed: ${detail}`);
    e.exitCode = err.status;
    throw e;
  }
}

/**
 * Shallow single-branch clone of <slug>.git into `destDir` (empty or absent).
 *
 * `--no-local` with a plain path, not a bare path and not a file:// URL:
 * measured, a plain-path clone IGNORES --depth ("--depth is ignored in local
 * clones") and hardlinks the live repo's objects into the release directory;
 * `--no-local` goes through upload-pack like a remote clone, honours --depth,
 * and needs no URL-encoding of DATA_DIR. `--template=` copies no hooks into
 * the new clone.
 */
export function cloneForDeploySync(slug, destDir, branch) {
  if (!localRepoExists(slug)) {
    throw fail('REPO_NOT_FOUND', 404, `the managed repository '${MANAGED_REPO_PREFIX}${slug}' does not exist on this host.`);
  }
  const b = assertBranch(branch || DEFAULT_BRANCH);
  deployGitSync('clone', ['clone', '--quiet', '--no-local', '--template=', '--depth', '1', '--branch', b, '--', repoPath(slug), destDir], slug);
}

/**
 * Check a deploy clone out at `commit` (full or abbreviated SHA), the same
 * sequence deployer.js runs against GitHub: fetch that exact commit; if that
 * fails (an abbreviated SHA cannot be fetched by name), deepen the branch to
 * 200 commits; then detach at it. Throws if the commit is unreachable.
 */
export function pinDeployCloneSync(slug, workTree, commit, branch) {
  if (typeof commit !== 'string' || !/^[0-9a-f]{4,40}$/.test(commit)) {
    throw new Error(`invalid commit ${JSON.stringify(commit)}: expected a hex SHA`);
  }
  const b = assertBranch(branch || DEFAULT_BRANCH);
  let fetched = false;
  try {
    deployGitSync('fetch', ['-C', workTree, 'fetch', '--quiet', '--depth', '1', 'origin', commit], slug);
    fetched = true;
  } catch (_) { /* abbreviated SHA: deepen below */ }
  if (!fetched) {
    try { deployGitSync('fetch', ['-C', workTree, 'fetch', '--quiet', '--depth', '200', 'origin', b], slug); } catch (_) { /* checkout reports it */ }
  }
  deployGitSync('checkout', ['-C', workTree, 'checkout', '--quiet', '--detach', commit], slug);
}

// ---------------------------------------------------------------------------
// Backup (synchronous: configBackup.js builds its zip synchronously)
// ---------------------------------------------------------------------------

/**
 * One repo as { head, bundle }. `head` is HEAD's symbolic target
 * ('refs/heads/main'); `bundle` is a git bundle of every ref, or null for a
 * repo with no refs yet (git refuses to create an empty bundle).
 *
 * A bundle rather than a copy of the repo directory, because it is: a
 * consistent snapshot taken by git itself (a copy racing a push can capture a
 * ref before its objects); already packed, whatever state the loose objects
 * are in, without gc-ing the live repo; and it cannot carry the repo's
 * `config` or `hooks/`, so a backup is never a way to smuggle those in.
 */
export function bundleRepoSync(slug) {
  const gitDir = repoPath(slug);
  let head = `refs/heads/${DEFAULT_BRANCH}`;
  try {
    const ref = gitSync(gitDir, ['symbolic-ref', '--quiet', 'HEAD']).toString('utf8').trim();
    if (ref.startsWith('refs/heads/')) head = ref;
  } catch (_) { /* keep the default */ }
  const refs = gitSync(gitDir, ['for-each-ref', '--format=%(refname)']).toString('utf8').trim();
  if (!refs) return { head, bundle: null };

  const dir = mkdtempSync(join(tmpdir(), 'appcrane-git-bundle-'));
  try {
    const file = join(dir, 'repo.bundle');
    gitSync(gitDir, ['bundle', 'create', '--quiet', file, '--all']);
    return { head, bundle: readFileSync(file) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Build a repo from a backup into `stageDir/<slug>.git` WITHOUT touching the
 * live one. Verifies the bundle, unbundles it, recreates every ref it lists,
 * points HEAD at `head`, and runs `git fsck --full`. Throws on any failure so
 * an import can refuse before it has replaced anything.
 *
 * Returns { slug, head, refs, headSha }.
 */
export function stageRepoFromBundleSync(stageDir, slug, head, bundle) {
  assertSlug(slug);
  if (typeof head !== 'string' || !/^refs\/heads\//.test(head)) throw new Error(`repo ${slug}: invalid HEAD ${JSON.stringify(head)}`);
  const branch = assertBranch(head.slice('refs/heads/'.length));
  const root = resolve(stageDir);
  const dest = resolve(join(root, `${slug}.git`));
  if (!dest.startsWith(`${root}/`)) throw new Error(`repo ${slug}: staging path escapes ${root}`);

  initBareSync(dest, branch);
  let refs = 0;
  if (bundle) {
    const file = join(root, `${slug}.bundle`);
    writeFileSync(file, bundle);
    try {
      gitSync(dest, ['bundle', 'verify', '--quiet', file]);
      const listed = gitSync(dest, ['bundle', 'unbundle', file]).toString('utf8');
      const updates = [];
      for (const line of listed.split('\n')) {
        const m = /^([0-9a-f]{40}) (refs\/\S+)$/.exec(line.trim());
        if (!m) continue;
        gitSync(null, ['check-ref-format', m[2]]);
        updates.push(`create ${m[2]} ${m[1]}\n`);
      }
      if (updates.length) gitSync(dest, ['update-ref', '--stdin'], { input: updates.join('') });
      refs = updates.length;
    } finally {
      rmSync(file, { force: true });
    }
  }
  gitSync(dest, ['symbolic-ref', 'HEAD', head]);
  gitSync(dest, ['fsck', '--full', '--no-progress']);
  let headSha = null;
  try { headSha = gitSync(dest, ['rev-parse', '--verify', '--quiet', `${head}^{commit}`]).toString('utf8').trim() || null; } catch (_) {}
  return { slug, head, refs, headSha };
}

/**
 * Move staged repos into the live repos root. A live repo being replaced is
 * moved to `preImportDir/repos/<slug>.git` first, the same reversible pattern
 * the DB import uses. Returns the slugs installed.
 */
export function installStagedReposSync(stageDir, slugs, preImportDir) {
  const root = reposRoot();
  mkdirSync(root, { recursive: true });
  const installed = [];
  for (const slug of slugs) {
    const live = repoPath(slug);
    if (existsSync(live)) {
      const aside = join(preImportDir, 'repos', `${slug}.git`);
      mkdirSync(dirname(aside), { recursive: true });
      renameSync(live, aside);
    }
    renameSync(join(stageDir, `${assertSlug(slug)}.git`), live);
    installed.push(slug);
  }
  return installed;
}

export function newImportStageDir() {
  const dir = join(reposRoot(), `.import-${Date.now()}-${randomBytes(4).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ---------------------------------------------------------------------------
// Bounded reads (Ask Claude on a local repo)
// ---------------------------------------------------------------------------

// Plumbing that only reads. `grep` is git's own tree search, not the shell's.
const READ_ONLY_SUBCOMMANDS = new Set(['ls-tree', 'cat-file', 'grep', 'rev-parse']);

/**
 * Run one read-only git command against <slug>.git with the same isolation as
 * every other call here, keeping at most `maxBytes` of stdout. Past the cap the
 * process is killed, so a huge blob or a grep matching everything costs at most
 * `maxBytes` of memory — gitAsync buffers up to 512 MiB and cannot promise that.
 * Resolves { stdout, truncated, exitCode, timedOut }; never rejects on a git
 * failure (grep exits 1 for "no match"), only on a refused subcommand.
 */
export function gitReadCapped(slug, args, { maxBytes, timeoutMs = 15000 } = {}) {
  if (!Array.isArray(args) || !READ_ONLY_SUBCOMMANDS.has(args[0])) {
    throw new Error(`localGit: ${JSON.stringify(args?.[0])} is not a read-only subcommand`);
  }
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) throw new Error('localGit: maxBytes is required');
  ensureGitVersion();
  const gitDir = repoPath(slug);
  return new Promise((resolveP) => {
    const child = spawn('git', gitArgs(gitDir, args), { env: gitEnv(), stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks = [];
    let kept = 0;
    let truncated = false;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      const room = maxBytes - kept;
      if (chunk.length > room) {
        chunks.push(chunk.subarray(0, room));
        kept = maxBytes;
        truncated = true;
        child.kill('SIGKILL');
        return;
      }
      chunks.push(chunk);
      kept += chunk.length;
    });
    child.on('error', () => {});
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveP({ stdout: Buffer.concat(chunks, kept), truncated, exitCode: code, timedOut });
    });
  });
}

// ---------------------------------------------------------------------------
// Moving a GitHub-backed repo onto this host (phase 3, services/repoMigration.js)
// ---------------------------------------------------------------------------

/**
 * Where an app's repo is assembled before it is moved into place. One fixed
 * name per slug, so a process that died mid-migration leaves exactly one
 * directory behind, and the next attempt removes it before starting. It starts
 * with "." so listLocalRepoSlugs (and so the config backup) never sees it.
 */
export function migrationStagingPath(slug) {
  return join(reposRoot(), `.migrating-${assertSlug(slug)}.git`);
}

/**
 * Remote git with a hard wall-clock deadline and the credential kept out of
 * every place that outlives the process or is visible to other users:
 *   - not in the URL (so not in argv, `ps`, FETCH_HEAD, reflogs or error text);
 *   - not in any config file: it travels as GIT_CONFIG_COUNT/KEY/VALUE in the
 *     child's environment, which only the same uid (or root) can read;
 *   - scoped to the remote's origin (`http.<origin>/.extraHeader`) with
 *     redirects refused, so it is never sent to a host GitHub redirects to.
 * The allowed transport is only the URL's own scheme; everything else stays
 * refused by the shared `protocol.allow=never`.
 *
 * Resolves stdout; rejects with .code 'GIT_TIMEOUT' when the deadline kills it,
 * or 'GIT_FAILED'. Every message has the token removed before it leaves here.
 */
function migrationGit(gitDir, args, { url, token, deadline, allowedSchemes = ['https'] } = {}) {
  ensureGitVersion();
  const extra = ['-c', 'http.followRedirects=false', '-c', 'credential.helper='];
  const env = {};
  if (url) {
    const u = new URL(url);
    const scheme = u.protocol.replace(/:$/, '');
    if (!allowedSchemes.includes(scheme)) {
      return Promise.reject(Object.assign(new Error(`transport '${scheme}' is not allowed for a repo migration`), { code: 'BAD_REMOTE' }));
    }
    if (u.username || u.password) {
      return Promise.reject(Object.assign(new Error('remote URL must not carry credentials'), { code: 'BAD_REMOTE' }));
    }
    extra.push('-c', `protocol.${scheme}.allow=always`);
    if (token && (scheme === 'https' || scheme === 'http')) {
      env.GIT_CONFIG_COUNT = '1';
      env.GIT_CONFIG_KEY_0 = `http.${u.origin}/.extraHeader`;
      env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`;
    }
  }
  const scrub = (s) => {
    let out = String(s);
    if (token) {
      out = out.replaceAll(token, '[redacted]')
        .replaceAll(Buffer.from(`x-access-token:${token}`).toString('base64'), '[redacted]');
    }
    return out;
  };
  const remaining = deadline - Date.now();
  if (!(remaining > 0)) {
    return Promise.reject(Object.assign(new Error(`git ${args[0]} not started: migration deadline already passed`), { code: 'GIT_TIMEOUT' }));
  }
  // Measured: SIGKILL on `git` alone leaves its `git remote-http` helpers
  // running (reparented to init) with the stdout/stderr pipes still open, so
  // 'close' never fires while the remote stays silent and the deadline bounds
  // nothing. git therefore runs as its own process group, the whole group is
  // killed, and a timed-out call settles on 'exit' without waiting for 'close'.
  return new Promise((resolveP, reject) => {
    const child = spawn('git', gitArgs(gitDir, [...extra, ...args]), { env: gitEnv(env), stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    const out = [];
    let err = '';
    let timedOut = false;
    let settled = false;
    const settle = (fn) => { if (!settled) { settled = true; fn(); } };
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch (_) { try { child.kill('SIGKILL'); } catch (_) { /* already gone */ } }
    }, remaining);
    const timeoutError = () => Object.assign(new Error(`git ${args[0]} killed after ${remaining}ms (migration deadline)`), { code: 'GIT_TIMEOUT' });
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => { if (err.length < 8192) err += c.toString('utf8'); });
    child.on('error', (e) => { clearTimeout(timer); settle(() => reject(Object.assign(new Error(scrub(`git ${args[0]}: ${e.message}`)), { code: 'GIT_FAILED' }))); });
    child.on('exit', () => {
      if (!timedOut) return;
      clearTimeout(timer);
      child.stdout.destroy();
      child.stderr.destroy();
      settle(() => reject(timeoutError()));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (timedOut) {
        return reject(timeoutError());
      }
      if (code !== 0) {
        return reject(Object.assign(new Error(scrub(`git ${args[0]} failed (exit ${code}): ${err.trim()}`)), { code: 'GIT_FAILED' }));
      }
      resolveP(Buffer.concat(out).toString('utf8'));
    });
  });
}

function parseRefLines(textOut) {
  const refs = {};
  for (const line of textOut.split('\n')) {
    const m = /^([0-9a-f]{40})[\t ](refs\/\S+)$/.exec(line.trim());
    if (m) refs[m[2]] = m[1];
  }
  return refs;
}

/**
 * Fresh bare repo at `stagingDir` holding GitHub's branches and tags, and
 * nothing else. The fetch names the URL directly with explicit refspecs, so no
 * remote is ever configured, refs/pull/* and other hosting refs are never
 * requested, and --no-write-fetch-head keeps the URL out of FETCH_HEAD.
 */
export async function fetchMirrorIntoStaging(stagingDir, { url, token, branch, deadline, allowedSchemes }) {
  assertBranch(branch);
  rmSync(stagingDir, { recursive: true, force: true });
  initBareSync(stagingDir, branch);
  await migrationGit(stagingDir, [
    'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--no-recurse-submodules', '--no-auto-gc',
    '--', url, '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*',
  ], { url, token, deadline, allowedSchemes });
}

/** GitHub's branches and tags as { ref: sha } (tag objects, not peeled). */
export async function listRemoteHeadsAndTags({ url, token, deadline, allowedSchemes }) {
  const outText = await migrationGit(null, ['ls-remote', '--heads', '--tags', '--refs', '--', url],
    { url, token, deadline, allowedSchemes });
  return parseRefLines(outText);
}

/** The staged repo's branches and tags as { ref: sha }, same shape as the remote listing. */
export async function listStagedHeadsAndTags(stagingDir, { deadline }) {
  const outText = await migrationGit(stagingDir,
    ['for-each-ref', '--format=%(objectname) %(refname)', 'refs/heads', 'refs/tags'], { deadline });
  return parseRefLines(outText);
}

/**
 * Violations that make a staged repo differ from what createAppRepo builds:
 * any remote or http config, any ref outside refs/heads and refs/tags, a
 * FETCH_HEAD, or a HEAD that is not refs/heads/<branch> at a commit.
 * Returns [] for a clean repo.
 */
export async function inspectMigratedRepoShape(gitDir, { branch, deadline }) {
  assertBranch(branch);
  const problems = [];
  let cfg = '';
  try {
    cfg = await migrationGit(gitDir, ['config', '--file', join(gitDir, 'config'), '--name-only', '--get-regexp', '^(remote|http|credential|url)\\.'], { deadline });
  } catch (e) {
    if (e.code === 'GIT_TIMEOUT') throw e;
    // exit 1 = no matching key, the clean case
  }
  if (cfg.trim()) problems.push(`config keys that must not exist: ${cfg.trim().split('\n').join(', ')}`);
  const refs = (await migrationGit(gitDir, ['for-each-ref', '--format=%(refname)'], { deadline })).split('\n').filter(Boolean);
  const stray = refs.filter((r) => !r.startsWith('refs/heads/') && !r.startsWith('refs/tags/'));
  if (stray.length) problems.push(`refs outside heads/tags: ${stray.join(', ')}`);
  if (existsSync(join(gitDir, 'FETCH_HEAD'))) problems.push('FETCH_HEAD present');
  let head = '';
  try { head = (await migrationGit(gitDir, ['symbolic-ref', '--quiet', 'HEAD'], { deadline })).trim(); } catch (e) { if (e.code === 'GIT_TIMEOUT') throw e; }
  if (head !== `refs/heads/${branch}`) problems.push(`HEAD is ${JSON.stringify(head)}, expected refs/heads/${branch}`);
  else {
    try { await migrationGit(gitDir, ['rev-parse', '--verify', '--quiet', `refs/heads/${branch}^{commit}`], { deadline }); } catch (e) {
      if (e.code === 'GIT_TIMEOUT') throw e;
      problems.push(`branch ${branch} does not resolve to a commit`);
    }
  }
  return problems;
}

/**
 * Bring a staged repo to the shape createAppRepo produces, then refuse it if
 * anything is still off. Removes every remote.* section, deletes refs outside
 * heads/tags, drops FETCH_HEAD, points HEAD at the app's branch, and checks the
 * object graph is connected. Throws (.code 'SHAPE') on a remaining violation.
 */
export async function finalizeStagedMirror(stagingDir, { branch, deadline }) {
  assertBranch(branch);
  let names = '';
  try {
    names = await migrationGit(stagingDir, ['config', '--file', join(stagingDir, 'config'), '--name-only', '--get-regexp', '^remote\\.'], { deadline });
  } catch (e) { if (e.code === 'GIT_TIMEOUT') throw e; }
  const sections = new Set(names.split('\n').filter(Boolean).map((n) => n.slice(0, n.lastIndexOf('.'))));
  for (const section of sections) {
    await migrationGit(stagingDir, ['config', '--file', join(stagingDir, 'config'), '--remove-section', section], { deadline });
  }
  const refs = (await migrationGit(stagingDir, ['for-each-ref', '--format=%(refname)'], { deadline })).split('\n').filter(Boolean);
  const stray = refs.filter((r) => !r.startsWith('refs/heads/') && !r.startsWith('refs/tags/'));
  for (const ref of stray) {
    await migrationGit(stagingDir, ['update-ref', '--no-deref', '-d', ref], { deadline });
  }
  rmSync(join(stagingDir, 'FETCH_HEAD'), { force: true });
  await migrationGit(stagingDir, ['symbolic-ref', 'HEAD', `refs/heads/${branch}`], { deadline });
  await migrationGit(stagingDir, ['fsck', '--connectivity-only', '--no-progress'], { deadline });
  const problems = await inspectMigratedRepoShape(stagingDir, { branch, deadline });
  if (problems.length) {
    throw Object.assign(new Error(`staged repo is not clean: ${problems.join('; ')}`), { code: 'SHAPE' });
  }
}

/**
 * Move a verified staged repo to repoPath(slug). Never replaces anything: an
 * existing path (repo or not) is refused with .code 'LOCAL_REPO_EXISTS'.
 */
export function installMigratedRepo(slug, stagingDir) {
  const final = repoPath(slug);
  if (existsSync(final)) {
    throw Object.assign(new Error(`a local repository for '${slug}' already exists; not overwriting it`), { code: 'LOCAL_REPO_EXISTS' });
  }
  try {
    renameSync(stagingDir, final);
  } catch (e) {
    if (['EEXIST', 'ENOTEMPTY', 'EISDIR', 'ENOTDIR'].includes(e.code)) {
      throw Object.assign(new Error(`a local repository for '${slug}' appeared during install; not overwriting it`), { code: 'LOCAL_REPO_EXISTS' });
    }
    throw e;
  }
  return final;
}

// ---------------------------------------------------------------------------
// Upload conversion (services/uploadConversion.js)
// ---------------------------------------------------------------------------

/**
 * Where an uploaded app's repo is assembled before it is renamed into place.
 * Same rules as migrationStagingPath: one fixed name per slug, starts with "."
 * so listLocalRepoSlugs and the config backup never see it.
 */
export function conversionStagingPath(slug) {
  return join(reposRoot(), `.converting-${assertSlug(slug)}.git`);
}

/** The isolated environment every git in this module runs with (no host config, fixed identity). */
export function isolatedGitEnv(extra = {}) {
  return gitEnv(extra);
}

/** The isolated argv prefix (no hooks, no fsmonitor, no signing, no gc, no transports). */
export function isolatedGitArgs(gitDir, args) {
  return gitArgs(gitDir, args);
}
