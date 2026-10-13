import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * The host must never run git — or npm — inside an agent-writable workspace
 * (builder/workspaceRunner.js). v2.97.8's allowlist check ran on the host and
 * then the host ran git: two moments, and a container loop swapping
 * .git/config between them got a filter driver executed as the AppCrane user.
 *
 * This file pins the design statically and from the argv actually issued:
 *   1. no host `git` / `npm` call in the coder and AppStudio services except
 *      the marked, justified ones (pre-mount clones, AppCrane's own repos);
 *   2. the helper container's confinement and its single mount;
 *   3. the rescue leaves the workspace as a bundle the HOST unbundles into
 *      the managed bare repo — no `git push` from the workspace.
 * test/workspace-runner-live.test.js proves it against real Docker.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'crane-wsrunner-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A docker that records its argv and plays nothing else, so the runtime cases
// below see exactly what AppCrane would hand the real daemon.
const BIN = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(DOCKER_LOG, '');
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\036'; } >> "${DOCKER_LOG}"
exit 0
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const runner = await import('../server/services/builder/workspaceRunner.js');
const { HARDENED_GIT_ARGS } = await import('../server/services/builder/workspaceGitGuard.js');
const { STUDIO_UID, STUDIO_GID } = await import('../server/services/builder/appContainer.js');
const { listWorkspaceChanges } = await import('../server/services/builder/gitOps.js');
const lg = await import('../server/services/localGit.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');
const dockerCalls = () => readFileSync(DOCKER_LOG, 'utf8').split('\x1e').filter(Boolean).map((l) => l.split('\x1f').slice(0, -1));

// ---------------------------------------------------------------------------
// 1. Static: where host git / npm may still run
// ---------------------------------------------------------------------------

const SCANNED = [
  ...readdirSync(new URL('../server/services/builder/', import.meta.url)).filter((f) => f.endsWith('.js')).map((f) => `server/services/builder/${f}`),
  'server/services/appstudio/worker.js',
  'server/services/appstudio/generator.js',
  'server/services/appstudio/contextBuilder.js',
  'server/services/appstudio/workspacePush.js',
  'server/routes/coder.js',
];

/**
 * Every host git left in these files, by file, with its reason. Adding one
 * means adding it here — on purpose, with the reason in a `host-git-ok:`
 * comment on the call — not by accident.
 */
const ALLOWED_HOST_GIT = {
  'server/services/builder/appContainer.js': 3,     // pre-mount: config user.* + checkout -B on a fresh clone
  'server/services/builder/workspaceGitGuard.js': 1, // `git config --file` of the config file, no repository
  'server/services/appstudio/generator.js': 6,       // ls-remote, pre-mount clone/config/checkout, the build clone
  'server/services/appstudio/contextBuilder.js': 1,  // production/current only; coder workspaces go through the runner
  'server/services/appstudio/workspacePush.js': 2,   // AppCrane's own temp bare repo
};

const HOST_PROC_RE = /\b(execFileSync|execFile|spawnSync|spawn|execSync|exec)\(\s*['"`](git|npm|npx)['"`]/;

test('no unmarked host git or npm call remains in the coder / AppStudio services', () => {
  const offenders = [];
  const counts = {};
  for (const rel of SCANNED) {
    const lines = read(rel).split('\n');
    lines.forEach((line, i) => {
      const m = HOST_PROC_RE.exec(line);
      if (!m) return;
      if (m[2] !== 'git' || !/\/\/ host-git-ok: \S/.test(line)) {
        offenders.push(`${rel}:${i + 1}: ${line.trim().slice(0, 140)}`);
        return;
      }
      counts[rel] = (counts[rel] || 0) + 1;
    });
  }
  assert.deepEqual(offenders, [], `host git/npm in an agent-writable workspace:\n${offenders.join('\n')}`);
  assert.deepEqual(counts, ALLOWED_HOST_GIT, 'the set of justified host git calls changed — review it and update ALLOWED_HOST_GIT');
});

test('the workspace git wrappers route through the container runner', () => {
  const gitOps = read('server/services/builder/gitOps.js');
  const appContainer = read('server/services/builder/appContainer.js');
  assert.match(gitOps, /runWorkspaceGit\(workspaceDir, args, \{ container/);
  assert.match(gitOps, /runWorkspaceScript\(workspaceDir, script, args, \{ container/);
  assert.match(appContainer, /export function gitIn\(dir, args, opts = \{\}\) \{\n\s+const out = runWorkspaceGit\(dir, args, opts\);/);
  // The rescue never pushes from the workspace: it bundles and the host imports.
  assert.doesNotMatch(appContainer, /gitIn\([^)]*\['push'/);
  assert.match(appContainer, /importWorkspaceBundleSync\(/);
  assert.match(appContainer, /'bundle', 'create', '-', 'HEAD'/);
});

// ---------------------------------------------------------------------------
// 2. The helper's confinement, from the argv it is started with
// ---------------------------------------------------------------------------

function flagValue(argv, flag) {
  const i = argv.indexOf(flag);
  return i < 0 ? undefined : argv[i + 1];
}

test('a helper runs non-root, with no network, no capabilities, limits, and only the workspace mounted', () => {
  const ws = join(ROOT, 'ws-helper');
  mkdirSync(join(ws, '.git'), { recursive: true });
  writeFileSync(DOCKER_LOG, '');
  runner.runWorkspaceGit(ws, ['status']);
  const calls = dockerCalls();
  assert.equal(calls.length, 1, `expected one docker call, got ${JSON.stringify(calls)}`);
  const a = calls[0];
  assert.equal(a[0], 'run');
  assert.ok(a.includes('--rm'));
  assert.equal(flagValue(a, '--network'), 'none');
  assert.equal(flagValue(a, '--cap-drop'), 'ALL');
  assert.equal(flagValue(a, '--security-opt'), 'no-new-privileges');
  assert.equal(flagValue(a, '--pids-limit'), '256');
  assert.equal(flagValue(a, '--memory'), '512m');
  assert.equal(flagValue(a, '--cpus'), '1');
  assert.ok(a.includes('--read-only'));
  assert.equal(flagValue(a, '--pull'), 'never');
  assert.equal(flagValue(a, '--user'), `${STUDIO_UID}:${STUDIO_GID}`);
  assert.notEqual(flagValue(a, '--user').split(':')[0], '0', 'helper runs as root');
  const mounts = a.filter((_, i) => a[i - 1] === '-v');
  assert.deepEqual(mounts, [`${ws}:/workspace`], 'a helper mounted more than the workspace');
  assert.ok(!a.some((x) => x === '--privileged' || x.startsWith('--network=host')));
  // The command is git with the hardened config, through --entrypoint (argv, no shell).
  const ep = a.indexOf('--entrypoint');
  assert.equal(a[ep + 1], 'git');
  const gitArgv = a.slice(ep + 3);
  for (const x of [...HARDENED_GIT_ARGS, 'core.fileMode=false', 'safe.directory=/workspace']) assert.ok(gitArgv.includes(x), `missing ${x}`);
  // And the same config in the environment, so a fixed script's gits get it too.
  assert.ok(a.includes('GIT_CONFIG_GLOBAL=/dev/null') && a.includes('GIT_CONFIG_NOSYSTEM=1'));
  assert.ok(a.includes('GIT_CONFIG_KEY_2=core.hooksPath') && a.includes('GIT_CONFIG_VALUE_2=/dev/null'));
});

test('with a live container, git is a docker exec as the studio user — no helper', () => {
  const ws = join(ROOT, 'ws-exec');
  mkdirSync(join(ws, '.git'), { recursive: true });
  writeFileSync(DOCKER_LOG, '');
  runner.runWorkspaceGit(ws, ['status'], { container: 'appcrane-app-demo' });
  const [a] = dockerCalls();
  assert.equal(a[0], 'exec');
  assert.equal(flagValue(a, '-u'), `${STUDIO_UID}:${STUDIO_GID}`);
  assert.equal(flagValue(a, '-w'), '/workspace');
  assert.equal(a[a.indexOf('appcrane-app-demo') + 1], 'git');
  assert.throws(() => runner.execArgs({ container: '--privileged', argv: ['git'] }), /refusing to exec/);
});

test('the change list costs two container round trips, not one per file', () => {
  const ws = join(ROOT, 'ws-batch');
  mkdirSync(join(ws, '.git'), { recursive: true });
  for (let i = 0; i < 30; i++) writeFileSync(join(ws, `f${i}.txt`), 'x');
  // The recording docker prints nothing, so fake a status listing through a
  // docker that answers the listing script once with 30 untracked files.
  const status = Array.from({ length: 30 }, (_, i) => `?? f${i}.txt`).join('\0');
  writeFileSync(join(BIN, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\036'; } >> "${DOCKER_LOG}"
case "$*" in *"git status"*) printf '\\000%b\\000' "${status.replace(/\0/g, '\\000')}" ;; esac
exit 0
`, { mode: 0o755 });
  writeFileSync(DOCKER_LOG, '');
  try {
    const out = listWorkspaceChanges(ws);
    assert.equal(out.length, 30);
    assert.equal(dockerCalls().length, 2, 'one docker call per changed file came back');
  } finally {
    writeFileSync(join(BIN, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\036'; } >> "${DOCKER_LOG}"
exit 0
`, { mode: 0o755 });
  }
});

// ---------------------------------------------------------------------------
// 3. Push design: the host imports a bundle into the managed repo
// ---------------------------------------------------------------------------

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const git = (args, cwd) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'core.hooksPath=/dev/null', ...args], { cwd, env: CLEAN }).toString('utf8').trim();

async function seededRepo(slug) {
  await lg.createAppRepo(slug);
  await lg.pushFilesToManagedRepo(slug, [{ path: 'a.txt', content: 'one\n' }], { message: 'seed' });
  const ws = join(ROOT, `${slug}-ws`);
  execFileSync('git', ['clone', '-q', '--no-local', '--depth', '1', lg.repoPath(slug), ws], { env: CLEAN });
  return ws;
}

function bundleOf(ws, name, notRef = 'refs/remotes/origin/main') {
  const file = join(ROOT, `${name}.bundle`);
  git(['bundle', 'create', '-q', file, 'HEAD', '--not', notRef], ws);
  return file;
}

test('importWorkspaceBundleSync lands the rescue on the branch, fast-forwards, and refuses unrelated history', async () => {
  const ws = await seededRepo('wsr-push');
  writeFileSync(join(ws, 'b.txt'), 'b\n');
  git(['add', 'b.txt'], ws); git(['commit', '-q', '-m', 'rescue'], ws);
  const head1 = git(['rev-parse', 'HEAD'], ws);
  assert.deepEqual(lg.importWorkspaceBundleSync('wsr-push', bundleOf(ws, 'b1'), 'agent/1/s', head1), { ok: true });
  assert.equal(git(['--git-dir', lg.repoPath('wsr-push'), 'rev-parse', 'refs/heads/agent/1/s']), head1);

  // A descendant fast-forwards the same branch.
  writeFileSync(join(ws, 'c.txt'), 'c\n');
  git(['add', 'c.txt'], ws); git(['commit', '-q', '-m', 'more'], ws);
  const head2 = git(['rev-parse', 'HEAD'], ws);
  assert.deepEqual(lg.importWorkspaceBundleSync('wsr-push', bundleOf(ws, 'b2'), 'agent/1/s', head2), { ok: true });

  // Unrelated history (a fresh clone's commit) is "taken", never forced.
  const ws2 = join(ROOT, 'wsr-push-ws2');
  execFileSync('git', ['clone', '-q', '--no-local', '--depth', '1', lg.repoPath('wsr-push'), ws2], { env: CLEAN });
  writeFileSync(join(ws2, 'd.txt'), 'd\n');
  git(['add', 'd.txt'], ws2); git(['commit', '-q', '-m', 'other'], ws2);
  const head3 = git(['rev-parse', 'HEAD'], ws2);
  assert.deepEqual(lg.importWorkspaceBundleSync('wsr-push', bundleOf(ws2, 'b3'), 'agent/1/s', head3), { ok: false, reason: 'taken' });
  assert.equal(git(['--git-dir', lg.repoPath('wsr-push'), 'rev-parse', 'refs/heads/agent/1/s']), head2, 'a taken ref was moved');
});

test('importWorkspaceBundleSync refuses a bundle whose tip is not the expected head, or whose base the repo lacks', async () => {
  const ws = await seededRepo('wsr-bad');
  writeFileSync(join(ws, 'b.txt'), 'b\n');
  git(['add', 'b.txt'], ws); git(['commit', '-q', '-m', 'x'], ws);
  const head = git(['rev-parse', 'HEAD'], ws);
  assert.throws(() => lg.importWorkspaceBundleSync('wsr-bad', bundleOf(ws, 'bad1'), 'agent/1/s', 'f'.repeat(40)), /expected head/);
  // A bundle built on a commit the managed repo has never seen.
  const alien = join(ROOT, 'alien');
  execFileSync('git', ['init', '-q', '-b', 'main', alien], { env: CLEAN });
  writeFileSync(join(alien, 'z'), 'z'); git(['add', 'z'], alien); git(['commit', '-q', '-m', 'z1'], alien);
  writeFileSync(join(alien, 'z'), 'zz'); git(['commit', '-qam', 'z2'], alien);
  const alienHead = git(['rev-parse', 'HEAD'], alien);
  assert.throws(() => lg.importWorkspaceBundleSync('wsr-bad', bundleOf(alien, 'bad2', 'HEAD~1'), 'agent/1/s', alienHead), /prerequisite|lacks/i);
  assert.equal(existsSync(join(lg.repoPath('wsr-bad'), 'refs', 'heads', 'agent')), false);
  assert.ok(head);
});
