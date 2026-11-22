import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A repo URL is never parsed as a git option, and the released version is never
// read through a committed symlink. git is a logging wrapper around real git.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-askgitargs-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const REAL_GIT = execFileSync('which', ['git']).toString().trim();
const SHIM = join(ROOT, 'bin');
const LOG = join(ROOT, 'git.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${LOG}"
exec "${REAL_GIT}" "$@"
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb } = await import('../server/db.js');
initDb();
const { checkRemoteBranchExists, cloneForBuild, cloneForCode, cleanupWorkspace } = await import('../server/services/appstudio/generator.js');
const { deployedPackageVersion } = await import('../server/services/appstudio/worker.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const IDENTITY = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid' };
const git = (...a) => execFileSync(REAL_GIT, a, { stdio: 'pipe', env: { ...process.env, ...IDENTITY } }).toString().trim();
const seed = join(ROOT, 'seed');
git('init', '-q', '-b', 'main', seed);
writeFileSync(join(seed, 'hello.txt'), 'hello\n');
git('-C', seed, 'add', '.');
git('-C', seed, 'commit', '-qm', 'seed');
const BARE = join(ROOT, 'repo.git');
git('clone', '-q', '--bare', seed, BARE);
git('--git-dir', BARE, 'branch', 'appstudio/1-x', 'main');

const logged = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8') : '').split('\n').filter(Boolean).map((l) => l.split('\x1f').slice(0, -1));
function urlArgFollowsSeparator(sub, url) {
  const argv = logged().find((a) => a[0] === sub);
  assert.ok(argv, `git ${sub} was never run`);
  const at = argv.indexOf(url);
  assert.ok(at > 0, `${url} not in ${argv.join(' ')}`);
  assert.equal(argv[at - 1], '--', `no -- before the URL: ${argv.join(' ')}`);
}

const pwned = join(ROOT, 'PWNED');
const EVIL = `--upload-pack=touch ${pwned};`;

test('ls-remote does not run a command from a URL that looks like an option', () => {
  writeFileSync(LOG, '');
  const found = checkRemoteBranchExists(EVIL, null, null, 'appstudio/5-foo');
  assert.equal(found, false);
  assert.equal(existsSync(pwned), false, 'git ran the --upload-pack value');
  urlArgFollowsSeparator('ls-remote', EVIL);
});

test('ls-remote still answers for a real remote', () => {
  assert.equal(checkRemoteBranchExists(BARE, null, null, 'appstudio/1-x'), true);
  assert.equal(checkRemoteBranchExists(BARE, null, null, 'appstudio/2-y'), false);
});

test('cloneForBuild passes the URL after -- and still clones', () => {
  writeFileSync(LOG, '');
  const dir = cloneForBuild(9001, { github_url: BARE, github_token_encrypted: null }, 'appstudio/1-x');
  assert.equal(readFileSync(join(dir, 'hello.txt'), 'utf8'), 'hello\n');
  urlArgFollowsSeparator('clone', BARE);
  cleanupWorkspace(9001);
});

test('cloneForCode passes the URL after -- at both git calls and still clones', async () => {
  writeFileSync(LOG, '');
  const dir = join(ROOT, 'code-job');
  mkdirSync(dir, { recursive: true });
  await cloneForCode(dir, { slug: 'x', github_url: BARE, github_token_encrypted: null }, 'main', 'appstudio/7-new');
  assert.equal(readFileSync(join(dir, 'workspace', 'hello.txt'), 'utf8'), 'hello\n');
  urlArgFollowsSeparator('ls-remote', BARE);
  urlArgFollowsSeparator('clone', BARE);
});

test('a URL that looks like an option does not run through either clone', async () => {
  writeFileSync(LOG, '');
  assert.throws(() => cloneForBuild(9002, { github_url: EVIL, github_token_encrypted: null }, 'main'));
  const dir = join(ROOT, 'code-job-evil');
  mkdirSync(dir, { recursive: true });
  await assert.rejects(cloneForCode(dir, { slug: 'x', github_url: EVIL, github_token_encrypted: null }, 'main', 'appstudio/8-new'));
  assert.equal(existsSync(pwned), false);
  for (const a of logged().filter((x) => x[0] === 'clone')) assert.equal(a[a.indexOf(EVIL) - 1], '--');
  cleanupWorkspace(9002);
});

// --- released version --------------------------------------------------------

function release(slug) {
  const current = join(ROOT, 'apps', slug, 'production', 'current');
  mkdirSync(current, { recursive: true });
  return current;
}

test('the released version comes from a regular package.json', () => {
  writeFileSync(join(release('rel-ok'), 'package.json'), JSON.stringify({ version: '1.2.3' }));
  assert.equal(deployedPackageVersion('rel-ok'), '1.2.3');
});

test('a package.json that is a symlink to a host file is not read', () => {
  const outside = join(ROOT, 'host-file.json');
  writeFileSync(outside, JSON.stringify({ version: 'HOST-SECRET-VALUE' }));
  symlinkSync(outside, join(release('rel-link'), 'package.json'));
  assert.equal(deployedPackageVersion('rel-link'), null);
});

test('no package.json, or one without a version, gives no version', () => {
  release('rel-none');
  assert.equal(deployedPackageVersion('rel-none'), null);
  writeFileSync(join(release('rel-nover'), 'package.json'), '{}');
  assert.equal(deployedPackageVersion('rel-nover'), null);
});
