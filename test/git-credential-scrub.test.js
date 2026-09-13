import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, lstatSync, rmSync, symlinkSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync, spawn } from 'child_process';

// Credentials that earlier versions left on disk.
//
// Deploys, AppStudio and the builder used to clone with the token in the URL,
// and git writes that URL into the working copy's .git/config. The clone paths
// are fixed; these working copies already exist on every upgraded host and
// keep the token until something removes it.
//
// The leaked copies here are made the way production made them: a real git
// clone from a real `git http-backend` that refuses requests without an
// Authorization header, with the credential in the URL, then the promote-style
// pin fetch. So the files checked are the files git really writes.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-scrub-'));
process.env.LOG_LEVEL = 'error';
process.env.GIT_TERMINAL_PROMPT = '0';
const TOKEN = 'ghp_LEAKEDONDISK0123456789abcdefABCD';
const DATA = join(ROOT, 'data');

// --- a git server that requires the credential ---------------------------------
const REPOS = join(ROOT, 'srv');
mkdirSync(join(REPOS, 'acme'), { recursive: true });
const BARE = join(REPOS, 'acme', 'widget.git');
execFileSync('git', ['init', '--bare', '-q', '-b', 'main', BARE]);
{
  const work = mkdtempSync(join(ROOT, 'seed-'));
  const g = (...a) => execFileSync('git', ['-C', work, ...a], { stdio: 'pipe' });
  execFileSync('git', ['init', '-q', '-b', 'main', work]);
  g('config', 'user.email', 'seed@example.com');
  g('config', 'user.name', 'seed');
  writeFileSync(join(work, 'index.js'), 'console.log(1)\n');
  g('add', '.');
  g('commit', '-qm', 'seed');
  g('push', '-q', BARE, 'main');
}
const HEAD_SHA = execFileSync('git', ['-C', BARE, 'rev-parse', 'HEAD']).toString().trim();
const AUTH_LOG = join(ROOT, 'git-auth.jsonl');
writeFileSync(AUTH_LOG, '');
const gitServer = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/git-http-auth-server.mjs', import.meta.url)), REPOS, AUTH_LOG], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
const GIT_PORT = await new Promise((resolveP, reject) => {
  gitServer.once('error', reject);
  gitServer.stdout.once('data', (d) => resolveP(parseInt(String(d).trim(), 10)));
});
const TOKEN_URL = `http://x-access-token:${TOKEN}@127.0.0.1:${GIT_PORT}/acme/widget.git`;

after(() => {
  gitServer.kill();
  rmSync(ROOT, { recursive: true, force: true });
});

const { scrubGitCredentialsOnDisk, stripUrlCredentials } = await import('../server/services/gitCredentialScrub.js');

/** Clone the way the old code did: token in the URL, then a pin fetch. */
function leakedClone(dir) {
  mkdirSync(join(dir, '..'), { recursive: true });
  execFileSync('git', ['clone', '-q', '--depth', '1', '--branch', 'main', TOKEN_URL, dir], { stdio: 'pipe' });
  execFileSync('git', ['-C', dir, 'fetch', '-q', '--depth', '1', 'origin', HEAD_SHA], { stdio: 'pipe' });
  return dir;
}

/** Every regular file under `dir` (no symlinks followed) that contains the token. */
function filesWithToken(dir) {
  const hits = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && readFileSync(p).includes(TOKEN)) hits.push(p.slice(dir.length + 1));
    }
  };
  walk(dir);
  return hits.sort();
}

const release = leakedClone(join(DATA, 'apps', 'widget', 'sandbox', 'releases', '1789000000000-git'));
const studioWorkspace = leakedClone(join(DATA, 'appstudio-jobs', '42', 'workspace'));
const studioBuild = leakedClone(join(DATA, 'appstudio-jobs', 'build-43'));
const builderWorkspace = leakedClone(join(DATA, 'app-containers', 'widget', 'workspace'));

// App data is the app's own business: a repo an app keeps under its data dir is
// out of scope even if its config holds a credential.
const appData = join(DATA, 'apps', 'widget', 'sandbox', 'shared', 'data', 'vendored');
mkdirSync(join(appData, '.git'), { recursive: true });
const APP_DATA_CONFIG = `[remote "origin"]\n\turl = https://user:${TOKEN}@example.com/app/own.git\n`;
writeFileSync(join(appData, '.git', 'config'), APP_DATA_CONFIG);

// A release whose .git is a symlink to somewhere else must not be followed.
const outside = join(ROOT, 'outside-git');
mkdirSync(outside, { recursive: true });
const OUTSIDE_CONFIG = `[remote "origin"]\n\turl = https://${TOKEN}@github.com/acme/other\n`;
writeFileSync(join(outside, 'config'), OUTSIDE_CONFIG);
const linkedRelease = join(DATA, 'apps', 'widget', 'production', 'releases', '1789000000001-git');
mkdirSync(linkedRelease, { recursive: true });
symlinkSync(outside, join(linkedRelease, '.git'));

const leakedCopies = [release, studioWorkspace, studioBuild, builderWorkspace];
const before = Object.fromEntries(leakedCopies.map((d) => [d, filesWithToken(d)]));

test('CONTROL: the old clone really left the token on disk', () => {
  for (const d of leakedCopies) {
    assert.ok(before[d].includes(join('.git', 'config')), `no token in ${d}/.git/config, so the scrub below would prove nothing: ${JSON.stringify(before[d])}`);
  }
  const auth = readFileSync(AUTH_LOG, 'utf8');
  assert.match(auth, /"auth":"Basic /, 'the server never saw a credential, so these clones did not authenticate');
});

test('the scrub removes the token from every working copy the clone paths made', () => {
  const r = scrubGitCredentialsOnDisk(DATA);
  assert.equal(r.errors, 0);
  assert.equal(r.dirsScrubbed, 4, JSON.stringify(r));
  for (const d of leakedCopies) {
    assert.deepEqual(filesWithToken(d), [], `token still on disk in ${d}`);
  }
});

test('the working copies still work and point at the same remote, without the credential', () => {
  for (const d of leakedCopies) {
    assert.equal(execFileSync('git', ['-C', d, 'rev-parse', 'HEAD']).toString().trim(), HEAD_SHA);
    assert.equal(execFileSync('git', ['-C', d, 'config', 'remote.origin.url']).toString().trim(),
      `http://127.0.0.1:${GIT_PORT}/acme/widget.git`);
  }
});

test('file modes are kept', () => {
  const cfg = join(release, '.git', 'config');
  assert.equal(statSync(cfg).mode & 0o777, statSync(join(release, '.git', 'HEAD')).mode & 0o777);
});

test('app data and symlinked .git directories are left alone', () => {
  assert.equal(readFileSync(join(appData, '.git', 'config'), 'utf8'), APP_DATA_CONFIG, 'the scrub rewrote a repo inside app data');
  assert.equal(readFileSync(join(outside, 'config'), 'utf8'), OUTSIDE_CONFIG, 'the scrub followed a symlinked .git');
});

test('FETCH_HEAD and reflogs are scrubbed too, whatever wrote them', () => {
  // Measured above: git itself anonymizes the URL it records in FETCH_HEAD and
  // the reflogs, so a clone never leaves the token there. The scrub covers them
  // anyway, because a working copy can be touched by other tools and older gits.
  const d = leakedClone(join(DATA, 'apps', 'widget', 'sandbox', 'releases', '1789000000002-git'));
  const planted = `${HEAD_SHA}\t\tbranch 'main' of https://${TOKEN}@github.com/acme/widget\n`;
  writeFileSync(join(d, '.git', 'FETCH_HEAD'), planted);
  writeFileSync(join(d, '.git', 'logs', 'HEAD'), `0 ${HEAD_SHA} x <x@example.com> 1 +0000\tclone: from https://${TOKEN}@github.com/acme/widget\n`);
  mkdirSync(join(d, '.git', 'logs', 'refs', 'remotes', 'origin'), { recursive: true });
  writeFileSync(join(d, '.git', 'logs', 'refs', 'remotes', 'origin', 'main'), `0 ${HEAD_SHA} x <x@example.com> 1 +0000\tfetch: https://${TOKEN}@github.com/acme/widget\n`);
  scrubGitCredentialsOnDisk(DATA);
  assert.deepEqual(filesWithToken(d), [], 'a planted credential survived');
});

test('a second run finds nothing to do', () => {
  const r = scrubGitCredentialsOnDisk(DATA);
  assert.equal(r.dirsScrubbed, 0);
  assert.equal(r.filesScrubbed, 0);
});

test('only the credential is removed from a URL', () => {
  assert.equal(stripUrlCredentials('url = https://ghp_x@github.com/a/b'), 'url = https://github.com/a/b');
  assert.equal(stripUrlCredentials('url = https://x-access-token:ghs_y@github.com/a/b.git'), 'url = https://github.com/a/b.git');
  assert.equal(stripUrlCredentials('url = https://github.com/a/b'), 'url = https://github.com/a/b');
  assert.equal(stripUrlCredentials('email = someone@example.com'), 'email = someone@example.com');
});

test('a missing data directory is not an error', () => {
  assert.deepEqual(scrubGitCredentialsOnDisk(join(ROOT, 'nope')), { scanned: 0, filesScrubbed: 0, dirsScrubbed: 0, errors: 0 });
});
