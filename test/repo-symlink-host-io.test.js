import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Second Defending Code harness pass (2026-10-14), area 3. A release dir, an
// AppStudio workspace and a coder workspace are git checkouts of the app's
// repo, and git checks a committed symbolic link out as a link. The host then
// read and wrote through them as root:
//   icon      public/icon.png -> a host file, copied to the public icon URL
//   docker    a dangling Dockerfile link; the generated Dockerfile was written
//             wherever it pointed
//   snapshot  .appcrane -> a host dir; the GitHub snapshot was written there
//   context   README.md -> a host file; its text went into the LLM prompt and
//             the stored context document

const ROOT = mkdtempSync(join(tmpdir(), 'crane-rsym-'));
process.env.DATA_DIR = join(ROOT, 'data');
mkdirSync(process.env.DATA_DIR, { recursive: true });
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-platform-key-for-test';
const REAL_GIT = execFileSync('which', ['git']).toString().trim();

// The host secret every case tries to reach.
const SECRET_DIR = join(ROOT, 'host');
mkdirSync(SECRET_DIR);
const SECRET = join(SECRET_DIR, 'appcrane.env');
writeFileSync(SECRET, 'ENCRYPTION_KEY=host-secret-value\n');

// A docker that records its argv (the context prompt travels there) and fails.
const BIN = join(ROOT, 'bin');
const ARGV = join(ROOT, 'docker-argv');
mkdirSync(BIN);
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in
  image) echo 5 ; exit 0 ;;
  run) { for a in "$@"; do printf '%s\\037' "$a"; done; } > "${ARGV}" ; exit 1 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb } = await import('../server/db.js');
initDb();

const release = (name) => {
  const dir = mkdtempSync(join(ROOT, `${name}-`));
  return dir;
};

test('icon: a linked public/icon.png is not copied to the public icon path', async () => {
  const { pickUpAppIcon } = await import('../server/services/appIcon.js');
  const dir = release('icon');
  mkdirSync(join(dir, 'public'));
  symlinkSync(SECRET, join(dir, 'public', 'icon.png'));
  assert.equal(pickUpAppIcon({ releaseDir: dir, dataDir: process.env.DATA_DIR, slug: 'rsym' }), null);
  assert.ok(!existsSync(join(process.env.DATA_DIR, 'apps', 'rsym', 'icon.png')), 'the host file was published as the app icon');

  // A linked public/ directory is the same thing one level up.
  const dir2 = release('icon2');
  symlinkSync(SECRET_DIR, join(dir2, 'public'));
  writeFileSync(join(SECRET_DIR, 'icon.png'), 'host bytes');
  assert.equal(pickUpAppIcon({ releaseDir: dir2, dataDir: process.env.DATA_DIR, slug: 'rsym' }), null);

  // A real icon is still picked up.
  const ok = release('icon3');
  mkdirSync(join(ok, 'public'));
  writeFileSync(join(ok, 'public', 'icon.png'), 'png bytes');
  assert.equal(pickUpAppIcon({ releaseDir: ok, dataDir: process.env.DATA_DIR, slug: 'rsym' }), 'png');
});

test('docker: a dangling Dockerfile link is refused, and nothing is written where it points', async () => {
  const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
  const dir = release('docker');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', scripts: { start: 'node server.js' } }));
  writeFileSync(join(dir, 'package-lock.json'), '{}');
  writeFileSync(join(dir, 'server.js'), '');
  const target = join(SECRET_DIR, 'cron-job');
  symlinkSync(target, join(dir, 'Dockerfile'));
  assert.throws(() => ensureDockerfile({ releaseDir: dir, manifest: {}, appBasePath: '/x', craneUrl: '', craneInternalUrl: '' }),
    /symbolic link/);
  assert.ok(!existsSync(target), 'the generated Dockerfile was written through the link');
});

test('snapshot: a linked .appcrane directory does not carry the snapshot out of the workspace', async () => {
  const { writeSnapshot } = await import('../server/services/github/snapshot.js');
  const ws = release('ws');
  const outside = mkdtempSync(join(ROOT, 'outside-'));
  symlinkSync(outside, join(ws, '.appcrane'));
  await writeSnapshot({ slug: 'rsym' }, ws);
  assert.ok(!existsSync(join(outside, 'CLAUDE.md')), 'the snapshot was written outside the workspace');
  assert.ok(!existsSync(join(outside, 'github-snapshot.md')));
});

test('context: a linked key file never reaches the prompt', async () => {
  const { ensureCodebaseContext } = await import('../server/services/appstudio/contextBuilder.js');
  const repo = release('ctx');
  const git = (...a) => execFileSync(REAL_GIT, ['-C', repo, ...a], { stdio: 'pipe' });
  git('init', '-q');
  writeFileSync(join(repo, 'server.js'), 'console.log(1)\n');
  writeFileSync(join(repo, 'package.json'), '{"name":"ctx-real-file"}\n');
  symlinkSync(SECRET, join(repo, 'README.md'));
  git('add', '.');
  git('-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'seed');

  await ensureCodebaseContext('rsymctx', repo).catch(() => {});
  const argv = readFileSync(ARGV, 'utf8');
  assert.match(argv, /ctx-real-file/, 'key files never reached the prompt, so this test would prove nothing');
  assert.doesNotMatch(argv, /host-secret-value/, 'a host file was read through a committed link into the prompt');
});

test('helpers: writeFileInside and regularFileInside refuse links', async () => {
  const { writeFileInside, regularFileInside } = await import('../server/utils/paths.js');
  const dir = release('helpers');
  symlinkSync(join(SECRET_DIR, 'new-file'), join(dir, 'dangling'));
  assert.throws(() => writeFileInside(dir, join(dir, 'dangling'), 'x'), /symbolic link/);
  assert.ok(!existsSync(join(SECRET_DIR, 'new-file')));
  symlinkSync(SECRET_DIR, join(dir, 'sub'));
  assert.throws(() => writeFileInside(dir, join(dir, 'sub', 'f'), 'x'), /outside/);
  writeFileInside(dir, join(dir, 'plain'), 'ok');
  assert.equal(readFileSync(join(dir, 'plain'), 'utf8'), 'ok');
  assert.equal(regularFileInside(dir, join(dir, 'plain')), true);
  assert.equal(regularFileInside(dir, join(dir, 'sub', 'icon.png')), false);
});
