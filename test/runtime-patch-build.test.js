import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, mkdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// docker.js builds on a freshly pulled base, falls back to the cached copy
// with a warning when the pull fails, and labels the image with the base it
// was built on. Docker is a PATH shim that records every call.

const root = mkdtempSync(join(tmpdir(), 'crane-runtime-build-'));
process.env.DATA_DIR = join(root, 'data');
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_DOCKER_BUILDKIT = '1';
const bin = join(root, 'bin');
mkdirSync(bin);
const LOG = join(root, 'docker.log');
process.env.FAKE_DOCKER_LOG = LOG;
const DIGEST = `sha256:${'1b'.repeat(32)}`;
writeFileSync(join(bin, 'docker'), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  pull) if [ "$FAKE_PULL_FAIL" = 1 ]; then echo 'Error response from daemon: failed to resolve reference "php:8.3-apache": dial tcp: i/o timeout' >&2; exit 1; fi; echo "docker.io/library/php:8.3-apache"; exit 0 ;;
  image)
    case "$*" in
      *RepoDigests*) echo '["php@${DIGEST}"]'; exit 0 ;;
      *) exit 1 ;;
    esac ;;
  build)
    for a in "$@"; do if [ "$a" = "--pull" ] && [ "$FAKE_BUILD_PULL_FAIL" = 1 ]; then echo 'ERROR: failed to solve: failed to resolve source metadata for docker.io/library/x' >&2; exit 1; fi; done
    exit 0 ;;
esac
exit 0
`);
chmodSync(join(bin, 'docker'), 0o755);
process.env.PATH = `${bin}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const docker = await import('../server/services/docker.js');

const ctx = join(root, 'ctx');
mkdirSync(ctx);
const calls = () => readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean);
const builds = () => calls().filter((c) => c.startsWith('build '));
const pulls = () => calls().filter((c) => c.startsWith('pull '));

beforeEach(() => {
  rmSync(LOG, { force: true });
  writeFileSync(LOG, '');
  delete process.env.FAKE_PULL_FAIL;
  delete process.env.FAKE_BUILD_PULL_FAIL;
  db.prepare("DELETE FROM settings WHERE key = 'pull_base_images_app_dockerfiles'").run();
});

function build(dockerfile, opts = {}) {
  writeFileSync(join(ctx, 'Dockerfile'), dockerfile);
  const lines = [];
  return docker.buildImageIfNeeded({ slug: 'web', env: 'sandbox', contextDir: ctx, commitHash: 'abc1234', onLog: (l) => lines.push(l), ...opts })
    .then((tag) => ({ tag, lines }));
}

test('generated Dockerfile: the base is pulled before the build, and the image is labelled with base and digest', async () => {
  const { tag, lines } = await build('FROM php:8.3-apache\nRUN true\n');
  assert.equal(tag, 'appcrane-web-sandbox:abc1234');
  assert.deepEqual(pulls(), ['pull --quiet php:8.3-apache']);
  const order = calls().map((c) => c.split(' ')[0]);
  assert.ok(order.indexOf('pull') < order.indexOf('build'), order.join(','));
  const b = builds();
  assert.equal(b.length, 1);
  assert.match(b[0], /--label appcrane\.base\.image=php:8\.3-apache/);
  assert.match(b[0], new RegExp(`--label appcrane\\.base\\.digest=${DIGEST}`));
  assert.doesNotMatch(b[0], /--pull/, 'a literal base was already pulled; the build uses the local copy');
  assert.ok(lines.some((l) => /Pulled the latest php:8\.3-apache/.test(l)));
});

test('pull fails (offline, rate limited): the build still runs on the cached copy, with a warning in the deploy log', async () => {
  process.env.FAKE_PULL_FAIL = '1';
  const { tag, lines } = await build('FROM php:8.3-apache\n');
  assert.equal(tag, 'appcrane-web-sandbox:abc1234');
  assert.equal(builds().length, 1);
  const w = lines.find((l) => l.startsWith('⚠ Could not pull a fresh php:8.3-apache'));
  assert.ok(w, lines.join('\n'));
  assert.match(w, /i\/o timeout/);
  assert.match(w, /building on the copy already on this host/);
});

test('app Dockerfile: pulled by default; not pulled when the platform setting is off', async () => {
  await build('FROM node:22-alpine AS b\nRUN true\nFROM b\n', { appDockerfile: true });
  assert.deepEqual(pulls(), ['pull --quiet node:22-alpine']);
  assert.match(builds()[0], /appcrane\.base\.image=node:22-alpine/);
  writeFileSync(LOG, '');
  db.prepare("INSERT INTO settings (key, value) VALUES ('pull_base_images_app_dockerfiles', 'false')").run();
  const { lines } = await build('FROM node:22-alpine\n', { appDockerfile: true });
  assert.deepEqual(pulls(), []);
  assert.ok(lines.some((l) => /pulling bases for app Dockerfiles is turned off/.test(l)));
  writeFileSync(LOG, '');
  await build('FROM node:22-alpine\n', { appDockerfile: false });
  assert.deepEqual(pulls(), ['pull --quiet node:22-alpine'], 'the setting never stops pulls for generated Dockerfiles');
});

test('a FROM with an ARG cannot be pre-pulled: the build runs with --pull, and once more without it when the pull fails', async () => {
  const { lines } = await build('ARG V=8.3\nFROM php:${V}-apache\n', { appDockerfile: true });
  assert.equal(builds().length, 1);
  assert.match(builds()[0], /^build --pull /);
  writeFileSync(LOG, '');
  process.env.FAKE_BUILD_PULL_FAIL = '1';
  const r = await build('ARG V=8.3\nFROM php:${V}-apache\n', { appDockerfile: true });
  assert.equal(builds().length, 2);
  assert.match(builds()[0], /^build --pull /);
  assert.doesNotMatch(builds()[1], /--pull/);
  assert.ok(r.lines.some((l) => /building again on the copies already on this host/.test(l)), r.lines.join('\n'));
  assert.equal(lines.filter((l) => /⚠/.test(l)).length, 0);
});

test('freshBase: never reuses the cached image and builds under its own tag, so the image it replaces keeps its tag', async () => {
  const { tag } = await build('FROM php:8.3-apache\n', { freshBase: true });
  assert.match(tag, /^appcrane-web-sandbox:abc1234-rt[0-9a-z]+$/);
  assert.equal(calls().filter((c) => /--format \{\{\.Id\}\}/.test(c)).length, 0, 'no cache lookup');
  assert.match(builds()[0], new RegExp(`-t ${tag.replace(/[.]/g, '\\.')} `));
});
