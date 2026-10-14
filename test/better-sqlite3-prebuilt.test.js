import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// better-sqlite3 13.x publishes no prebuilt binaries, so `npm install` falls
// back to compiling it with node-gyp. On a server without a C++ toolchain that
// fails, and AppCrane's self-update stops at `npm install` (apphub, v2.107.1:
// "npm error command sh -c node-gyp rebuild"). 12.11.1 ships linux-x64
// binaries for Node 22 (ABI 127). Bump the major only once the new major's
// GitHub releases carry prebuilt assets for the Node versions AppCrane supports.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

test('better-sqlite3 stays on a major that ships prebuilt binaries', () => {
  const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'));
  const v = lock.packages['node_modules/better-sqlite3']?.version;
  assert.ok(v, 'better-sqlite3 is not in package-lock.json');
  assert.equal(v.split('.')[0], '12', `better-sqlite3 ${v} has no prebuilt binaries; self-update would compile it on the server`);
});

test('Dependabot does not bump better-sqlite3 to a new major', () => {
  const dep = readFileSync(join(ROOT, '.github/dependabot.yml'), 'utf8');
  assert.match(dep, /dependency-name: better-sqlite3\s+update-types: \["version-update:semver-major"\]/);
});
