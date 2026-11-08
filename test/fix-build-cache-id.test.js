import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { createHmac } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';

// The BuildKit cache id is the only thing separating one app's npm cache from
// another's: dockerfileValidator has no rule on --mount, so any app's Dockerfile
// can name any id it can work out. So the id must not be derivable from the slug.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-fix-cache-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { npmCacheId, ensureDockerfile } = await import('../server/services/dockerfileGen.js');
const { deriveSecret } = await import('../server/services/encryption.js');

function installLine(slug) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-fix-cache-rel-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0', scripts: { start: 'node server.js' } }));
    writeFileSync(join(dir, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}');
    ensureDockerfile({ releaseDir: dir, manifest: null, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '', buildkit: true, slug });
    return readFileSync(join(dir, 'Dockerfile'), 'utf8').split('\n').find((l) => l.includes('--mount=type=cache'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('the id is an HMAC under the instance secret, not the slug', () => {
  const id = npmCacheId('victim');
  assert.notEqual(id, 'npm-victim');
  assert.ok(!id.includes('victim'), id);
  assert.match(id, /^npm-[0-9a-f]{32}$/);
  const expected = createHmac('sha256', deriveSecret('npm-build-cache')).update('victim').digest('hex').slice(0, 32);
  assert.equal(id, `npm-${expected}`);
});

test('the id changes with the instance key, stays stable across builds, and differs per slug', () => {
  const before = npmCacheId('victim');
  assert.equal(npmCacheId('victim'), before);
  assert.notEqual(npmCacheId('other'), before);
  const other = createHmac('sha256', deriveSecret('npm-build-cache', 'b'.repeat(64))).update('victim').digest('hex').slice(0, 32);
  assert.notEqual(`npm-${other}`, before);
  assert.equal(npmCacheId(null), null);
});

test('hostile slug text cannot reach the mount options', () => {
  assert.match(npmCacheId('x,target=/root,id=npm-victim sharing=shared'), /^npm-[0-9a-f]{32}$/);
});

test('the generated Dockerfile mounts that id and nothing derived from the slug', () => {
  const line = installLine('victim');
  assert.ok(line, 'no cache mount was generated');
  assert.ok(line.includes(`id=${npmCacheId('victim')},`), line);
  assert.ok(!line.includes('npm-victim'), line);
});
