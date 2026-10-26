import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';

// Opt-in (RUNTIME_PATCH_LIVE=1, needs Docker and Docker Hub): a tiny PHP app
// with no Dockerfile, built by the real generator and the real docker.js on
// php:8.3-apache with a fresh pull, runs PHP 8.3.36 or later (the PHP2Shell
// fix), and its image records the base and digest it was built on.

const LIVE = process.env.RUNTIME_PATCH_LIVE === '1';

test('live: generated PHP app on a freshly pulled php:8.3-apache runs a PHP2Shell-fixed PHP', { skip: !LIVE && 'set RUNTIME_PATCH_LIVE=1 to build for real' }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'crane-runtime-live-'));
  process.env.DATA_DIR = join(root, 'data');
  process.env.ENCRYPTION_KEY = 'f'.repeat(64);
  process.env.LOG_LEVEL = 'error';
  const { initDb } = await import('../server/db.js');
  initDb();
  const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
  const docker = await import('../server/services/docker.js');
  const { imageRuntimeVersion } = await import('../server/services/autoPatch/runtimeInspect.js');
  const { compareVersions } = await import('../server/services/autoPatch/runtimeAdvisories.js');

  const rel = join(root, 'release');
  execFileSync('mkdir', ['-p', rel]);
  writeFileSync(join(rel, 'composer.json'), JSON.stringify({ name: 'acme/hello', require: { php: '~8.3.0' } }));
  writeFileSync(join(rel, 'index.php'), '<?php echo PHP_VERSION;');
  const gen = ensureDockerfile({ releaseDir: rel, manifest: null, appBasePath: '/hello/' });
  assert.equal(gen.runtime, 'php');
  assert.match(readFileSync(join(rel, 'Dockerfile'), 'utf8'), /^FROM php:8\.3-apache/m);

  const lines = [];
  const tag = await docker.buildImageIfNeeded({ slug: 'rtlive', env: 'sandbox', contextDir: rel, commitHash: `t${Date.now()}`, appBasePath: '/hello/', onLog: (l) => lines.push(l) });
  try {
    console.log(lines.filter((l) => /Pulled|Could not pull/.test(l)).join('\n'));
    assert.ok(lines.some((l) => l === 'Pulled the latest php:8.3-apache'), lines.slice(0, 5).join('\n'));
    const base = await docker.imageBaseInfo(tag);
    console.log('base', JSON.stringify(base));
    assert.equal(base.image, 'php:8.3-apache');
    assert.match(base.digest, /^sha256:[0-9a-f]{64}$/);
    const envVersion = await imageRuntimeVersion(tag, 'php');
    const inside = execFileSync('docker', ['run', '--rm', '--pull', 'never', '--entrypoint', 'php', tag, '-r', 'echo PHP_VERSION;'], { encoding: 'utf8' }).trim();
    console.log('PHP_VERSION env', envVersion, 'php -r', inside);
    assert.equal(inside, envVersion);
    assert.ok(compareVersions(inside, '8.3.36') >= 0, inside);
  } finally {
    execFileSync('docker', ['rmi', tag]);
  }
});
