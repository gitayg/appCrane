import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Serial: the gate (services/buildGate.js) holds builds and prunes apart inside
// one AppCrane process. Under `npm test` other test files run `docker image
// prune` against the same daemon from their own processes, which no in-process
// gate can see, so this test runs alone (npm run test:serial).

let docker = false;
try { execFileSync('docker', ['info'], { stdio: 'pipe', timeout: 10000 }); docker = true; } catch (_) {}

// The failure this exists for, end to end: a classic-builder build with image
// prunes fired at it the whole time. Without the gate this failed with
// "failed to export layer: NotFound: lease does not exist" (measured).
test('LIVE: a classic build survives image prunes fired at it throughout', { skip: !docker && 'no docker', timeout: 300_000 }, async () => {
  process.env.APPCRANE_DOCKER_BUILDKIT = '0';
  const { buildImage, pruneDanglingImages } = await import('../../server/services/docker.js');
  const ctx = mkdtempSync(join(tmpdir(), 'build-gate-'));
  const lines = ['FROM alpine:3.20', `RUN echo gate-${Date.now()}-${Math.random()} > /a`];
  for (let i = 1; i <= 25; i++) lines.push(`RUN echo ${i} > /f${i}`, `ENV X${i}=${i}`);
  writeFileSync(join(ctx, 'Dockerfile'), lines.join('\n') + '\n');
  const tag = 'appcrane-buildgate-sandbox:live';
  let done = false;
  const build = buildImage({ slug: 'buildgate', env: 'sandbox', contextDir: ctx, commitHash: 'live', appDockerfile: true, tag })
    .finally(() => { done = true; });
  const prunes = (async () => { while (!done) { pruneDanglingImages(); await new Promise((r) => setTimeout(r, 50)); } })();
  try {
    assert.equal(await build, tag);
  } finally {
    await prunes;
    try { execFileSync('docker', ['rmi', '-f', tag], { stdio: 'pipe' }); } catch (_) {}
    rmSync(ctx, { recursive: true, force: true });
    delete process.env.APPCRANE_DOCKER_BUILDKIT;
  }
});
