import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * BuildKit needs the buildx CLI plugin, and it is not part of every Docker
 * install — Ubuntu's `docker.io` package ships the daemon without it. Forcing
 * DOCKER_BUILDKIT=1 there fails EVERY build. Measured on Ubuntu 26.04 /
 * Docker 29.1.3 before this fix:
 *
 *     ERROR: BuildKit is enabled but the buildx component is missing or broken.
 *     DEPLOY FAILED: docker build failed
 *
 * The error named Docker's install docs and not APPCRANE_DOCKER_BUILDKIT, so
 * the platform simply could not deploy and the message did not say why.
 */
const ROOT = mkdtempSync(join(tmpdir(), 'crane-buildx-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const BIN = join(ROOT, 'bin');
mkdirSync(BIN, { recursive: true });
const ORIGINAL_PATH = process.env.PATH;

/** Put a fake `docker` on PATH whose `buildx version` succeeds or fails. */
function fakeDocker({ buildx }) {
  writeFileSync(join(BIN, 'docker'), `#!/bin/sh
if [ "$1" = "buildx" ]; then ${buildx ? 'echo "github.com/docker/buildx v0.30.1"; exit 0' : 'echo "docker: \'buildx\' is not a docker command." >&2; exit 1'}; fi
exit 0
`, { mode: 0o755 });
  chmodSync(join(BIN, 'docker'), 0o755);
  process.env.PATH = `${BIN}:${ORIGINAL_PATH}`;
}

const { dockerBuildEnv, hasBuildx, resetBuildxProbe } = await import('../server/services/docker.js');

beforeEach(() => {
  delete process.env.APPCRANE_DOCKER_BUILDKIT;
  resetBuildxProbe();
});

test('buildx present → BuildKit on', () => {
  fakeDocker({ buildx: true });
  assert.equal(hasBuildx(), true);
  assert.equal(dockerBuildEnv().DOCKER_BUILDKIT, '1');
});

test('buildx MISSING → classic builder, not a failed build', () => {
  fakeDocker({ buildx: false });
  assert.equal(hasBuildx(), false);
  assert.equal(
    dockerBuildEnv().DOCKER_BUILDKIT, '0',
    'BuildKit was forced on a host with no buildx — every deploy fails at the build step',
  );
});

test('an explicit override wins in both directions', () => {
  // An operator who pins '1' on a box without buildx gets the failure they
  // asked for; one who pins '0' on a box with buildx is not overruled either.
  fakeDocker({ buildx: false });
  process.env.APPCRANE_DOCKER_BUILDKIT = '1';
  assert.equal(dockerBuildEnv().DOCKER_BUILDKIT, '1');

  resetBuildxProbe();
  fakeDocker({ buildx: true });
  process.env.APPCRANE_DOCKER_BUILDKIT = '0';
  assert.equal(dockerBuildEnv().DOCKER_BUILDKIT, '0');
});

test('the probe runs once, not per build', () => {
  fakeDocker({ buildx: false });
  hasBuildx();
  // Swap in a docker whose buildx WOULD succeed; the cached answer must hold.
  fakeDocker({ buildx: true });
  assert.equal(hasBuildx(), false, 'the buildx probe re-runs on every build — one exec per deploy for a fixed fact');
});
