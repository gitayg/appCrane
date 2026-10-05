import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// `docker diff` gets a minute, not ten seconds (v2.94.1).
//
// On crane.glick.run (Docker 29, containerd snapshotter, 23 containers) it took
// 4-10 s on containers with ZERO changed paths. At a 10 s limit the slow runs
// were killed and every redeploy of a clean app asked for a data-loss
// acknowledgement. A fake `docker` on PATH reproduces the slow-but-clean case.

const bin = mkdtempSync(join(tmpdir(), 'crane-fakedocker-'));
const fake = join(bin, 'docker');
writeFileSync(fake, `#!/bin/sh
case "$1" in
  inspect) case "$4" in *Volumes*) echo null ;; *) echo '[]' ;; esac ;;
  diff) sleep "\${FAKE_DIFF_SECONDS:-0}" ;;
esac
`);
chmodSync(fake, 0o755);
const realPath = process.env.PATH;
process.env.PATH = `${bin}:${realPath}`;
after(() => { process.env.PATH = realPath; });

const { inspectContainerState } = await import('../server/services/redeployRisk.js');

test('a clean container whose diff takes 11 s is read as clean, not unknown', async () => {
  process.env.FAKE_DIFF_SECONDS = '11';
  const state = await inspectContainerState('appcrane-slow-production');
  assert.equal(state.present, true);
  assert.equal(state.diffError, undefined, `diff was abandoned: ${state.diffError}`);
  assert.deepEqual(state.diff, []);
});

test('a diff that really does not finish says it timed out, not "Command failed"', async () => {
  process.env.FAKE_DIFF_SECONDS = '5';
  const state = await inspectContainerState('appcrane-stuck-production', { diffTimeoutMs: 1000 });
  assert.equal(state.diffError, 'docker diff did not finish within 1 s');
});
