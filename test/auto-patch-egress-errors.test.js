import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dockerErrorMessage } from '../server/services/autoPatch/egress.js';

test('docker errors shown to owners never carry the command line or host paths', () => {
  const cmd = 'Command failed: docker run --rm -v /var/lib/appcrane/scratch/ap-123:/work node:22-slim npm install';
  const timedOut = Object.assign(new Error(cmd), { killed: true, code: null });
  assert.equal(dockerErrorMessage(timedOut, '', ['run']), 'docker run timed out');
  const exited = Object.assign(new Error(cmd), { killed: false, code: 125 });
  assert.equal(dockerErrorMessage(exited, '', ['network', 'create']), 'docker network exited with code 125');
  const withStderr = dockerErrorMessage(exited, 'Error response from daemon: invalid mount config: /var/lib/appcrane/scratch/ap-123 does not exist', ['run']);
  assert.ok(!withStderr.includes('/var/lib/appcrane'), withStderr);
  assert.ok(withStderr.includes('<path>'), withStderr);
  for (const m of [dockerErrorMessage(timedOut, '', ['run']), dockerErrorMessage(exited, '', ['run'])]) {
    assert.ok(!m.includes('Command failed'), m);
  }
});
