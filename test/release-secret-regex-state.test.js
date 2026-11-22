import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const { scanTreeForSecrets, secretMatches } = await import('../server/services/releaseSecretScan.js');
const LEAK = 'sk_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4';

test('a tree secret scan earlier in the run does not blind the served-output matcher', () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-regex-state-'));
  try {
    const text = `x = "${LEAK}"`;
    writeFileSync(join(dir, 'a.js'), `${' '.repeat(40)}${text}`);
    scanTreeForSecrets(dir);
    assert.equal(secretMatches(text).length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
