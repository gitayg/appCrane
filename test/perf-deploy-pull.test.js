import { test } from 'node:test';
import assert from 'node:assert/strict';

import { prepareBuildBase } from '../server/services/autoPatch/runtimeImages.js';

const dockerfile = [
  'FROM a:1 AS one', 'FROM b:1 AS two', 'FROM c:1 AS three', 'FROM d:1 AS four', 'FROM e:1',
].join('\n');

test('base images are pulled in parallel, at most 3 at a time, warnings in FROM order', async () => {
  let inFlight = 0;
  let peak = 0;
  const run = async (args) => {
    if (args[0] !== 'pull') return '[]';
    inFlight++;
    peak = Math.max(peak, inFlight);
    const ref = args[2];
    await new Promise((r) => setTimeout(r, ref === 'a:1' ? 120 : 40));
    inFlight--;
    if (ref === 'a:1' || ref === 'd:1') throw new Error(`pull failed\nno route for ${ref}`);
    return '';
  };
  const t0 = Date.now();
  const r = await prepareBuildBase({ contextDir: '/nonexistent', dockerfileText: dockerfile, run });
  const took = Date.now() - t0;
  assert.equal(peak, 3);
  assert.ok(took < 200, `took ${took} ms (serial would be ~280 ms)`);
  assert.equal(r.warnings.length, 2);
  assert.match(r.warnings[0], /a:1 \(no route for a:1\)/);
  assert.match(r.warnings[1], /d:1 \(no route for d:1\)/);
});
