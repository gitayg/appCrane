import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/index.js'), 'utf8');

test('auto-heal (services/containerRecovery.js) skips the release check only for the live release, by option', async () => {
  assert.doesNotMatch(src, /'auto-heal: live deploy had no running container'/, 'the boot-only auto-heal moved out of index.js');
  const { restorePlan } = await import('../server/services/containerRecovery.js');
  const live = { live_id: 7, commit_hash: 'abc1234', release_path: '/r/1', tree_sha256: 't', source_type: 'github' };
  const plans = [
    restorePlan(live, { fileExists: () => true }),
    restorePlan({ ...live, commit_sha: 'deadbeef1234' }, { fileExists: () => false }),
    restorePlan({ ...live, commit_hash: 'unknown' }, { fileExists: () => false }),
    restorePlan({ ...live, source_type: 'image', image_ref: 'r.example.test/x@sha256:00' }),
  ];
  for (const p of plans) {
    if (p.error) continue;
    assert.equal(p.opts.releaseCheck, 'skip');
    assert.ok(p.opts.preExtractedDir || p.opts.imageRef || p.opts.targetCommit, 'skipped only when pinned to what was live');
  }
  assert.ok(plans[2].error, 'no release dir and no commit: refused rather than deploying the branch head unchecked');
});

test('the bulk redeploy also skips the release check by option', () => {
  const bulk = src.slice(src.indexOf("'auto-queued after PM2 cleanup'"));
  const call = bulk.slice(0, bulk.indexOf('.catch('));
  assert.match(call, /liveCommit \? \{ releaseCheck: 'skip', targetCommit: liveCommit \} : \{\}/, 'the bulk redeploy also skips only when pinned to the live commit');
});
