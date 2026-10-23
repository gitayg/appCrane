import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/index.js'), 'utf8');

test('auto-heal redeploys the live commit and skips the release check by option, not by log text', () => {
  const heal = src.slice(src.indexOf("'auto-heal: live deploy had no running container'"));
  const call = heal.slice(0, heal.indexOf('.catch('));
  assert.match(call, /liveCommit \? \{ releaseCheck: 'skip', targetCommit: liveCommit \} : \{\}/, 'the check is skipped only when the rebuild is pinned to the commit that was live; otherwise it runs');
  assert.match(src, /d\.commit_sha AS live_commit_sha, d\.commit_hash AS live_commit_hash/);
});

test('the bulk redeploy also skips the release check by option', () => {
  const bulk = src.slice(src.indexOf("'auto-queued after PM2 cleanup'"));
  const call = bulk.slice(0, bulk.indexOf('.catch('));
  assert.match(call, /liveCommit \? \{ releaseCheck: 'skip', targetCommit: liveCommit \} : \{\}/, 'the bulk redeploy also skips only when pinned to the live commit');
});
