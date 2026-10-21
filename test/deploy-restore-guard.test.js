import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');

test('every deploy path refuses while a restore of that app+env is running, inside the failure-handling try', () => {
  const fn = src.slice(src.indexOf('export async function deployApp('));
  const tryAt = fn.indexOf('  try {\n');
  const guardAt = fn.indexOf('assertNoRestoreInProgress(app.slug, env);');
  const admitAt = fn.indexOf('await admitAppStart(');
  assert.ok(guardAt > 0, 'deployApp does not check for a running restore');
  assert.ok(tryAt > 0 && guardAt > tryAt, 'the restore check is outside the try, so a refusal would not be recorded as a failed deploy');
  assert.ok(guardAt < admitAt, 'the restore check runs after work has started');
});
