import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Pins each plugin in this repo's marketplace against plugins/releases.json.
//
// plugin.json sets an explicit `version`, and that version is what Claude Code
// compares to decide whether an update exists. So a change to a plugin's files
// that leaves the version alone reaches nobody who already installed it, and
// nothing anywhere goes red: `claude plugin update` just says "latest". This
// test is that red light. It fails when a plugin's files no longer match the
// recorded hash; the generator refuses to re-record a change without a bump.

const { currentReleases, unbumped, RELEASES } = await import('../scripts/gen-plugin-releases.mjs');

test('every plugin change ships with a version bump', () => {
  const recorded = JSON.parse(readFileSync(RELEASES, 'utf8'));
  const current = currentReleases();
  const stuck = unbumped(recorded, current);
  assert.deepEqual(stuck, [], `${stuck.join(', ')} changed without a version bump: bump "version" in its .claude-plugin/plugin.json, then run npm run gen:plugin-releases`);
  for (const [name, c] of Object.entries(current)) {
    assert.ok(recorded[name], `${name} is not recorded: run npm run gen:plugin-releases`);
    assert.equal(recorded[name].hash, c.hash, `${name} was bumped to ${c.version} but not re-recorded: run npm run gen:plugin-releases`);
    assert.equal(recorded[name].version, c.version, `${name}: run npm run gen:plugin-releases`);
  }
});

test('the guard refuses a changed plugin that kept its version, and accepts a bumped one', () => {
  const before = { p: { version: '1.0.0', hash: 'a' } };
  assert.deepEqual(unbumped(before, { p: { version: '1.0.0', hash: 'b' } }), ['p']);
  assert.deepEqual(unbumped(before, { p: { version: '1.0.1', hash: 'b' } }), []);
  assert.deepEqual(unbumped(before, { p: { version: '1.0.0', hash: 'a' } }), []);
});
