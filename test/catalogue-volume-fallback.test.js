import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

import { declaredVolumePathsFor } from '../server/services/containerRuntimeSpec.js';

// Where an app's persisted paths come from.
//
// 23 catalogue entries were measured against their own images and given
// volume_paths. For a while that field was INERT: deployer.js read only
// apps.volume_paths, the install path never copied the entry's value, and
// nothing anywhere read entry.volume_paths. Every measured declaration changed
// nothing, and no test failed, because each half was individually correct.
//
// The fallback also has to fix apps that ALREADY EXIST. An app installed before
// its entry declared anything carries NULL forever; if NULL meant "no volumes",
// every existing bookstack would keep losing /config on every redeploy — which
// is the problem the declarations were measured for in the first place. So the
// entry applies whenever the row has not decided.
//
// The row is deliberately NOT populated at install. This repo has a history of
// two-sources-of-truth bugs (apps.health_path vs health_configs.endpoint,
// memory_mb vs HostConfig.Memory, X-AppCrane-App-Role vs -App-Roles), and
// copying would add another: an entry corrected later would not reach apps
// already installed from the old value.

const entry = (paths) => (paths === undefined ? undefined : { volume_paths: paths });

test('a row that has not decided inherits the catalogue entry', () => {
  assert.deepEqual(
    declaredVolumePathsFor({ app: { volume_paths: null }, entry: entry(['/config']) }),
    ['/config'],
    'NULL means nobody decided — an app installed before its entry declared paths must still get them',
  );
});

test('an EMPTY ARRAY on the row is a decision and beats the entry', () => {
  // The reason this checks null rather than falsiness. `[] || entry` would
  // silently re-add paths an operator deliberately removed, every deploy,
  // with no way to opt out.
  assert.deepEqual(
    declaredVolumePathsFor({ app: { volume_paths: '[]' }, entry: entry(['/config']) }),
    [],
    'an operator saying "this app persists nothing" must win',
  );
});

test('an explicit row value overrides the entry', () => {
  assert.deepEqual(
    declaredVolumePathsFor({ app: { volume_paths: '["/srv/custom"]' }, entry: entry(['/config']) }),
    ['/srv/custom'],
  );
});

test('no entry and no row value is simply no declared paths', () => {
  assert.deepEqual(declaredVolumePathsFor({ app: { volume_paths: null }, entry: undefined }), []);
  assert.deepEqual(declaredVolumePathsFor({ app: {}, entry: null }), []);
});

test('an entry carrying an invalid path degrades instead of failing the deploy', () => {
  // parseVolumePaths swallows a bad value by design: a malformed catalogue
  // entry must not make an app undeployable. /data is added unconditionally by
  // resolveVolumeMounts, so degrading here is "the old behaviour", not "no
  // mounts at all".
  assert.deepEqual(declaredVolumePathsFor({ app: { volume_paths: null }, entry: entry(['/config:ro']) }), []);
  assert.deepEqual(declaredVolumePathsFor({ app: { volume_paths: null }, entry: entry(['../escape']) }), []);
});

test('the deploy path actually consults the catalogue entry', () => {
  // The inert-field bug was invisible precisely because both halves were fine
  // on their own. This asserts the wiring: deployApp must pass the ENTRY in,
  // not just the row.
  const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  assert.match(src, /declaredVolumePathsFor\(\{\s*app,\s*entry:\s*findEntry\(app\.catalog_slug\)\s*\}\)/,
    'deployApp must resolve declared paths through the entry, or every catalogue declaration is inert again');
});

test('the catalogue actually carries declarations for the fallback to find', () => {
  // Guards the other half: the rule above is worthless if no entry declares
  // anything. Measured at 23 entries; asserted as a floor so a merge that
  // drops the field is caught.
  const raw = JSON.parse(readFileSync(new URL('../server/services/appCatalog.json', import.meta.url), 'utf8'));
  const list = Array.isArray(raw) ? raw : (raw.apps || Object.values(raw).find(Array.isArray));
  const declaring = list.filter((a) => Array.isArray(a.volume_paths) && a.volume_paths.length > 0);
  assert.ok(declaring.length >= 20,
    `only ${declaring.length} catalogue entries declare volume_paths; 23 were measured`);

  // Every declared path must survive the validator the deploy path will run.
  for (const a of declaring) {
    assert.deepEqual(
      declaredVolumePathsFor({ app: { volume_paths: null }, entry: a }),
      a.volume_paths,
      `${a.slug} declares a path the validator rejects, so it silently degrades to none`,
    );
  }
});
