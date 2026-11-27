import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Settings > Backup > Settings only (v2.148.0): the dashboard door to
// /api/config/export|import, which refuse API keys since v2.147.0. tsc cannot
// check that the card goes through the step-up fetch, sends the fields the
// route reads, or shows a protected-settings refusal instead of swallowing it.

const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
const card = read('../studio-web/src/components/backup/SettingsSnapshotCard.tsx');
const settings = read('../studio-web/src/pages/Settings.tsx');
const route = read('../server/routes/config.js');
const cli = read('../cli/index.js');

test('the Backup tab renders the settings-only card', () => {
  assert.match(settings, /import \{ SettingsSnapshotCard \} from '\.\.\/components\/backup\/SettingsSnapshotCard'/);
  assert.match(settings, /<SettingsSnapshotCard \/>/);
});

test('export and import go through archiveFetch, so a stale session gets the step-up dialog', () => {
  assert.match(card, /archiveFetch\('\/api\/config\/export'\)/);
  assert.match(card, /archiveFetch\('\/api\/config\/import', \{\s*method: 'POST'/);
  assert.doesNotMatch(card, /adminApi\.(get|post)\('\/api\/config/);
});

test('import sends exactly the fields the route reads', () => {
  for (const field of ['config', 'old_key', 'include_protected']) {
    assert.match(route, new RegExp(`\\b${field}\\b[^\\n]*= req\\.body`), `route no longer reads ${field}`);
  }
  assert.match(card, /JSON\.stringify\(\{ config, old_key: sourceKey\.trim\(\) \|\| undefined, include_protected: includeProtected \}\)/);
});

test('a PROTECTED_SETTINGS refusal lists the keys; errors and one-way keys are shown', () => {
  assert.match(card, /err\.code === PROTECTED && err\.keys\) \{ setRefused\(err\.keys\)/);
  assert.match(card, /const PROTECTED = 'PROTECTED_SETTINGS'/);
  assert.match(card, /result\.errors\.map/);
  assert.match(card, /result\.regenerate\.map/);
});

test('the source key is a masked field and is cleared after a successful import', () => {
  assert.match(card, /<PasswordInput label="source encryption key"/);
  assert.match(card, /setResult\(out\)\s*setSourceKey\(''\)/);
});

test('crane config export/import point at the new section', () => {
  assert.match(cli, /Settings -> Backup & Restore -> Settings only/);
});

test('import messages name what the dashboard asks for, not the retired CLI flag, and count in the singular', () => {
  const migration = read('../server/services/configMigration.js');
  assert.doesNotMatch(migration, /--old-key/);
  assert.match(migration, /encrypted; import again with the source instance's ENCRYPTION_KEY/);
  assert.match(card, /k === 1 \? one : many/);
  assert.doesNotMatch(card, /were skipped/);
});
