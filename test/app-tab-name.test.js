import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// A Launch tab opened by slug alone (a direct load or refresh of /launch/<slug>,
// or Catalog's "Open /<slug>/") showed the slug as its title for good. The tab
// host now fills in the app's name from /api/apps.

const src = (f) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'studio-web/src', f), 'utf8');

test('tabs named by their slug get the app name written back', () => {
  const host = src('components/PersistentAppTabs.tsx');
  assert.match(host, /filter\(t => t\.name === t\.slug\)/, 'slug-named tabs are not picked out');
  assert.match(host, /adminApi\.get<[^>]*>\('\/api\/apps'\)/, 'the app list is not fetched');
  assert.match(host, /updateTab\(slug, \{ name: app\.name/, 'the name is never written back to the tab');
});

test('the tab context can update an open tab', () => {
  assert.match(src('components/AppTabsContext.tsx'), /const updateTab = \(slug: string, patch/);
});
