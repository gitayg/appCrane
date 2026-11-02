import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { shippedBundle } from './admin-bundle.js';

// An app tab (/launch/:slug) can be the first page opened. <crane-app-topbar>
// must be registered by code that loads at boot, not by a lazy page chunk: in
// 2.133.0 only the lazy Applications chunk defined it, so an app opened straight
// from the sidebar showed just the slotted Request/Coder buttons, with no name,
// Refresh, Back or fold chevron.

const ASSETS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs/admin-app/assets');

function staticallyLoaded(entry) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f) || !existsSync(join(ASSETS_DIR, f))) continue;
    seen.add(f);
    const src = readFileSync(join(ASSETS_DIR, f), 'utf8');
    for (const m of src.matchAll(/(?:^|[;\n}])\s*import\s*(?:[\w${}\s,*]+from\s*)?["'`]\.\/([\w.-]+\.js)["'`]/g)) queue.push(m[1]);
  }
  return [...seen];
}

test('the admin SPA registers <crane-app-topbar> at boot, not in a lazy page', () => {
  const { entry } = shippedBundle();
  assert.ok(entry, 'index.html names an entry script');
  const boot = staticallyLoaded(entry).map((f) => readFileSync(join(ASSETS_DIR, f), 'utf8')).join('\n');
  assert.match(boot, /customElements\.define\(\s*["'`]crane-app-topbar["'`]/);
});

test('AdminApp imports the element entry eagerly', () => {
  const src = readFileSync(new URL('../studio-web/src/AdminApp.tsx', import.meta.url), 'utf8');
  assert.match(src, /^import '\.\/topbar-element\/entry'/m);
});
