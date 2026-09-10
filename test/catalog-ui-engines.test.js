import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The Catalog dialog must offer every engine the platform can provision.
//
// This drift is invisible from the server, which is why it needs a test rather
// than a convention. managedDb.js gained 'redis' and then 'mongo'; both worked
// over the HTTP API and over MCP the moment they landed. But
// studio-web/src/pages/Catalog.tsx kept its own private
// `DbEngine = 'postgres' | 'mariadb'`, so canonicalEngine() returned null for
// both, the entry fell through to "the manifest named something else", and the
// install dialog silently declined to offer provisioning.
//
// The result was the worst-shaped bug available: rocketchat, opensign and wekan
// installed from the UI with NO DATABASE, started, and failed — looking exactly
// like three broken apps rather than one missing branch in a type union. Every
// server-side test passed the whole time.
//
// Asserted against the SOURCE rather than a duplicated list, because a
// hand-copied list here would be the same failure one file further along.

const ROOT = new URL('../', import.meta.url);
const catalogTsx = readFileSync(new URL('studio-web/src/pages/Catalog.tsx', ROOT), 'utf8');
const managedDb = readFileSync(new URL('server/services/managedDb.js', ROOT), 'utf8');

/** The engines the server will actually provision. */
function supportedEngines() {
  const m = /export const SUPPORTED_ENGINES = \[([^\]]*)\]/.exec(managedDb);
  assert.ok(m, 'SUPPORTED_ENGINES not found in managedDb.js — this test cannot verify anything');
  return [...m[1].matchAll(/'([a-z0-9_-]+)'/g)].map((x) => x[1]);
}

/** The engine tokens the dialog's own type union admits. */
function uiEngines() {
  const m = /type DbEngine = ([^\n]+)/.exec(catalogTsx);
  assert.ok(m, 'the DbEngine union was renamed or removed — update this test deliberately');
  return [...m[1].matchAll(/'([a-z0-9_-]+)'/g)].map((x) => x[1]);
}

test('every engine the server provisions is in the UI type union', () => {
  const server = supportedEngines();
  const ui = uiEngines();
  assert.ok(server.length >= 2, `parsed only ${server.length} engines from managedDb.js`);

  const missing = server.filter((e) => !ui.includes(e));
  assert.deepEqual(missing, [],
    `the Catalog dialog cannot offer ${missing.join(', ')}. An app whose manifest asks for one ` +
    'installs with no database and fails as if the app were broken, while every server-side ' +
    'test stays green. Widen DbEngine in studio-web/src/pages/Catalog.tsx.');
});

test('canonicalEngine maps each supported engine to itself', () => {
  // The union alone is not enough: canonicalEngine() is what actually decides,
  // and a token in the type with no branch in the function returns null and
  // fails exactly as before.
  const fn = /function canonicalEngine\(raw: string\): DbEngine \| null \{([\s\S]*?)\n\}/.exec(catalogTsx);
  assert.ok(fn, 'canonicalEngine was renamed or restructured — update this test deliberately');

  for (const engine of supportedEngines()) {
    assert.match(fn[1], new RegExp(`return '${engine}'`),
      `canonicalEngine has no branch returning '${engine}', so the dialog resolves it to null`);
  }
});

test('every engine in the union has a label and a default port', () => {
  // ENGINE_LABEL and ENGINE_PORT are Record<DbEngine, ...>, so TypeScript
  // catches a missing key at build time -- but only if the build runs. This
  // states it as a test so the suite catches it too.
  for (const engine of uiEngines()) {
    assert.match(catalogTsx, new RegExp(`ENGINE_LABEL[\\s\\S]{0,200}?\\b${engine}:`),
      `${engine} is in DbEngine but has no ENGINE_LABEL entry`);
    assert.match(catalogTsx, new RegExp(`ENGINE_PORT[\\s\\S]{0,200}?\\b${engine}:`),
      `${engine} is in DbEngine but has no ENGINE_PORT entry`);
  }
});
