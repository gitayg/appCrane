import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { slugRefusal, PLATFORM_PATHS } from '../server/utils/slugPolicy.js';

// Security audit 2026-10-09, H4. An app is routed by `handle /<slug>*` and the
// platform is Caddy's catch-all, which Caddy sorts last; an app named `a` took
// every /api/... request, one named `login` the sign-in page.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

test('slugs that would capture a platform path are refused', () => {
  for (const s of ['a', 'ap', 'api', 'l', 'login', 'mcp', 'm', 'd', 'docs', 'favicon', 'public']) {
    assert.ok(slugRefusal(s), `'${s}' is allowed but /${s}* captures a platform path`);
  }
});

test('ordinary slugs, including ones that merely start like a platform path, are allowed', () => {
  for (const s of ['voc', 'odoo', 'apiary', 'logins-demo', 'my-app', 'crm2']) {
    assert.equal(slugRefusal(s), null, `'${s}' was refused`);
  }
});

test('a slug that is another app\'s sandbox path is refused', () => {
  assert.ok(slugRefusal('voc-sandbox'));
});

test('every top-level path server/index.js mounts is in PLATFORM_PATHS', () => {
  const src = readFileSync(join(ROOT, 'server/index.js'), 'utf8');
  const mounted = new Set([...src.matchAll(/app\.(?:use|get|post|all)\(\s*['"`]\/([A-Za-z0-9_-][A-Za-z0-9_.-]*)/g)].map(m => m[1]));
  const missing = [...mounted].filter(p => !PLATFORM_PATHS.includes(p));
  assert.deepEqual(missing, [], `platform paths an app slug could capture: ${missing.join(', ')}`);
});

test('every place that names an app uses the policy', () => {
  for (const f of ['server/routes/apps.js', 'server/services/appRename.js']) {
    assert.match(readFileSync(join(ROOT, f), 'utf8'), /slugRefusal\((slug|newSlug)\)/, `${f} skips the slug policy`);
  }
  const mcp = readFileSync(join(ROOT, 'server/services/mcpTools.js'), 'utf8');
  assert.equal((mcp.match(/slugRefusal\(slug\)/g) || []).length, 2, 'an MCP create tool skips the slug policy');
});
