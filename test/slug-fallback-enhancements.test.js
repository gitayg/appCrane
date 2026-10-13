import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// An app's in-page "send feedback" button POSTs /api/enhancements. The slug
// fallback 307s any root-path request whose Referer is an app page into that
// app, unless the path is on APPCRANE_PASSTHROUGH; /api/enhancements was not,
// so the request landed on the app's own server and came back 404.

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/index.js'), 'utf8');
const list = JSON.parse(src.match(/const APPCRANE_PASSTHROUGH = (\[[^\]]*\])/)[1].replace(/'/g, '"'));
const passes = (path) => list.some(p => path === p || path.startsWith(p + '/'));

test('request submission from inside an app page reaches AppCrane, not the app', () => {
  assert.ok(passes('/api/enhancements'), '/api/enhancements is redirected into the app');
  assert.ok(passes('/api/enhancements/42/status'));
});

test('the platform endpoints apps already call still pass through', () => {
  for (const p of ['/api/me', '/api/notices', '/api/mcp']) assert.ok(passes(p), p);
});
