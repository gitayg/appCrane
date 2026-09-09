import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

// v2.66.5. The SPA called `/api/apps/<slug>/logs/<env>`. That route does not
// exist and never did: logs.js is mounted at the bare '/api', so its
// `/:slug/logs/:env` pattern resolves to `/api/<slug>/logs/<env>` — one segment
// higher than every router mounted at '/api/apps'.
//
// Nothing caught it because the failure is indistinguishable from an empty app:
// the drawer's catch renders "Error loading logs", so a 404 URL and a container
// with no output look identical to the operator. Measured against production
// before the fix: /api/apps/<slug>/logs/sandbox → 404 NOT_FOUND, while
// /api/<slug>/logs/sandbox → 200 with the container's real output.
//
// This guards the mount boundary rather than one string: any SPA call shaped
// `/api/apps/<something>/logs|audit` is wrong by construction, because those
// two resources are served by a router that is not mounted under /api/apps.

// fileURLToPath, not .pathname: this repo lives under a directory with a space
// in its name, and .pathname hands back the percent-encoded form.
const SRC = fileURLToPath(new URL('../studio-web/src/', import.meta.url));
const SERVER = fileURLToPath(new URL('../server/', import.meta.url));

function walk(dir) {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? walk(p) : (/\.(ts|tsx)$/.test(p) ? [p] : []);
  });
}

test('logs.js is still mounted at the bare /api, not /api/apps', () => {
  // The premise of the rule below. If someone remounts logsRoutes under
  // /api/apps, this test must fail loudly rather than keep enforcing a
  // path shape that has quietly become wrong.
  const index = readFileSync(join(SERVER, 'index.js'), 'utf8');
  assert.match(index, /app\.use\('\/api',\s*logsRoutes\)/,
    'logsRoutes moved — the SPA path rule below is derived from this mount and must be revisited');
});

test('no SPA call puts /apps/ in front of a logs or audit path', () => {
  const offenders = [];
  for (const file of walk(SRC)) {
    const text = readFileSync(file, 'utf8');
    text.split('\n').forEach((line, i) => {
      if (/^\s*(\/\/|\*)/.test(line)) return;            // prose may cite the wrong URL
      if (/["'`]\/api\/apps\/[^"'`]*\/(logs|audit)\b/.test(line)) {
        offenders.push(`${file.replace(SRC, '')}:${i + 1}  ${line.trim().slice(0, 100)}`);
      }
    });
  }
  assert.deepEqual(offenders, [],
    'these call /api/apps/<slug>/logs|audit, which matches no route — logs.js serves '
    + 'them at /api/<slug>/... because it is mounted at the bare /api');
});
