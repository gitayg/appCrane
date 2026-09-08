import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'events';
import { readFileSync } from 'fs';

// v2.65.4. A Caddy reload must never sit between the work a route did and the
// response that reports it.
//
// reloadCaddy() cycles the proxy the response travels back through, and
// escalates to `systemctl restart caddy` when Caddy's admin API does not answer
// after a reload. A restart destroys every connection Caddy holds, including
// the one carrying this response, so the client sees a socket closed with no
// response bytes and re-sends. The re-send finds the work already done and the
// route answers honestly: 409 DUPLICATE for a slug the caller just created, 404
// NOT_FOUND for an app it just deleted. Measured on a live instance against a
// random slug that had never existed:
//
//   CREATE cadtest-veppu 409 660ms | row exists? true
//   DELETE cadtest-veppu 404 648ms | row exists? false
//
// The operator reading those answers renames and retries, which is how six
// orphaned bookstack..bookstack-6 rows accumulated, each from a request that
// reported a conflict.
//
// Three properties, because there are three ways to reintroduce this: the
// helper could stop deferring, a handler could stop using it, or the reload
// could go back to blocking the event loop for the ~650ms it takes.

process.env.LOG_LEVEL = 'error';

const APPS_SRC = readFileSync(new URL('../server/routes/apps.js', import.meta.url), 'utf8');
const CADDY_SRC = readFileSync(new URL('../server/services/caddy.js', import.meta.url), 'utf8');

// Body of one route registration: from the `router.<method>(` line to the next
// line that starts a new top-level statement. Deliberately not a fixed line
// number — apps.js is edited constantly and a pinned range rots silently into a
// test that reads the wrong function and passes.
function routeBody(src, opener) {
  const start = src.indexOf(opener);
  assert.notEqual(start, -1, `route not found in apps.js: ${opener}`);
  const rest = src.slice(start + opener.length);
  const end = rest.search(/\n(?:router\.|function |export |\/\*\*)/);
  return rest.slice(0, end === -1 ? rest.length : end);
}

test('the helper defers the reload until the response has been sent', async () => {
  const { reloadCaddyAfterResponse } = await import('../server/routes/apps.js');

  const calls = [];
  const fakeReload = async () => { calls.push('reloaded'); return { success: true }; };
  const res = new EventEmitter();

  reloadCaddyAfterResponse(res, 'test', fakeReload);
  assert.deepEqual(calls, [], 'reload ran before the response was finished');

  res.emit('finish');
  await new Promise(r => setImmediate(r));
  assert.deepEqual(calls, ['reloaded'], 'reload never ran after the response finished');
});

test('create and delete do not await a Caddy reload before responding', () => {
  for (const [label, opener] of [
    ['create', "router.post('/', "],
    ['delete', "router.delete('/:slug', "],
  ]) {
    const body = routeBody(APPS_SRC, opener);
    assert.ok(
      !/await\s+reloadCaddy\s*\(/.test(body),
      `${label} awaits reloadCaddy before its response — the response can be lost to a Caddy restart`,
    );
    assert.ok(
      /reloadCaddyAfterResponse\(res,/.test(body),
      `${label} does not schedule its Caddy reload for after the response`,
    );
  }
});

test('reloadCaddy does not block the event loop', () => {
  const code = CADDY_SRC.split('\n')
    .filter(l => !/^\s*(\*|\/\/|\/\*)/.test(l))
    .join('\n');
  assert.ok(
    !/execFileSync\s*\(/.test(code),
    'caddy.js calls execFileSync — systemctl reload/restart takes ~650ms and stops '
    + "Node's only thread for all of it, including the health checks",
  );
});
