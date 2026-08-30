import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Credentials in the query string, only where the browser leaves no choice
// (v2.53.1).
//
// coder.js and agents.js promote `?api_key=` / `?token=` into headers so
// EventSource can authenticate — it cannot set headers, so for SSE there is no
// alternative short of a separate ticket endpoint. That much is forced.
//
// What was not forced: the promotion ran for EVERY route on both routers. A URL
// carrying a live credential is written to the proxy access log, kept in browser
// history, and sent in the Referer of anything the response loads. Applying that
// to `POST /:slug/session/:id/ship` and `POST /:slug/evict` bought nothing —
// those are called with fetch(), which sets headers perfectly well.
//
// So: GET, and only the two SSE endpoints. Everything else must present a
// header. This is asserted against the source rather than a live server because
// the property is about which requests the rule can apply to at all, and a
// route added later is exactly the regression worth catching.

const FILES = {
  'server/routes/coder.js': '/:slug/session/:id/events',
  'server/routes/agents.js': '/:id/events',
};

for (const [file, sseRoute] of Object.entries(FILES)) {
  const src = readFileSync(new URL('../' + file, import.meta.url), 'utf8');

  test(`${file}: query-credential promotion is guarded, not unconditional`, () => {
    const promo = src.match(/if \(req\.query\.api_key[^\n]*\n[^\n]*req\.query\.token[^\n]*/);
    assert.ok(promo, 'the promotion lines moved — re-check this test against the new shape');
    // The guard has to appear BEFORE the promotion, in the same middleware.
    const before = src.slice(0, src.indexOf(promo[0]));
    const guard = before.slice(-600);
    assert.match(guard, /isSseRequest|allowQueryCredentials/,
      'the promotion is unconditional: every route on this router accepts a credential in the URL');
  });

  test(`${file}: the guard admits only GET on the SSE path`, () => {
    assert.match(src, /req\.method === 'GET'/,
      'without a method check, a POST with ?api_key= still authenticates');
    assert.ok(src.includes(sseRoute.replace('/:slug', '').replace('/:id', '')) || src.includes('/events'),
      'the guard must be anchored to the SSE endpoint, not to any path');
  });
}

test('the SSE endpoints are still reachable with a query credential', () => {
  // The point is to narrow the rule, not remove it — EventSource has no other
  // way to authenticate, so deleting the promotion outright would break the
  // live log stream in the Studio UI.
  const src = readFileSync(new URL('../server/routes/coder.js', import.meta.url), 'utf8');
  assert.match(src, /req\.query\.api_key/, 'SSE auth via query must survive');
});
