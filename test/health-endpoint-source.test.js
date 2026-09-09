import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

// v2.67.1. AppCrane had two sources of truth for an app's health path:
//
//   apps.health_path          — written by the catalogue and the Deploy dialog,
//                               validated against by deployer.js at deploy time
//   health_configs.endpoint   — default '/api/health' (migration 001), and the
//                               only thing the continuous monitor ever read
//
// Setting one did not touch the other, so an app could deploy green and then sit
// permanently red. Measured on BookStack in production: the deploy probe
// validated /status and passed, the monitor kept probing /api/health, got a fast
// 404 (response_ms 47) and marked BOTH environments down while the app served
// pages normally. The operator had set the field; it was not the field in use.

const SRC = fileURLToPath(new URL('../server/services/healthChecker.js', import.meta.url));
const CHECKER = readFileSync(SRC, 'utf8');

// The real function, lifted from source rather than re-implemented — a
// re-implementation would pass while the shipped one regressed.
const body = CHECKER.slice(
  CHECKER.indexOf('function effectiveEndpoint(config)'),
  CHECKER.indexOf('async function probeHttp'),
);
assert.ok(body.includes('DEFAULT_ENDPOINT'), 'could not locate effectiveEndpoint in healthChecker.js');
const effectiveEndpoint = new Function(`${body}; return effectiveEndpoint;`)();

test('a default endpoint defers to the app health_path', () => {
  assert.equal(
    effectiveEndpoint({ endpoint: '/api/health', health_path: '/status' }), '/status',
    'a catalogue app must be monitored at the path it was installed with',
  );
});

test('an operator override wins over health_path', () => {
  // routes/health.js lets an operator set this deliberately. Deferring to
  // health_path there would silently discard their choice.
  assert.equal(
    effectiveEndpoint({ endpoint: '/healthz', health_path: '/status' }), '/healthz',
  );
});

test('an app with no health_path keeps the default', () => {
  for (const hp of [null, undefined, '']) {
    assert.equal(
      effectiveEndpoint({ endpoint: '/api/health', health_path: hp }), '/api/health',
      'an app AppCrane built still owes /api/health',
    );
  }
});

test('the monitor actually queries health_path and uses the resolver', () => {
  // The resolver is worth nothing if the column is never selected, or if the
  // probe target still interpolates config.endpoint directly. Both were true
  // before this change, and either alone reinstates the bug.
  const selects = CHECKER.match(/SELECT hc\.\*[^`]*?FROM health_configs/g) || [];
  assert.ok(selects.length >= 2, `expected both config queries, found ${selects.length}`);
  for (const s of selects) {
    assert.match(s, /a\.health_path/,
      'a health_configs query does not select a.health_path, so the resolver sees undefined');
  }
  assert.match(CHECKER, /\$\{effectiveEndpoint\(config\)\}/,
    'the probe target must go through effectiveEndpoint, not config.endpoint');
});
