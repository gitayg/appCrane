import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveHealthProbe,
  DEFAULT_HEALTH_PATH,
  PHP_DEFAULT_HEALTH_PATH,
} from '../server/services/healthProbeTarget.js';

// Which URL a deploy probes, and whether the body must be {status, version}.
//
// The bug this exists to prevent: a generated PHP app was undeployable. The
// default path is /api/health, Laravel and Symfony serve no such route, so the
// probe 404s for the full 30s window and deployer.js docker rm -f's a container
// that was serving correctly the whole time.
//
// Relaxing `strict` would NOT have fixed it, and that is the misreading worth
// guarding: strict governs only the BODY. A non-strict probe still demands 200
// AT THE PATH. The path is the thing that had to move, and the assertions below
// pin path and strict separately so a future change cannot satisfy one while
// silently dropping the other.

const app = (over = {}) => ({ source_type: 'github', health_path: null, ...over });

// ---------------------------------------------------------------------------
// Node — unchanged
// ---------------------------------------------------------------------------

test('a Node app still defaults to /api/health and is still held to the body shape', () => {
  const r = resolveHealthProbe({ manifest: {}, app: app(), runtime: 'node' });
  assert.equal(r.path, DEFAULT_HEALTH_PATH);
  assert.equal(r.strict, true,
    'the {status, version} contract is fair to demand of an app whose author declares be.health');
});

test('a Node app that declares be.health gets that path, strictly', () => {
  const r = resolveHealthProbe({ manifest: { be: { health: '/healthz' } }, app: app(), runtime: 'node' });
  assert.equal(r.path, '/healthz');
  assert.equal(r.strict, true);
  assert.match(r.source, /manifest\.be\.health/);
});

// ---------------------------------------------------------------------------
// PHP — the fix
// ---------------------------------------------------------------------------

test('a generated PHP build probes the front controller, not /api/health', () => {
  const r = resolveHealthProbe({ manifest: {}, app: app(), runtime: 'php' });
  assert.equal(r.path, PHP_DEFAULT_HEALTH_PATH);
  assert.notEqual(r.path, DEFAULT_HEALTH_PATH,
    'php:8.3-apache serves the release front controller; /api/health is an AppCrane-build ' +
    'convention no Laravel or Symfony app has a reason to serve, so probing it 404s for the ' +
    'whole window and the deploy tears down a healthy container');
});

test('a generated PHP build is NOT held to the {status, version} body', () => {
  // The front controller answers HTML. Demanding AppCrane's JSON shape there
  // fails a healthy app for the crime of being a web app.
  const r = resolveHealthProbe({ manifest: {}, app: app(), runtime: 'php' });
  assert.equal(r.strict, false);
});

test('the two relaxations are independent — moving the path is what makes PHP deployable', () => {
  // Guards the misreading directly: had only `strict` been relaxed, the path
  // would still be /api/health and every PHP deploy would still fail.
  const php = resolveHealthProbe({ manifest: {}, app: app(), runtime: 'php' });
  assert.notEqual(php.path, DEFAULT_HEALTH_PATH, 'strict:false alone would not have helped');
  assert.equal(php.strict, false);
});

test('a PHP app may still declare its own health path, and it is honoured', () => {
  const r = resolveHealthProbe({ manifest: { be: { health: '/up' } }, app: app(), runtime: 'php' });
  assert.equal(r.path, '/up');
  assert.equal(r.strict, false,
    'declaring a path is not agreeing to a body shape — AppCrane did not write this app');
});

test('the PHP default explains itself in the deploy log', () => {
  // healthSource is printed verbatim into the deploy log; an operator reading
  // "why is it probing /" gets the answer there and nowhere else.
  const r = resolveHealthProbe({ manifest: {}, app: app(), runtime: 'php' });
  assert.match(r.source, /php/i);
});

// ---------------------------------------------------------------------------
// Image apps — unchanged by this refactor
// ---------------------------------------------------------------------------

test('an image app keeps apps.health_path and stays non-strict', () => {
  const r = resolveHealthProbe({
    manifest: {},
    app: app({ source_type: 'image', health_path: '/status' }),
    runtime: null,
  });
  assert.equal(r.path, '/status');
  assert.equal(r.strict, false);
  assert.match(r.source, /apps\.health_path/);
});

test('an image app with no health_path still defaults to /api/health, non-strict', () => {
  // Not ideal, but it is the pre-existing contract and this change must not
  // move it: the catalogue carries health paths precisely because the default
  // does not fit most images.
  const r = resolveHealthProbe({ manifest: {}, app: app({ source_type: 'image' }), runtime: null });
  assert.equal(r.path, DEFAULT_HEALTH_PATH);
  assert.equal(r.strict, false);
});

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

test('the manifest outranks the column, which outranks every default', () => {
  const both = resolveHealthProbe({
    manifest: { be: { health: '/from-manifest' } },
    app: app({ health_path: '/from-column' }),
    runtime: 'php',
  });
  assert.equal(both.path, '/from-manifest');

  const columnOnly = resolveHealthProbe({
    manifest: {},
    app: app({ health_path: '/from-column' }),
    runtime: 'php',
  });
  assert.equal(columnOnly.path, '/from-column',
    'an explicit column must beat the PHP default, or a catalogue PHP app cannot name its own path');
});

test('an empty manifest, a missing app and a null runtime do not throw', () => {
  // deployApp passes buildRuntime=null for image deploys and manifest may be {}.
  assert.equal(resolveHealthProbe({ manifest: {}, app: {} }).path, DEFAULT_HEALTH_PATH);
  assert.equal(resolveHealthProbe({ manifest: {}, app: {}, runtime: null }).strict, true);
});
