import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { withBuild, withPrune, buildsInFlight } from '../server/services/buildGate.js';

const tick = () => new Promise((r) => setTimeout(r, 10));

// The live end-to-end race is test/serial/build-gate-live.test.js: other test
// files prune the same Docker daemon from their own processes, outside this gate.

test('a prune waits until every running build has finished', async () => {
  const order = [];
  let endA, endB;
  const a = withBuild(() => new Promise((r) => { endA = r; }));
  const b = withBuild(() => new Promise((r) => { endB = r; }));
  const p = withPrune('t1', async () => { order.push('prune'); });
  await tick();
  assert.equal(buildsInFlight(), 2);
  assert.deepEqual(order, []);
  endA(); await a; await tick();
  assert.deepEqual(order, [], 'one build still running');
  endB(); await b; await p;
  assert.deepEqual(order, ['prune']);
});

test('a build waits while a prune is running', async () => {
  const order = [];
  let endPrune;
  const p = withPrune('t2', () => new Promise((r) => { endPrune = r; }));
  await tick();
  const b = withBuild(async () => { order.push('build'); });
  await tick();
  assert.deepEqual(order, []);
  endPrune(); await p; await b;
  assert.deepEqual(order, ['build']);
});

test('prunes asked for during a build coalesce by key', async () => {
  let runs = 0;
  let end;
  const b = withBuild(() => new Promise((r) => { end = r; }));
  const ps = Array.from({ length: 10 }, () => withPrune('t3', async () => { runs += 1; }));
  await tick();
  end(); await b; await Promise.all(ps);
  assert.equal(runs, 1);
});

test('the same prune asked for twice in a row runs twice', async () => {
  let runs = 0;
  await withPrune('t4', async () => { runs += 1; });
  await withPrune('t4', async () => { runs += 1; });
  assert.equal(runs, 2);
});

test('every image build and every image prune goes through the gate', () => {
  const docker = readFileSync(new URL('../server/services/docker.js', import.meta.url), 'utf8');
  assert.match(docker, /function runDockerBuild[\s\S]{0,200}withBuild\(/);
  assert.match(docker, /withPrune\('dangling-images', \(\) => dockerExec\(\['image', 'prune', '-f'\]\)\)/);
  assert.match(docker, /withPrune\(`old-images:/);
  assert.match(docker, /withPrune\(`old-pulled:/);
  const nix = readFileSync(new URL('../server/services/nixpacks.js', import.meta.url), 'utf8');
  assert.match(nix, /withBuild\(\(\) => new Promise/);
  const left = readFileSync(new URL('../server/services/buildLeftovers.js', import.meta.url), 'utf8');
  assert.match(left, /withPrune\('build-leftovers'/);
  const cache = readFileSync(new URL('../server/services/buildCachePrune.js', import.meta.url), 'utf8');
  assert.match(cache, /withPrune\('build-cache'/);
});
