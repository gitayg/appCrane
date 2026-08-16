import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A published host port PER ENVIRONMENT (v2.46.0).
//
// docker.js used to refuse outright: `if (env !== 'production') return null`.
// The reason recorded was "one public_port per app but two containers, so the
// second `docker run` dies with 'port is already allocated'". That argued
// against ONE port on TWO containers and never against two different ones —
// sandbox was excluded because there was only one number to go round. The cost
// was that a raw data plane could not be exercised before it went live.
//
// The thing that must not break while adding the second number is the
// invariant the single UNIQUE index used to give for free: NO TWO APPS SHARE A
// HOST PORT. A second column could not express it — SQLite cannot enforce
// uniqueness across two columns as one value space, so app A's sandbox port
// could equal app B's production port with every constraint satisfied, and the
// collision would surface as a failed `docker run` mid-deploy naming a port
// that looks unclaimed in the dashboard. Hence the app_host_ports registry,
// keyed BY the port. Most of this file is that invariant, from every angle.
//
// Rollout is opt-in, and that is asserted too: a published port has no
// forward_auth, no TLS from AppCrane, no identity headers and no audit, so no
// app may gain a sandbox one because the schema changed.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-envports-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const {
  assignPublicPort, releasePublicPort, publicPortForApp, dataPlanePortForApp,
  assertPublicPortAssignable, PUBLISHABLE_ENVS,
} = await import('../server/services/tcpIngress.js');

let slot = 1;
function makeApp(slug, ingress_type = 'dual', data_plane_port = 10800) {
  return db.prepare(
    `INSERT INTO apps (name, slug, slot, source_type, ingress_type, data_plane_port)
     VALUES (?, ?, ?, 'managed', ?, ?)`
  ).run(slug, slug, slot++, ingress_type, data_plane_port).lastInsertRowid;
}
const row = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
const registry = () =>
  db.prepare('SELECT host_port, app_id, env FROM app_host_ports ORDER BY host_port').all();

// ---------------------------------------------------------------------------
// The two numbers
// ---------------------------------------------------------------------------

test('an app can hold a different port in each environment', () => {
  const id = makeApp('two-ports');
  assert.equal(assignPublicPort(db, id, 8080, 'production'), 8080);
  assert.equal(assignPublicPort(db, id, 8081, 'sandbox'), 8081);

  const a = row(id);
  assert.equal(publicPortForApp(a, 'production'), 8080);
  assert.equal(publicPortForApp(a, 'sandbox'), 8081);
  // The container side is a property of the image, so it is the same in both.
  assert.equal(dataPlanePortForApp(a, 'production'), 10800);
  assert.equal(dataPlanePortForApp(a, 'sandbox'), 10800);
});

test('production is still the default, so no existing caller changed meaning', () => {
  const id = makeApp('defaulting');
  assignPublicPort(db, id, 8100, 'production');
  assert.equal(publicPortForApp(row(id)), 8100,
    'a caller that passes no env must still get the production port');
});

test('an app with no sandbox port publishes nothing there — opt-in, not automatic', () => {
  const id = makeApp('prod-only');
  assignPublicPort(db, id, 8200, 'production');
  assert.equal(publicPortForApp(row(id), 'sandbox'), null,
    'a sandbox port appeared without anyone asking — that is a second unauthenticated door ' +
    'opened by a schema change');
  assert.equal(registry().filter(r => r.app_id === id && r.env === 'sandbox').length, 0);
});

// ---------------------------------------------------------------------------
// The invariant: one owner per host port, across apps AND environments
// ---------------------------------------------------------------------------

test('THE INVARIANT: one app\'s sandbox port cannot be another app\'s production port', () => {
  const a = makeApp('holder');
  const b = makeApp('taker');
  assignPublicPort(db, a, 8300, 'production');

  assert.throws(
    () => assignPublicPort(db, b, 8300, 'sandbox'),
    e => e.code === 'PORT_TAKEN',
    'a second column would have allowed this: app A production 8300 and app B sandbox 8300 ' +
    'satisfy every per-column constraint, and the clash only appears as a failed docker run',
  );
});

test('and not the other way round either', () => {
  const a = makeApp('holder2');
  const b = makeApp('taker2');
  assignPublicPort(db, a, 8400, 'sandbox');
  assert.throws(
    () => assignPublicPort(db, b, 8400, 'production'),
    e => e.code === 'PORT_TAKEN');
});

test('an app cannot give itself the same port in both environments', () => {
  const id = makeApp('self-clash');
  assignPublicPort(db, id, 8500, 'production');
  assert.throws(
    () => assignPublicPort(db, id, 8500, 'sandbox'),
    e => e.code === 'PORT_TAKEN',
    'both containers would bind the same host port and the second docker run would die');
});

test('re-assigning the SAME port to the same app and env is idempotent, not a collision', () => {
  const id = makeApp('idempotent');
  assignPublicPort(db, id, 8600, 'sandbox');
  assert.equal(assignPublicPort(db, id, 8600, 'sandbox'), 8600,
    'an app collided with itself — every re-save of an unchanged form would fail');
});

test('the error names which app and which environment holds the port', () => {
  const a = makeApp('named-holder');
  const b = makeApp('named-taker');
  assignPublicPort(db, a, 8700, 'sandbox');
  assert.throws(() => assignPublicPort(db, b, 8700, 'production'), /named-holder/);
  assert.throws(() => assignPublicPort(db, b, 8700, 'production'), /sandbox/,
    'without the environment the operator has to guess which of the two containers holds it');
});

// ---------------------------------------------------------------------------
// Allocation and release
// ---------------------------------------------------------------------------

test('an auto-allocated sandbox port does not collide with an auto-allocated production one', () => {
  const id = makeApp('auto-both');
  const prod = assignPublicPort(db, id, null, 'production');
  const sand = assignPublicPort(db, id, null, 'sandbox');
  assert.notEqual(prod, sand, 'the allocator handed the same number to both containers');
  assert.equal(registry().filter(r => r.app_id === id).length, 2);
});

test('releasing one environment leaves the other alone', () => {
  const id = makeApp('release-one');
  assignPublicPort(db, id, 8800, 'production');
  assignPublicPort(db, id, 8801, 'sandbox');

  releasePublicPort(db, id, 'sandbox');
  assert.equal(publicPortForApp(row(id), 'sandbox'), null);
  assert.equal(publicPortForApp(row(id), 'production'), 8800,
    'releasing sandbox took production down with it');
  assert.equal(registry().filter(r => r.app_id === id).length, 1);
});

test('a released port is free for another app to take', () => {
  const a = makeApp('gives-back');
  const b = makeApp('picks-up');
  assignPublicPort(db, a, 8900, 'sandbox');
  releasePublicPort(db, a, 'sandbox');
  assert.equal(assignPublicPort(db, b, 8900, 'production'), 8900,
    'the registry kept a row for a port nobody holds, so the number leaked out of the pool');
});

test('registry and column never disagree — they are written in one transaction', () => {
  const id = makeApp('consistency');
  assignPublicPort(db, id, 9000, 'sandbox');
  const r = registry().find(x => x.app_id === id && x.env === 'sandbox');
  assert.equal(r.host_port, 9000);
  assert.equal(row(id).sandbox_public_port, 9000,
    'the fast-path column disagrees with the registry that owns the invariant');

  releasePublicPort(db, id, 'sandbox');
  assert.equal(registry().find(x => x.app_id === id && x.env === 'sandbox'), undefined);
  assert.equal(row(id).sandbox_public_port, null);
});

test('a rejected assignment leaves NOTHING behind in either store', () => {
  const a = makeApp('rollback-holder');
  const b = makeApp('rollback-taker');
  assignPublicPort(db, a, 9100, 'production');
  assert.throws(() => assignPublicPort(db, b, 9100, 'sandbox'));

  assert.equal(row(b).sandbox_public_port, null,
    'the column was written before the collision check threw');
  assert.equal(registry().filter(x => x.app_id === b).length, 0,
    'a registry row survived a rejected assignment, so the port is now owned by nobody reachable');
});

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

test('only the environments that can publish are accepted', () => {
  assert.deepEqual(PUBLISHABLE_ENVS, ['production', 'sandbox']);
  const id = makeApp('bad-env');
  assert.throws(() => assignPublicPort(db, id, 9200, 'staging'), /env must be one of/);
  assert.throws(() => assertPublicPortAssignable(db, 9201, id, 'staging'), /env must be one of/);
});

test('the guards a production publish passes are the SAME ones sandbox passes', () => {
  // A sandbox publish that skipped the data-plane guard would be a second way
  // to expose the HTTP origin raw, by a path the v2.45.0 guard tests never look
  // at. data_plane_port = the control plane, which tcpIngress refuses.
  const id = makeApp('guarded', 'dual', 3000);
  assignPublicPort(db, id, 9300, 'sandbox');
  assert.equal(publicPortForApp(row(id), 'sandbox'), null,
    'sandbox published a dual app whose data plane IS the control plane — the exact exposure ' +
    'the production guard exists to prevent, reached one environment over');
  assert.equal(dataPlanePortForApp(row(id), 'sandbox'), null);
});

test('an http app publishes in neither environment even holding numbers', () => {
  const id = makeApp('http-app', 'http', null);
  assignPublicPort(db, id, 9400, 'production');
  assignPublicPort(db, id, 9401, 'sandbox');
  assert.equal(publicPortForApp(row(id), 'production'), null);
  assert.equal(publicPortForApp(row(id), 'sandbox'), null,
    'ingress_type still decides whether anything is published at all');
});

// ---------------------------------------------------------------------------
// Draining: changing a port a live container is still bound to (v2.47.0)
// ---------------------------------------------------------------------------
//
// Target ports are deliberately BELOW the 31000-31999 auto band: another test
// in this file auto-allocates and legitimately takes 31000, and a hardcoded
// number inside the band makes this section fail depending on test order.
//
// This used to be refused, and the operator was told to flip to http, redeploy,
// then pin the new number. The hazard was real — the pin is the only thing
// reserving a number, so overwriting it returns a still-answering port to the
// pool — but the refusal was a workaround for having nowhere to record
// "bound to X, pinned to Y". The registry is that place.

const { drainingPorts, releasePendingPortAfterRecreate } =
  await import('../server/services/tcpIngress.js');

const live = (appId, env) =>
  db.prepare("INSERT INTO deployments (app_id, env, status, version) VALUES (?, ?, 'live', '1.0.0')")
    .run(appId, env);

test('re-pinning a published sandbox port moves the pin and drains the old one', () => {
  const id = makeApp('drain-basic');
  assignPublicPort(db, id, 10800, 'sandbox');
  live(id, 'sandbox');

  assert.equal(assignPublicPort(db, id, 12000, 'sandbox'), 12000,
    'the re-pin was refused — this is the three-step dance the feature removes');
  assert.equal(publicPortForApp(row(id), 'sandbox'), 12000);
  assert.deepEqual(drainingPorts(db, id, 'sandbox').map(d => d.host_port), [10800]);
});

test('THE HAZARD: a draining port cannot be given to another app', () => {
  const a = makeApp('drain-holder');
  const b = makeApp('drain-thief');
  assignPublicPort(db, a, 10900, 'sandbox');
  live(a, 'sandbox');
  assignPublicPort(db, a, 12100, 'sandbox');

  assert.throws(
    () => assignPublicPort(db, b, 10900, 'production'),
    e => e.code === 'PORT_TAKEN',
    'a port a live container still answers on was handed to another app — its clients would ' +
    'now reach a different app entirely, which is exactly what the old refusal prevented',
  );
});

test('the recreate frees it, and only then', () => {
  const id = makeApp('drain-release');
  assignPublicPort(db, id, 11000, 'sandbox');
  live(id, 'sandbox');
  assignPublicPort(db, id, 12200, 'sandbox');

  const freed = releasePendingPortAfterRecreate(db, 'drain-release', 'sandbox');
  assert.deepEqual(freed, [11000]);
  assert.deepEqual(drainingPorts(db, id, 'sandbox'), []);

  const other = makeApp('drain-taker');
  assert.equal(assignPublicPort(db, other, 11000, 'production'), 11000,
    'the port never came back to the pool — it has leaked');
});

test('recreating the OTHER environment does not free this one\'s drained port', () => {
  const id = makeApp('drain-envscope');
  assignPublicPort(db, id, 11100, 'sandbox');
  live(id, 'sandbox');
  assignPublicPort(db, id, 12300, 'sandbox');

  assert.equal(releasePendingPortAfterRecreate(db, 'drain-envscope', 'production'), null,
    'a production recreate freed a port the SANDBOX container is still bound to');
  assert.deepEqual(drainingPorts(db, id, 'sandbox').map(d => d.host_port), [11100]);
});

test('a port allocated but never deployed is re-pinned with nothing left draining', () => {
  // No live deployment, so nothing is bound and there is nothing to reserve.
  // This is the common case — "I just enabled tcp, now set the number I want".
  const id = makeApp('drain-none');
  assignPublicPort(db, id, 11200, 'sandbox');
  assert.equal(assignPublicPort(db, id, 12400, 'sandbox'), 12400);
  assert.deepEqual(drainingPorts(db, id, 'sandbox'), [],
    'a port nothing was ever bound to was reserved anyway, wasting it until a recreate');
});

test('re-pinning twice before a recreate drains BOTH old ports', () => {
  const id = makeApp('drain-twice');
  assignPublicPort(db, id, 11300, 'sandbox');
  live(id, 'sandbox');
  assignPublicPort(db, id, 11301, 'sandbox');
  assignPublicPort(db, id, 11302, 'sandbox');

  // Only one of them is actually bound, but AppCrane cannot tell which, and
  // holding a number it does not need is strictly safer than reissuing one a
  // container answers on. Both come back on the next recreate.
  assert.deepEqual(drainingPorts(db, id, 'sandbox').map(d => d.host_port), [11300, 11301]);
  assert.equal(publicPortForApp(row(id), 'sandbox'), 11302);
  assert.deepEqual(releasePendingPortAfterRecreate(db, 'drain-twice', 'sandbox').sort(), [11300, 11301]);
});

test('the schema still refuses two PINNED ports for one app and environment', () => {
  const id = makeApp('drain-onepin');
  assignPublicPort(db, id, 11400, 'sandbox');
  live(id, 'sandbox');
  assignPublicPort(db, id, 12500, 'sandbox');
  const pinned = db.prepare(
    "SELECT COUNT(*) c FROM app_host_ports WHERE app_id = ? AND env = 'sandbox' AND state = 'pinned'"
  ).get(id).c;
  assert.equal(pinned, 1, 'draining rows are unconstrained, but there must be exactly one pin');
});
