import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// POST /api/apps/:slug/restart/:env now runs services/containerRecreate.js,
// which the gateway repair (hostGateway.js) also calls. Parity is pinned against the
// v2.145.0 (d1d91883) handler, not against the new function itself:
// fixtures/container-recreate-golden-argv.json is the docker argv that
// handler issued for two app shapes (a production app with a command, limits
// and a port; a multitenant sandbox app with two declared volumes), recorded by
// running d1d91883's server/ tree through fixtures/container-recreate-golden.setup.js.
// The route, and recreateEnvContainer for a user and for the system actor,
// must issue exactly that argv and report the same injected keys.
// v2.147.0 edited the recording by hand in one place only: the app's docker
// run gained `--label appcrane.db-scope=` (the shared database scope both
// shapes start in) right after `--label env=<env>`, which APPCRANE-DB reads
// (hostFirewall/dbDesired.js). d1d91883 cannot record a label it never wrote.

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, 'fixtures', 'container-recreate-golden-argv.json'), 'utf8'));
const { prepare, SHAPES } = await import('./fixtures/container-recreate-golden.setup.js');
const h = await prepare(join(here, '..', 'server'));
after(() => h.close());

const { recreateEnvContainer } = await import('../server/services/containerRecreate.js');
const { REPAIR_ACTOR, REPAIR_REASON } = await import('../server/services/hostGateway.js');
const { readFileSync: rf, writeFileSync } = await import('fs');

async function direct(slug, env, actor) {
  writeFileSync(h.LOG, '');
  const app = h.db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  const body = await recreateEnvContainer({ app, env, actor, reason: REPAIR_REASON });
  const argv = rf(h.LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
    .filter((a) => ['run', 'stop', 'rm', 'create', 'start'].includes(a[0])).map(h.normalise);
  return { status: 200, argv, injected_keys: body.injected_keys, image: body.image };
}

test('the golden fixture covers two app shapes and was recorded from a successful restart', () => {
  assert.deepEqual(Object.keys(GOLDEN).sort(), SHAPES.map((s) => `${s.slug}/${s.env}`).sort());
  for (const [k, g] of Object.entries(GOLDEN)) {
    assert.equal(g.status, 200, k);
    assert.ok(g.argv.some((a) => a[0] === 'run' && a.includes('-d')), `${k}: no app docker run recorded`);
  }
});

for (const s of SHAPES) {
  const key = `${s.slug}/${s.env}`;
  test(`${key}: the route issues the v2.145.0 handler's docker argv`, async () => {
    assert.deepEqual(await h.restart(s.slug, s.env), GOLDEN[key]);
  });
  test(`${key}: recreateEnvContainer issues the same argv for a user and for the system actor`, async () => {
    const user = h.db.prepare("SELECT * FROM users WHERE email = 'o@t.test'").get();
    for (const actor of [user, REPAIR_ACTOR]) {
      assert.deepEqual(await direct(s.slug, s.env, actor), GOLDEN[key], `actor ${typeof actor === 'string' ? actor : 'user'}`);
    }
  });
}

test('the route keeps its checks: unknown env is 400 and runs no docker', async () => {
  const r = await h.restart('golda', 'staging');
  assert.equal(r.status, 400);
  assert.deepEqual(r.argv, []);
});
