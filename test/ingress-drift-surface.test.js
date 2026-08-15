import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// What the MCP ingress payload SAYS about a publish that is not live (v2.45.3).
//
// `published_as` was assembled from the app row, so it stated a mapping that
// might exist nowhere. On apphub it reported `0.0.0.0:8080 -> container:10800`
// for an app whose container bound nothing: the ingress had been set after the
// container was created, and a port publish is a `docker run` argument. An
// operator and an agent both read that as fact and went looking at SDP, DNS and
// firewall rules for an afternoon.
//
// ingress-drift.test.js proves the comparison, and data-plane-e2e.test.js proves
// it against a real daemon. What is left is the thin wiring in between — the
// string the reader actually sees — and thin wiring reported as fact is the
// entire bug, so it gets its own cover.
//
// Docker is stubbed with a shim on PATH rather than by patching the module: ESM
// exports are read-only (an attempt to assign one failed with "Cannot assign to
// read only property"), and going through the CLI exercises the real
// `docker ps` parse too.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-driftsurf-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A `docker` that answers `ps` from a file the test rewrites between cases, and
// can be told to fail outright to stand in for an unreachable daemon.
const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const PS_OUT = join(process.env.DATA_DIR, 'ps-output');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const body = fs.readFileSync(process.env.CRANE_TEST_PS_OUT, 'utf8');
if (body === '__FAIL__') { process.stderr.write('Cannot connect to the Docker daemon\\n'); process.exit(1); }
process.stdout.write(body);
`, { mode: 0o755 });
process.env.CRANE_TEST_PS_OUT = PS_OUT;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { callTool } = await import('../server/services/mcpTools.js');
const { invalidatePublishedPortsCache } = await import('../server/services/docker.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const HOST_PORT = 8080;
const DATA_PORT = 10800;
const SLUG = 'drift-surface';

const KEY = generateApiKey('dhk_admin');
const userId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')"
).run(hashApiKey(KEY)).lastInsertRowid;
const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

db.prepare(
  `INSERT INTO apps (name, slug, slot, source_type, ingress_type, public_port, data_plane_port)
   VALUES ('Drift', ?, 90, 'managed', 'dual', ?, ?)`
).run(SLUG, HOST_PORT, DATA_PORT);

/** Point the shim at a `docker ps` result, and clear the short-lived cache. */
function dockerReports(line) {
  writeFileSync(PS_OUT, line);
  invalidatePublishedPortsCache();
}

const read = async () => {
  const r = await callTool(user, 'appcrane_get_app_ingress', { slug: SLUG });
  return typeof r === 'string' ? JSON.parse(r) : (r.content ? JSON.parse(r.content[0].text) : r);
};

after(() => { /* temp dir is disposable */ });

test('a publish the container does not carry is NOT LIVE, in published_as itself', async () => {
  // The container is up and binds only its loopback control plane — the apphub
  // state exactly.
  dockerReports(`${SLUG}|127.0.0.1:4013->3000/tcp\n`);
  const out = await read();

  assert.equal(out.publish_applied, false);
  assert.equal(out.publish_drift.state, 'not_applied');
  assert.match(out.exposure.published_as, /CONFIGURED BUT NOT LIVE/,
    'an agent reading only published_as is still told the port is live — the exact false ' +
    'claim this change exists to remove');
  assert.match(out.exposure.published_as, /RECREATED/,
    'the remedy has to travel with the finding: a plain restart does not apply a publish');
});

test('a publish the container DOES carry leaves published_as clean', async () => {
  dockerReports(`${SLUG}|127.0.0.1:4013->3000/tcp, 0.0.0.0:${HOST_PORT}->${DATA_PORT}/tcp\n`);
  const out = await read();

  assert.equal(out.publish_applied, true);
  assert.equal(out.publish_drift, undefined, 'no drift key at all when there is no drift');
  assert.equal(out.exposure.published_as, `0.0.0.0:${HOST_PORT} -> container:${DATA_PORT}`,
    'a live publish must not be annotated, or the warning stops meaning anything');
});

test('an unreadable daemon is unknown — published_as stays clean and applied is null', async () => {
  dockerReports('__FAIL__');
  const out = await read();

  assert.equal(out.publish_applied, null,
    'false here would tell an operator the port is closed because we failed to look');
  assert.equal(out.exposure.published_as, `0.0.0.0:${HOST_PORT} -> container:${DATA_PORT}`,
    'annotating every read on a host without Docker puts noise on the common case to ' +
    'describe a state that already has its own field');
});

test('a container publishing the OLD port is reported as stale, with both numbers', async () => {
  dockerReports(`${SLUG}|127.0.0.1:4013->3000/tcp, 0.0.0.0:9999->${DATA_PORT}/tcp\n`);
  const out = await read();

  assert.equal(out.publish_applied, false);
  assert.equal(out.publish_drift.state, 'stale');
  assert.match(out.exposure.published_as, /9999/, 'what clients reach right now');
  assert.match(out.exposure.published_as, new RegExp(String(HOST_PORT)), 'and what was configured');
});
