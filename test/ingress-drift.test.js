import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// "Configured" and "actually published" are two different facts (v2.45.3).
//
// A port publish is a `docker run` argument. Setting ingress on an app that is
// already running changes the row and nothing else — the container keeps the
// command line it was created with. Every read surface nonetheless printed the
// row as though it described the world: `published_as: 0.0.0.0:8080 ->
// container:10800` was reported for an app whose container bound nothing at
// all, and an operator debugging a refused connection was sent looking at
// firewalls and the VPN instead of at the container.
//
// The trap underneath it: not every restart recreates. The health checker calls
// `docker restart`, which reuses the existing container and therefore its
// bindings, so an app can bounce all day and still never publish. Only a path
// through startApp() applies it.
//
// These are the two halves that make the answer trustworthy — the parse of what
// Docker reports, and the comparison against what the row asks for. Both are
// pure, so they are tested against fixtures rather than a daemon; the live
// end-to-end proof is in data-plane-e2e.test.js.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-drift-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { parsePublishedPorts } = await import('../server/services/docker.js');
const { ingressDrift, intendedPublish } = await import('../server/services/ingressDrift.js');

const dual = { ingress_type: 'dual', public_port: 8080, data_plane_port: 10800 };
const tcp  = { ingress_type: 'tcp',  public_port: 31005, data_plane_port: null };
const http = { ingress_type: 'http', public_port: null,  data_plane_port: null };

// ---------------------------------------------------------------------------
// Parsing what `docker ps` reports
// ---------------------------------------------------------------------------

test('the loopback control-plane publish is not a public port', () => {
  const parsed = parsePublishedPorts('127.0.0.1:4013->3000/tcp, 0.0.0.0:8080->10800/tcp');
  assert.deepEqual(parsed, [{ hostIp: '0.0.0.0', hostPort: 8080, containerPort: 10800 }],
    'every app has the 127.0.0.1 publish — counting it would make every app look drifted');
});

test('an app with only the loopback publish parses to no public ports', () => {
  assert.deepEqual(parsePublishedPorts('127.0.0.1:4013->3000/tcp'), []);
});

test('an EXPOSEd port with no host binding is not a publish', () => {
  assert.deepEqual(parsePublishedPorts('3000/tcp, 9229/tcp'), [],
    'those reach nothing from outside the container');
});

test('empty and absent port columns are handled', () => {
  assert.deepEqual(parsePublishedPorts(''), []);
  assert.deepEqual(parsePublishedPorts(undefined), []);
});

test('IPv6 bindings parse, and IPv6 loopback is excluded like IPv4', () => {
  assert.deepEqual(parsePublishedPorts('[::]:8080->10800/tcp'),
    [{ hostIp: '[::]', hostPort: 8080, containerPort: 10800 }]);
  assert.deepEqual(parsePublishedPorts('[::1]:4013->3000/tcp'), []);
});

// ---------------------------------------------------------------------------
// Comparing the row against the container
// ---------------------------------------------------------------------------

test('a dual app whose container carries the publish reads as applied', () => {
  const r = ingressDrift(dual, { publishes: [{ hostIp: '0.0.0.0', hostPort: 8080, containerPort: 10800 }] });
  assert.equal(r.applied, true);
  assert.equal(r.drift, null);
});

test('THE BUG: configured to publish, container publishes nothing', () => {
  const r = ingressDrift(dual, { publishes: [] });
  assert.equal(r.applied, false);
  assert.equal(r.drift.state, 'not_applied');
  assert.match(r.drift.message, /not yet applied/i);
  // The remedy has to be in the message, and it has to be the RIGHT one — the
  // whole failure was someone restarting and nothing changing.
  assert.match(r.drift.message, /RECREATED/);
  assert.match(r.drift.message, /docker restart.*will NOT/is);
});

test('a container still on the OLD mapping is stale, not merely unapplied', () => {
  const r = ingressDrift(dual, { publishes: [{ hostIp: '0.0.0.0', hostPort: 9999, containerPort: 10800 }] });
  assert.equal(r.applied, false);
  assert.equal(r.drift.state, 'stale');
  assert.match(r.drift.message, /9999/, 'the operator needs to know what clients are reaching NOW');
  assert.match(r.drift.message, /8080/, 'and what it should be');
});

test('the host port matching is not enough — the container side must match too', () => {
  // 8080 is bound, so a host-port-only check would call this applied. It points
  // at the wrong port inside the container, so nothing works.
  const r = ingressDrift(dual, { publishes: [{ hostIp: '0.0.0.0', hostPort: 8080, containerPort: 3000 }] });
  assert.equal(r.applied, false, 'the publish reaches the wrong container port');
  assert.equal(r.drift.state, 'stale');
});

test('a pure-tcp app is judged against container port 3000', () => {
  assert.deepEqual(intendedPublish(tcp), { host: 31005, container: 3000 });
  assert.equal(ingressDrift(tcp, { publishes: [{ hostIp: '0.0.0.0', hostPort: 31005, containerPort: 3000 }] }).applied, true);
  assert.equal(ingressDrift(tcp, { publishes: [] }).drift.state, 'not_applied');
});

test('an http app that publishes nothing is applied, not drifted', () => {
  const r = ingressDrift(http, { publishes: [] });
  assert.equal(r.applied, true);
  assert.equal(r.drift, null);
});

test('an http app whose container still binds a port is an orphan', () => {
  const r = ingressDrift(http, { publishes: [{ hostIp: '0.0.0.0', hostPort: 8080, containerPort: 10800 }] });
  assert.equal(r.applied, false);
  assert.equal(r.drift.state, 'orphan');
  assert.match(r.drift.message, /still binds/);
});

test('a dual row the guards refuse publishes nothing, and a bare container matches that', () => {
  // data_plane_port = the control plane. tcpIngress refuses it, so the app is
  // SUPPOSED to publish nothing — a container binding nothing is correct, and
  // must not be reported as drift.
  const refused = { ingress_type: 'dual', public_port: 8080, data_plane_port: 3000 };
  assert.equal(intendedPublish(refused), null);
  assert.equal(ingressDrift(refused, { publishes: [] }).applied, true);
});

test('an unreadable container is UNKNOWN — never reported as unpublished', () => {
  const r = ingressDrift(dual, null);
  assert.equal(r.applied, null,
    'false here would tell an operator the port is closed because we failed to look');
  assert.equal(r.drift.state, 'unknown');
  assert.match(r.drift.message, /not a claim that the port is closed/i);
});

test('an unreadable container on an app that publishes nothing raises nothing', () => {
  const r = ingressDrift(http, null);
  assert.equal(r.applied, null);
  assert.equal(r.drift, null, 'there is no publish to be uncertain about');
});
