import { publicPortForApp, dataPlanePortForApp } from './tcpIngress.js';

// Does the RUNNING container actually publish what the app row says it does?
//
// The two can disagree, and until now every read surface reported only the row.
// `published_as: 0.0.0.0:8080 -> container:10800` was printed as fact when it was
// intent, and an operator chasing a refused connection had nothing pointing at
// the real cause.
//
// The cause is structural, not a bug: a port publish is a `docker run` argument.
// Setting ingress on an app that is already running changes the row and nothing
// else — the container keeps the command line it was created with until it is
// RECREATED. And not every restart recreates: the health checker's auto-restart
// is `docker restart`, which reuses the existing container and its bindings, so
// an app can bounce repeatedly and still never publish the port. Only a path
// that goes through startApp() applies it (POST /api/apps/:slug/restart/:env,
// and any deploy or rollback).
//
// This module is deliberately pure — it compares an app row against an already
// observed container state and knows nothing about how that state was read. The
// single `docker ps` that produces it lives in docker.js, because doing it per
// app would put one subprocess spawn per app on the catalog endpoint.
//
// Production only, matching publicPublishTargets(): there is one public_port and
// two containers, so only production ever carries the publish.

/**
 * What the app row says should be published, as the runtime resolves it —
 * null when the app publishes nothing (including a row the guards refuse).
 */
export function intendedPublish(app) {
  const host = publicPortForApp(app);
  if (host === null) return null;
  return { host, container: dataPlanePortForApp(app) };
}

/**
 * Compare intent against what the container is really doing.
 *
 * @param {object} app     app row with ingress_type, public_port, data_plane_port
 * @param {object|null} observed
 *   `null` when the container's state could not be read at all (Docker
 *   unreachable, or no production container exists). That is reported as
 *   `applied: null` — UNKNOWN — never as "not applied": claiming a port is
 *   unpublished because we failed to look would be the same class of wrong
 *   answer this module exists to remove.
 *   Otherwise `{ publishes: [{ hostIp, hostPort, containerPort }] }`, listing
 *   only non-loopback bindings; the 127.0.0.1 control-plane publish every app
 *   has is not a public port and is filtered out before it gets here.
 *
 * @returns {{ applied: boolean|null, drift: object|null }}
 */
export function ingressDrift(app, observed) {
  const expected = intendedPublish(app);

  if (observed === null) {
    return {
      applied: null,
      drift: expected === null ? null : {
        state: 'unknown',
        expected,
        actual: null,
        message: 'Could not read the running container, so whether this publish is live is unknown. ' +
          'This is not a claim that the port is closed.',
      },
    };
  }

  const publishes = observed.publishes || [];

  if (expected === null) {
    if (publishes.length === 0) return { applied: true, drift: null };
    // The container publishes a port the row does not ask for. pending_port_release
    // tracks this when AppCrane itself made the change; this catches the case it
    // did not see — a row edited directly, or a restore from a backup.
    return {
      applied: false,
      drift: {
        state: 'orphan',
        expected: null,
        actual: publishes,
        message: `This app is configured to publish nothing, but the running container still binds ` +
          `${publishes.map(p => `${p.hostIp}:${p.hostPort}`).join(', ')}. The publish is a docker run ` +
          `flag, so it stays until the container is RECREATED — restart the app to close it.`,
      },
    };
  }

  const match = publishes.find(p =>
    p.hostPort === expected.host && p.containerPort === expected.container);
  if (match) return { applied: true, drift: null };

  const wanted = `0.0.0.0:${expected.host} -> container:${expected.container}`;

  if (publishes.length === 0) {
    return {
      applied: false,
      drift: {
        state: 'not_applied',
        expected,
        actual: [],
        message: `Configured, not yet applied — nothing is published for this app yet. ${wanted} is what ` +
          `the configuration asks for, but the running container was created before it and binds no ` +
          `public port. A port publish is a docker run flag, so it takes effect only when the container ` +
          `is RECREATED: restart the app (POST /api/apps/<slug>/restart/production, or the Restart ` +
          `button), or deploy. A plain "docker restart" reuses the existing container and will NOT ` +
          `open it — that includes the health checker's automatic restart.`,
      },
    };
  }

  return {
    applied: false,
    drift: {
      state: 'stale',
      expected,
      actual: publishes,
      message: `The running container publishes ${publishes.map(p =>
        `${p.hostIp}:${p.hostPort} -> container:${p.containerPort}`).join(', ')}, but the configuration ` +
        `asks for ${wanted}. The container predates the change — restart the app to apply it. Clients ` +
        `are currently reaching the OLD mapping.`,
    },
  };
}
