/**
 * TCP ingress (v2.42.0) — schema helpers + the public-port allocator.
 *
 * An app with ingress_type='tcp' gets its container port published on the host
 * at 0.0.0.0:<public_port>, in ADDITION to the loopback publish every app
 * already has. Caddy is not in that path at all, which is the whole point: a
 * forward/CONNECT proxy speaks raw TCP and no HTTP reverse proxy can express
 * a tunnel.
 *
 * SECURITY: a directly-published port has no forward_auth, no identity
 * headers, no per-request audit, no rate limiting, no security headers and no
 * TLS from AppCrane. Those controls all live in Caddy, so they simply do not
 * apply here — a tcp app owns authentication completely. Setting ingress_type
 * or a public_port is platform-admin only (enforced by the callers), and
 * AppCrane still does not open the firewall: publishing the port and letting
 * traffic reach it are deliberately two different keys.
 */
import { getPortsForSlot } from './portAllocator.js';
import { isPortSafe } from './blockedPorts.js';

/**
 * Dedicated range so the operator's firewall rule is one predictable block
 * instead of a per-app list. Nothing in the WHATWG bad-ports list falls in
 * here, but every candidate is still run through isPortSafe() rather than
 * assumed safe — the list is external and can grow.
 */
export const PUBLIC_PORT_MIN = 31000;
export const PUBLIC_PORT_MAX = 31999;

export const INGRESS_TYPES = ['http', 'tcp'];

/**
 * How far past the highest allocated slot we still treat getPortsForSlot()
 * output as reserved. Mirrors getNextSlot()'s 1000-candidate scan: those are
 * the slots the allocator can hand out without any further app being created.
 */
const SLOT_HORIZON_HEADROOM = 1000;

function fail(message, status, code) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/**
 * Report the EFFECTIVE type rather than the raw column, mirroring
 * effectiveAuthMode(): the value is validated on write, but a legacy row
 * (every row that existed before migration 072) or a hand-edited one must
 * still read back as the behaviour the runtime actually implements — only the
 * literal 'tcp' gets a published host port.
 */
export function effectiveIngressType(raw) {
  return raw === 'tcp' ? 'tcp' : 'http';
}

export function validateIngressType(value) {
  if (!INGRESS_TYPES.includes(value)) {
    throw fail("ingress_type must be 'http' or 'tcp'", 400, 'VALIDATION');
  }
  return value;
}

export function isTcpApp(app) {
  return effectiveIngressType(app?.ingress_type) === 'tcp';
}

/**
 * The host port to publish for this app row, or null when there is nothing to
 * publish. Both conditions matter: an http app never publishes, and a tcp app
 * whose allocation has not landed yet must not publish port `null`.
 *
 * This is the one call the runtime (docker.js, healthChecker.js) needs — it
 * answers "is this app tcp, and on what public port" from an app row that has
 * already been read, with no second query.
 */
export function publicPortForApp(app) {
  if (!isTcpApp(app)) return null;
  return Number.isInteger(app?.public_port) ? app.public_port : null;
}

/**
 * The port this app still HOLDS but no longer publishes, or null.
 *
 * The publish is a `docker run` flag, so flipping an app from tcp back to http
 * cannot close anything by itself: the container that is already running keeps
 * binding 0.0.0.0:<port> until it is recreated. Returning the number to the
 * pool at flip time therefore broke the one invariant this allocator exists to
 * hold — the next app to ask got a port a live container was still bound to, so
 * its `docker run` died with "port is already allocated" while connections to
 * that port were still reaching the OLD app, and every AppCrane surface
 * meanwhile reported the port closed.
 *
 * So the row KEEPS the number as a reservation across the flip. It is no longer
 * published (publicPortForApp() is what the runtime asks, and that says null the
 * moment ingress_type is http), it is no longer assignable to anyone else, and
 * it goes back in the pool at the one moment nothing can still bind it: when the
 * production container is recreated without the publish. Callers report this
 * separately from public_port precisely because the two facts differ — AppCrane
 * publishes nothing, and the host port may still answer.
 */
export function pendingPortRelease(app) {
  if (isTcpApp(app)) return null;
  return Number.isInteger(app?.public_port) ? app.public_port : null;
}

/** Same answer for callers that hold only an app id. */
export function getIngressForApp(db, appId) {
  const row = db.prepare('SELECT ingress_type, public_port FROM apps WHERE id = ?').get(appId);
  return {
    ingress_type: effectiveIngressType(row?.ingress_type),
    public_port: publicPortForApp(row),
  };
}

function cranePort() {
  return Number(process.env.PORT || 5001);
}

/**
 * Does this port collide with something getPortsForSlot() can produce?
 *
 * The formula is unbounded (sand_fe = 3000 + 2N reaches 31000 at slot 14000),
 * so "can produce" is answered in two parts: exactly, against the slots that
 * actually exist, and structurally, against the slots the allocator could
 * still hand out. Asserting this rather than trusting the range to be clear is
 * the point — a silent overlap would mean two containers fighting for one host
 * port, with the loser's deploy failing at `docker run` for no visible reason.
 */
export function slotPortConflict(db, port) {
  const slots = db.prepare('SELECT DISTINCT slot FROM apps WHERE slot IS NOT NULL').all();
  for (const { slot } of slots) {
    const ports = getPortsForSlot(slot);
    for (const key of ['prod_fe', 'prod_be', 'sand_fe', 'sand_be']) {
      if (ports[key] === port) return { slot, key };
    }
  }

  const row = db.prepare('SELECT MAX(slot) AS max_slot FROM apps').get();
  const horizon = (row?.max_slot || 0) + SLOT_HORIZON_HEADROOM;
  for (const base of [3000, 4000]) {
    const offset = port - base;
    if (offset < 1) continue;
    const slot = Math.ceil(offset / 2);
    if (slot >= 1 && slot <= horizon) return { slot, key: base === 3000 ? 'fe' : 'be' };
  }
  return null;
}

/**
 * Throw unless `port` is a legal public port for this app. Callers that hand
 * an operator-chosen port straight to the database go through here first.
 */
export function assertPublicPortAssignable(db, port, appId) {
  if (!Number.isInteger(port)) {
    throw fail('public_port must be an integer', 400, 'VALIDATION');
  }
  if (port < PUBLIC_PORT_MIN || port > PUBLIC_PORT_MAX) {
    throw fail(`public_port must be between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}`, 400, 'VALIDATION');
  }
  if (!isPortSafe(port)) {
    throw fail(`Port ${port} is on the WHATWG blocked-ports list and cannot be used`, 400, 'VALIDATION');
  }
  if (port === cranePort()) {
    throw fail(`Port ${port} is AppCrane's own listening port`, 409, 'PORT_RESERVED');
  }
  const slotClash = slotPortConflict(db, port);
  if (slotClash) {
    throw fail(`Port ${port} is reserved for app slot ${slotClash.slot} (${slotClash.key})`, 409, 'PORT_RESERVED');
  }
  const taken = db.prepare('SELECT slug FROM apps WHERE public_port = ? AND id != ?').get(port, appId);
  if (taken) {
    throw fail(`Port ${port} is already published by app "${taken.slug}"`, 409, 'PORT_TAKEN');
  }
  return port;
}

/**
 * Lowest free port in the range. Lowest-first keeps allocations dense and
 * predictable, so an operator reading `ss -lntp` can tell at a glance which
 * ports are in play.
 */
export function allocatePublicPort(db, appId) {
  for (let port = PUBLIC_PORT_MIN; port <= PUBLIC_PORT_MAX; port++) {
    try {
      assertPublicPortAssignable(db, port, appId);
      return port;
    } catch (_) {
      continue;
    }
  }
  throw fail(
    `No free public port in ${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}. Release a TCP app's port or widen the range.`,
    409, 'NO_PUBLIC_PORT',
  );
}

/**
 * Give this app a public port and return it.
 *
 * `requested` null means "allocate one"; an existing allocation is returned
 * untouched, which is what makes the port survive redeploys, renames and slot
 * changes — nothing in those paths recomputes it.
 *
 * Runs as one synchronous transaction so the read that picks the port and the
 * write that claims it cannot interleave with a second admin doing the same;
 * the partial unique index is the backstop if they somehow do.
 */
export function assignPublicPort(db, appId, requested = null) {
  return db.transaction(() => {
    const row = db.prepare('SELECT public_port, ingress_type FROM apps WHERE id = ?').get(appId);
    if (requested === null) {
      if (Number.isInteger(row?.public_port)) return row.public_port;
      const port = allocatePublicPort(db, appId);
      db.prepare('UPDATE apps SET public_port = ? WHERE id = ?').run(port, appId);
      return port;
    }
    // Changing an app from one port to another is refused while it still holds
    // the old one, because this UPDATE would drop that number from the row —
    // and the row is the only thing reserving it. The container is still bound
    // to it, so the allocator would hand a live port to the next app and every
    // client pinned to the old number would reach a DIFFERENT app. That is the
    // silent cross-app redirection the pinned model exists to prevent; it just
    // reaches it by a path pendingPortRelease() cannot see, since that reports
    // only on an app whose ingress_type is already 'http'.
    //
    // Refused rather than tracked: recording "still bound to X while pinned to
    // Y" needs a second column, and the two-step below reuses the release path
    // that is already audited and tested. Flip to http, redeploy (which frees
    // the port the moment the container comes back without the publish), then
    // pin the new number.
    // Only when a container is actually publishing it. A port that was
    // allocated but never deployed is bound by nothing, so re-pinning before
    // the first deploy — "I just enabled tcp, now set the number I want" — is
    // both safe and the common case.
    const held = row?.public_port;
    const published = Number.isInteger(held) && effectiveIngressType(row?.ingress_type) === 'tcp'
      && !!db.prepare(
        "SELECT 1 FROM deployments WHERE app_id = ? AND env = 'production' AND status = 'live' LIMIT 1"
      ).get(appId);
    if (published && held !== requested) {
      const e = new Error(
        `This app still holds port ${held}. Set ingress_type='http' and redeploy to stop ` +
        `publishing it before pinning ${requested} — otherwise ${held} returns to the pool ` +
        `while the running container is still bound to it.`);
      e.status = 409; e.code = 'PORT_STILL_HELD';
      throw e;
    }
    assertPublicPortAssignable(db, requested, appId);
    db.prepare('UPDATE apps SET public_port = ? WHERE id = ?').run(requested, appId);
    return requested;
  })();
}

/**
 * Drop the allocation, returning the port to the pool.
 *
 * NOT what a tcp -> http flip calls: at that moment a container is very likely
 * still bound to the port (see pendingPortRelease). This is the unconditional
 * primitive; releasePendingPortAfterRecreate() below is the only caller that
 * knows when using it is safe. Deleting an app needs no call here: the row
 * goes, and the partial unique index only covers rows that exist.
 */
export function releasePublicPort(db, appId) {
  db.prepare('UPDATE apps SET public_port = NULL WHERE id = ?').run(appId);
}

/**
 * Return a flipped-away port to the pool, and report which one — or null when
 * the app was holding nothing.
 *
 * Call this ONLY once a production container has been created for this app
 * without the public publish. That is the moment the reservation exists to
 * survive: the new container does not bind the port, and the previous one — the
 * last thing that could — is necessarily gone, because `docker run` refuses a
 * duplicate --name and this runs after it succeeded. Until then the allocator
 * must keep treating the port as taken, however plainly the row says http.
 */
export function releasePendingPortAfterRecreate(db, slug) {
  const row = db.prepare('SELECT id, ingress_type, public_port FROM apps WHERE slug = ?').get(slug);
  const port = pendingPortRelease(row);
  if (port === null) return null;
  releasePublicPort(db, row.id);
  return port;
}
