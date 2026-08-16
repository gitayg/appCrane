/**
 * TCP ingress (v2.42.0) — schema helpers + the public-port allocator.
 *
 * An app with ingress_type='tcp' gets its container port published on the host
 * at 0.0.0.0:<public_port>, in ADDITION to the loopback publish every app
 * already has. Caddy is not in that path at all, which is the whole point: a
 * forward/CONNECT proxy speaks raw TCP and no HTTP reverse proxy can express
 * a tunnel.
 *
 * v2.45.0 adds a THIRD type, 'dual', for an app that is both at once: an
 * ordinary HTTP control plane served through Caddy on CONTROL_PLANE_PORT, plus
 * a raw data plane published at 0.0.0.0:<public_port> -> <data_plane_port>
 * inside the same container. See INGRESS_TYPES for why this is a type rather
 * than "an http app that happens to hold a port".
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
 * Two different questions, conflated until v2.45.0 and now separated.
 *
 * AUTO_* is the band an ALLOCATED port comes from: a dedicated block so the
 * operator's firewall rule is one predictable range instead of a per-app list.
 * That property is worth keeping for the common case, where nobody cares what
 * the number is.
 *
 * PUBLIC_PORT_* is the range an operator may explicitly NAME, and it is wide,
 * because the number is not always ours to choose. Clients get configured with
 * a host and a port — by hand, by MDM, in a product's own settings — and when
 * they already point at 8080, "use 31000 instead" is not a platform decision,
 * it is a request to go and reconfigure a fleet of clients. Refusing that is
 * how a platform gets worked around rather than used.
 *
 * Narrowing the range was never what made this safe. The real guards are in
 * assertPublicPortAssignable and apply to every port whatever its value: the
 * WHATWG blocked list, AppCrane's own listening port, Caddy's admin endpoint, a
 * collision with any slot-derived backend port, and the partial unique index
 * that stops two apps holding one number. Those matter MORE now the range is
 * wide, not less — on a platform with enough apps a number like 8080 lands on a
 * slot-derived backend port, and slotPortConflict is what catches it.
 *
 * Privileged ports stay out as POLICY, not because they would fail. The host
 * side of a `-p` publish is bound by the Docker daemon as root, so
 * `-p 0.0.0.0:81:3000` starts perfectly well (measured). The floor is here to
 * keep apps off the ports the platform itself depends on — 22, 80 and 443,
 * which Caddy needs — and stating a capability reason instead would invite a
 * future reader to "fix" it by granting a capability that was never the issue.
 */
export const AUTO_PORT_MIN = 31000;
export const AUTO_PORT_MAX = 31999;
export const PUBLIC_PORT_MIN = 1024;
export const PUBLIC_PORT_MAX = 65535;

/**
 * The container port every app's CONTROL plane listens on: AppCrane sets
 * PORT=3000 in the container and publishes 127.0.0.1:<slot port>:3000, which is
 * the binding Caddy proxies to and the health probe checks.
 *
 * Mirrors docker.js's CONTAINER_PORT, and lives here because the dependency
 * already runs docker.js -> tcpIngress.js: this module has to know the number to
 * refuse it as a data-plane port, and importing it the other way would be a
 * cycle.
 */
export const CONTROL_PLANE_PORT = 3000;

/**
 * 'dual' is a third TYPE rather than "an http app that also holds a port".
 *
 * An app can genuinely have both planes: an HTTP control plane that must keep
 * everything Caddy gives it (TLS, forward_auth, identity headers, audit) and a
 * raw data plane whose clients are already configured for a specific host port
 * and a DIFFERENT port inside the container. Stock Caddy cannot carry the second
 * one — raw TCP needs the layer4 plugin and a custom xcaddy build (BACKLOG.md) —
 * so a direct Docker publish is the passthrough.
 *
 * Modelling that as an http app with a data_plane_port set was the alternative,
 * and it was rejected for one reason: the row would say 'http' while the app
 * published a raw, unauthenticated host port. ingress_type is the field an
 * operator (and every audit entry, MCP payload and dashboard row) reads to learn
 * what doors an app has, so it has to NAME the exposure rather than leave it to
 * be inferred from a second column being non-null.
 *
 * Compatibility, both directions:
 *  - An app that sets nothing is 'http' — the column default, and effectively
 *    'http' for every pre-072 row. Nothing about it changes.
 *  - A v2.42.0 pure-tcp app keeps working unchanged: it has no control plane, so
 *    its publish still targets CONTROL_PLANE_PORT, which is where PORT=3000 tells
 *    the container to listen.
 *  - Runtime code that has not learned about 'dual' compares === 'tcp' and gets
 *    false, so a dual app falls back to the HTTP behaviour — an HTTP health
 *    probe on the control plane, which is the correct signal for it (see
 *    dataPlanePortForApp). The unhandled case degrades to the safe one.
 */
export const INGRESS_TYPES = ['http', 'tcp', 'dual'];

// v2.46.0: a published host port per environment. `env` is validated here
// rather than by a CHECK constraint, following ingress_type's precedent — see
// migration 076.
export const PUBLISHABLE_ENVS = ['production', 'sandbox'];

// The column mirroring the registry for each environment. The registry
// (app_host_ports) owns the invariant "one owner per host port, across every
// app and environment"; these columns are the fast read path, so a caller
// holding an app row does not need a query. Both are written in one
// transaction by assignPublicPort/releasePublicPort, which are the only writers.
const PORT_COLUMN = { production: 'public_port', sandbox: 'sandbox_public_port' };

export function assertPublishableEnv(env) {
  if (!PUBLISHABLE_ENVS.includes(env)) {
    throw fail(`env must be one of ${PUBLISHABLE_ENVS.join(', ')}`, 400, 'VALIDATION');
  }
  return env;
}

/** The column name for an environment — throws rather than returning undefined. */
function portColumn(env) {
  assertPublishableEnv(env);
  return PORT_COLUMN[env];
}

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
 * still read back as the behaviour the runtime actually implements — only a
 * literal member of the vocabulary gets a published host port.
 */
export function effectiveIngressType(raw) {
  return INGRESS_TYPES.includes(raw) ? raw : 'http';
}

export function validateIngressType(value) {
  if (!INGRESS_TYPES.includes(value)) {
    throw fail(`ingress_type must be one of ${INGRESS_TYPES.join(', ')}`, 400, 'VALIDATION');
  }
  return value;
}

export function isTcpApp(app) {
  return effectiveIngressType(app?.ingress_type) === 'tcp';
}

/**
 * Does this app's TYPE put a port on 0.0.0.0? True for the two publishing
 * types and nothing else. Separate from publicPortForApp() because the type is
 * what decides whether a held port is a live reservation or a leftover.
 */
export function publishesPublicPort(app) {
  const type = effectiveIngressType(app?.ingress_type);
  return type === 'tcp' || type === 'dual';
}

/**
 * The two ends of the public publish — `{ host, container }` — or null when
 * this app publishes nothing.
 *
 * Every condition here is a refusal to publish something half-specified, because
 * the failure mode of guessing is a raw port on the host:
 *  - an http app never publishes;
 *  - a publishing app whose allocation has not landed yet must not publish port
 *    `null`;
 *  - a 'dual' row whose data_plane_port is missing or is CONTROL_PLANE_PORT
 *    publishes NOTHING. Defaulting it to the control-plane port would put the
 *    HTTP origin Caddy fronts onto a public port with no TLS, no forward_auth,
 *    no identity headers and no audit — the exact surface Caddy exists to
 *    protect. The write path already rejects that value (validateDataPlanePort);
 *    this is the same guard at the runtime edge, for a row that got there some
 *    other way.
 */
function publishTargets(app, env = 'production') {
  if (!publishesPublicPort(app)) return null;
  // v2.46.0: which number is read depends on the environment, but every OTHER
  // rule is shared — the ingress type must publish, and a dual app's container
  // side must be a real port that is not the control plane. A sandbox publish
  // that skipped those checks would be a second way to expose the HTTP origin
  // raw, reached by a code path the guard tests never look at.
  const host = env === 'sandbox' ? app?.sandbox_public_port : app?.public_port;
  if (!Number.isInteger(host)) return null;
  // A pure-tcp app has no control plane to protect: the container is told
  // PORT=3000 and the whole of it is the data plane, so the publish targets
  // CONTROL_PLANE_PORT exactly as it did in v2.42.0.
  if (isTcpApp(app)) return { host, container: CONTROL_PLANE_PORT };
  const container = effectiveDataPlanePort(app);
  if (container === null || container === CONTROL_PLANE_PORT) return null;
  return { host, container };
}

/**
 * The host port to publish for this app row, or null when there is nothing to
 * publish.
 *
 * This and dataPlanePortForApp() are the pair the runtime (docker.js,
 * healthChecker.js) needs — together they answer "does this app publish, on
 * what host port, and to what port inside the container" from an app row that
 * has already been read, with no second query. A caller that publishes
 * publicPortForApp() must take the container side from dataPlanePortForApp()
 * rather than assuming CONTROL_PLANE_PORT.
 */
export function publicPortForApp(app, env = 'production') {
  return publishTargets(app, env)?.host ?? null;
}

/**
 * The CONTAINER port the public publish targets, or null when this app
 * publishes nothing. CONTROL_PLANE_PORT for a pure-tcp app, the app's own
 * data_plane_port for a dual one.
 */
export function dataPlanePortForApp(app, env = 'production') {
  return publishTargets(app, env)?.container ?? null;
}

/**
 * The data-plane port as CONFIGURED — what every read surface reports.
 *
 * Null unless the app is 'dual', on the same terms as publicPortForApp(): the
 * stored number survives a flip away from dual (so flipping back restores the
 * port clients are configured for) but must not read back as if it were in
 * effect. Unlike dataPlanePortForApp() this does not require a host-port
 * allocation to exist — a dual app between "type set" and "port allocated" has
 * a real configured data-plane port to show.
 */
export function effectiveDataPlanePort(app) {
  if (effectiveIngressType(app?.ingress_type) !== 'dual') return null;
  return Number.isInteger(app?.data_plane_port) ? app.data_plane_port : null;
}

/**
 * Throw unless `port` is a legal data-plane port.
 *
 * SECURITY: CONTROL_PLANE_PORT is refused. A data plane published at
 * 0.0.0.0:<public_port>:3000 is not a data plane at all — it is the app's HTTP
 * control plane re-published raw, without TLS, forward_auth, identity headers,
 * rate limiting or a single audit entry, and the operator who typed it would
 * have no signal that they had done it. That is precisely what Caddy is in the
 * path for.
 *
 * The lower bound IS a policy choice, and the numbers are PUBLIC_PORT_MIN/MAX
 * only because they happen to coincide. A container process here can bind a
 * privileged port perfectly well — AppCrane drops only NET_RAW and passes no
 * --user, so the root process inside keeps CAP_NET_BIND_SERVICE (measured: a
 * container under these exact flags binds :80). The floor exists so a data
 * plane cannot be pointed at the ports the platform's own conventions reserve.
 *
 * The WHATWG blocked list deliberately does NOT apply: it exists because Node's
 * fetch() refuses those ports, and nothing fetches the data plane — the health
 * probe stays on the control plane, and the clients are not undici.
 */
export function validateDataPlanePort(value) {
  if (!Number.isInteger(value)) {
    throw fail('data_plane_port must be an integer', 400, 'VALIDATION');
  }
  if (value < PUBLIC_PORT_MIN || value > PUBLIC_PORT_MAX) {
    throw fail(`data_plane_port must be between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}`, 400, 'VALIDATION');
  }
  if (value === CONTROL_PLANE_PORT) {
    throw fail(
      `data_plane_port cannot be ${CONTROL_PLANE_PORT}: that is the container's HTTP control plane, ` +
      'the port Caddy proxies to. Publishing it raw on the host would expose the app\'s ordinary ' +
      'HTTP origin with no TLS, no forward_auth, no identity headers and no request audit. Give the ' +
      'data plane its own listener on another port inside the container.',
      400, 'VALIDATION',
    );
  }
  return value;
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
/**
 * Every port this app still has RESERVED but no longer publishes, per
 * environment — the numbers a running container is bound to that AppCrane will
 * hand back once it is recreated. v2.47.0.
 *
 * Two ways to get here, and they are the same state:
 *   - flipped to http, so the type no longer publishes anything (the original
 *     pendingPortRelease case), and
 *   - re-pinned to a different number, which leaves the old one draining.
 *
 * Reported so an operator is never told a port is closed while it answers.
 */
export function drainingPorts(db, appId, env = null) {
  const rows = env
    ? db.prepare("SELECT host_port, env FROM app_host_ports WHERE app_id = ? AND env = ? AND state = 'draining' ORDER BY host_port").all(appId, env)
    : db.prepare("SELECT host_port, env FROM app_host_ports WHERE app_id = ? AND state = 'draining' ORDER BY host_port").all(appId);
  return rows;
}

export function pendingPortRelease(app) {
  // Keyed on the TYPE, not on publishTargets(): an app whose type still
  // publishes is holding its port on purpose, even in an intermediate state
  // where nothing is published yet (allocation not landed, dual without a data
  // plane port). Only a flip to http makes the number a leftover.
  if (publishesPublicPort(app)) return null;
  return Number.isInteger(app?.public_port) ? app.public_port : null;
}

/**
 * Same answer for callers that hold only an app id.
 *
 * data_plane_port is in the SELECT because publicPortForApp() routes through
 * publishTargets(), which needs it to answer for a 'dual' row: without the
 * column every dual app read through here reported public_port null while it
 * was in fact publishing, so this was not the same answer at all.
 */
export function getIngressForApp(db, appId) {
  const row = db.prepare('SELECT ingress_type, public_port, data_plane_port FROM apps WHERE id = ?').get(appId);
  return {
    ingress_type: effectiveIngressType(row?.ingress_type),
    public_port: publicPortForApp(row),
  };
}

function cranePort() {
  return Number(process.env.PORT || 5001);
}

/**
 * Caddy's admin endpoint, the port reloadCaddy() POSTs the new config to. Same
 * default and same env var as caddy.js, so the two cannot disagree about which
 * port that is.
 *
 * SECURITY / AVAILABILITY: this became reachable in v2.45.0. While an explicit
 * public_port had to come from 31000-31999 the number was structurally out of
 * play; the widened 1024-65535 range put it back on the table, and none of the
 * other guards catch it — 2019 is not on the WHATWG list, and slotPortConflict
 * skips it because both slot offsets are negative. On Linux a `docker run -p
 * 0.0.0.0:2019` cannot bind while Caddy holds 127.0.0.1:2019 (measured: EADDRINUSE),
 * so the app's deploy dies with "port is already allocated" — and if the
 * container wins the race instead, Caddy's admin API cannot bind on restart and
 * every reloadCaddy() fails afterwards, for every app on the platform, with
 * nothing pointing at the cause.
 */
function caddyAdminPort() {
  const url = process.env.CADDY_ADMIN_URL || 'http://localhost:2019';
  const parsed = Number(new URL(url).port);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 2019;
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
export function assertPublicPortAssignable(db, port, appId, env = 'production') {
  assertPublishableEnv(env);
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
  if (port === caddyAdminPort()) {
    throw fail(
      `Port ${port} is Caddy's admin endpoint — the port AppCrane reloads every app's routing through`,
      409, 'PORT_RESERVED',
    );
  }
  const slotClash = slotPortConflict(db, port);
  if (slotClash) {
    throw fail(`Port ${port} is reserved for app slot ${slotClash.slot} (${slotClash.key})`, 409, 'PORT_RESERVED');
  }
  // v2.46.0: asked of the REGISTRY rather than of apps.public_port, because the
  // question is now "does anything own this port" across every app AND every
  // environment. Checking a single column would let app A's sandbox port equal
  // app B's production port with every constraint satisfied, and the collision
  // would surface as a failed `docker run` mid-deploy naming a port that looks
  // unclaimed in the dashboard.
  const taken = db.prepare(`
    SELECT a.slug, p.env FROM app_host_ports p
    JOIN apps a ON a.id = p.app_id
    WHERE p.host_port = ? AND NOT (p.app_id = ? AND p.env = ?)
  `).get(port, appId, env);
  if (taken) {
    throw fail(
      `Port ${port} is already published by app "${taken.slug}" (${taken.env})`,
      409, 'PORT_TAKEN');
  }
  return port;
}

/**
 * Lowest free port in the range. Lowest-first keeps allocations dense and
 * predictable, so an operator reading `ss -lntp` can tell at a glance which
 * ports are in play.
 */
export function allocatePublicPort(db, appId, env = 'production') {
  // The AUTO band, not the full assignable range: an allocated port should land
  // in the predictable block an operator has already opened. Naming a port
  // outside it is an explicit act, and stays one.
  for (let port = AUTO_PORT_MIN; port <= AUTO_PORT_MAX; port++) {
    try {
      assertPublicPortAssignable(db, port, appId, env);
      return port;
    } catch (_) {
      continue;
    }
  }
  throw fail(
    `No free public port in the auto range ${AUTO_PORT_MIN}-${AUTO_PORT_MAX}. Release a published app's ` +
    `port, or name a port explicitly — an operator may choose any port in ${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}.`,
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
export function assignPublicPort(db, appId, requested = null, env = 'production') {
  const col = portColumn(env);
  // Registry and column are written together, always, by this function and
  // releasePublicPort — nothing else touches either. The registry carries the
  // invariant; the column is the read path that keeps /api/apps from querying
  // once per app.
  // Only the PINNED row is replaced. A draining row is a port a live container
  // is still bound to; deleting it here would return that number to the pool
  // while it is answering, which is the whole hazard this mechanism exists to
  // avoid.
  const claim = (port) => {
    db.prepare("DELETE FROM app_host_ports WHERE app_id = ? AND env = ? AND state = 'pinned'")
      .run(appId, env);
    db.prepare("INSERT INTO app_host_ports (host_port, app_id, env, state) VALUES (?, ?, ?, 'pinned')")
      .run(port, appId, env);
    db.prepare(`UPDATE apps SET ${col} = ? WHERE id = ?`).run(port, appId);
  };
  return db.transaction(() => {
    const row = db.prepare(`SELECT ${col} AS held, ingress_type FROM apps WHERE id = ?`).get(appId);
    if (requested === null) {
      if (Number.isInteger(row?.held)) return row.held;
      const port = allocatePublicPort(db, appId, env);
      claim(port);
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
    const held = row?.held;
    // Asked per environment: a live PRODUCTION deployment does not mean the
    // sandbox container is bound to the sandbox port, and refusing a sandbox
    // re-pin because production happens to be up would block the case this
    // feature exists for — trying a port in sandbox before committing to it.
    const published = Number.isInteger(held) && publishesPublicPort(row)
      && !!db.prepare(
        'SELECT 1 FROM deployments WHERE app_id = ? AND env = ? AND status = \'live\' LIMIT 1'
      ).get(appId, env);
    if (published && held !== requested) {
      // v2.47.0: tracked, not refused. The old number stays OWNED — moved to
      // 'draining' rather than deleted — so the allocator still cannot give it
      // to anyone while the running container answers on it, and the existing
      // release-on-recreate hook drops it the moment that container is gone.
      // Until v2.46.0 there was nowhere to record this, which is why an
      // operator was sent through flip-to-http, redeploy, re-pin instead.
      const moved = db.prepare(
        "UPDATE app_host_ports SET state = 'draining' WHERE app_id = ? AND env = ? AND state = 'pinned'"
      ).run(appId, env).changes;
      if (moved === 0) {
        // The COLUMN held a port the registry never recorded. `held` was read
        // from the column, so this is reachable whenever the two disagree — a
        // row written directly, a restored backup, a value that predates the
        // registry. Updating nothing and carrying on would forget the number
        // entirely, which is precisely the hazard: a live container answers on
        // it and the allocator is free to hand it to someone else. Reserve it.
        db.prepare(
          "INSERT OR IGNORE INTO app_host_ports (host_port, app_id, env, state) VALUES (?, ?, ?, 'draining')"
        ).run(held, appId, env);
      }
    }
    assertPublicPortAssignable(db, requested, appId, env);
    claim(requested);
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
export function releasePublicPort(db, appId, env = 'production') {
  const col = portColumn(env);
  db.transaction(() => {
    db.prepare('DELETE FROM app_host_ports WHERE app_id = ? AND env = ?').run(appId, env);
    db.prepare(`UPDATE apps SET ${col} = NULL WHERE id = ?`).run(appId);
  })();
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
export function releasePendingPortAfterRecreate(db, slug, env = 'production') {
  const row = db.prepare('SELECT id, ingress_type, public_port FROM apps WHERE slug = ?').get(slug);
  if (!row) return null;
  const freed = [];

  // v2.47.0: draining rows first. The container that was binding them has just
  // been replaced by one that is not, so the reservation has done its job and
  // the numbers go back in the pool. This is the half that makes a re-pin a
  // single step — the operator changes the number, redeploys, and the old one
  // frees itself.
  const draining = drainingPorts(db, row.id, env);
  if (draining.length) {
    db.prepare("DELETE FROM app_host_ports WHERE app_id = ? AND env = ? AND state = 'draining'")
      .run(row.id, env);
    freed.push(...draining.map(d => d.host_port));
  }

  // The original case: flipped to http, so the pinned number is a leftover too.
  // Production-only, as before — pendingPortRelease reads apps.public_port.
  if (env === 'production') {
    const port = pendingPortRelease(row);
    if (port !== null) {
      releasePublicPort(db, row.id, 'production');
      freed.push(port);
    }
  }
  return freed.length ? freed : null;
}
