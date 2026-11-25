import {
  PUBLISHABLE_ENVS, publicPortForApp, effectiveDataPlaneProtocol, storedDataPlaneProtocol,
  publishesPublicPort, pendingPortRelease,
} from '../tcpIngress.js';
import { sortEntries, validEntry } from './rules.js';
import { isPublicAddr } from './hostNet.js';

// What APPCRANE-PUBLISH should ACCEPT, from AppCrane's own state, cross-checked
// against what Docker actually publishes.

export const DOCKER_PS_ARGS = Object.freeze([
  'ps', '--format', '{{.Names}}|{{.Label "appcrane"}}|{{.Label "slug"}}|{{.Label "env"}}|{{.Ports}}',
]);

const LOOPBACK = (ip) => ip === '::1' || /^127\./.test(ip);

/**
 * Every binding in a `{{.Ports}}` cell that is reachable off the host:
 *   "127.0.0.1:4013->3000/tcp, 0.0.0.0:31001->5080/udp, [::]:31001->5080/udp"
 * Loopback and EXPOSE-only entries are dropped; a range expands to its ports.
 */
export function parsePublicBindings(cell) {
  const out = [];
  for (const part of String(cell || '').split(',')) {
    const m = /^(\[[^\]]*\]|[0-9.]+|::|:::?)?:(\d+)(?:-(\d+))?->(\d+)(?:-\d+)?\/(tcp|udp|sctp)$/.exec(part.trim());
    if (!m) continue;
    const ip = (m[1] || '').replace(/^\[|\]$/g, '') || '::';
    if (LOOPBACK(ip)) continue;
    const from = Number(m[2]);
    const to = m[3] ? Number(m[3]) : from;
    for (let p = from; p <= to && p - from < 1024; p++) out.push({ hostIp: ip, port: p, proto: m[5] });
  }
  return out;
}

export function parseDockerPs(text) {
  const rows = [];
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    const [name, appcrane, slug, env, ports] = line.split('|');
    rows.push({ name, appcrane: appcrane === 'true', slug: slug || null, env: env || null, bindings: parsePublicBindings(ports) });
  }
  return rows;
}

/** { ok, containers } from `docker ps`; ok:false when Docker could not be read. */
export async function readDockerPublishes(run) {
  const r = await run('docker', [...DOCKER_PS_ARGS]);
  if (r.code !== 0) return { ok: false, containers: [], error: (r.error || r.stderr || 'docker ps failed').split('\n')[0].slice(0, 200) };
  return { ok: true, containers: parseDockerPs(r.stdout) };
}

/**
 * Ports AppCrane's database says are bound on 0.0.0.0:
 *  - published: an app whose type publishes, per environment, with the
 *    protocol docker.js passes to `-p`;
 *  - reserved: a port still held for a container that has not been recreated
 *    yet (pending_port_release after a flip to http, a sandbox port after the
 *    same flip, and every 'draining' row after a re-pin). The running container
 *    still binds it, so its clients must keep reaching it until the recreate.
 */
export function dbPorts(db) {
  const apps = db.prepare(`SELECT id, slug, ingress_type, public_port, sandbox_public_port,
                                  data_plane_port, data_plane_protocol FROM apps`).all();
  const bySlug = new Map(apps.map(a => [a.id, a]));
  const out = [];
  for (const app of apps) {
    for (const env of PUBLISHABLE_ENVS) {
      const port = publicPortForApp(app, env);
      if (port !== null) out.push({ slug: app.slug, env, port, proto: effectiveDataPlaneProtocol(app), reason: 'published' });
    }
    const pending = pendingPortRelease(app);
    if (pending !== null) out.push({ slug: app.slug, env: 'production', port: pending, proto: storedDataPlaneProtocol(app), reason: 'pending_port_release' });
    if (!publishesPublicPort(app) && Number.isInteger(app.sandbox_public_port)) {
      out.push({ slug: app.slug, env: 'sandbox', port: app.sandbox_public_port, proto: storedDataPlaneProtocol(app), reason: 'pending_port_release' });
    }
  }
  const draining = db.prepare("SELECT app_id, env, host_port FROM app_host_ports WHERE state = 'draining'").all();
  for (const d of draining) {
    const app = bySlug.get(d.app_id);
    if (app) out.push({ slug: app.slug, env: d.env, port: d.host_port, proto: storedDataPlaneProtocol(app), reason: 'draining' });
  }
  return out;
}

const containerFor = (slug, env) => `appcrane-${slug}-${env}`;

/**
 * { accept: [{proto, port, slug, env, reason}], strays: [...], docker: 'read'|'unreadable' }.
 *
 * A stray is a public binding (a wildcard, or an address on the default
 * route's interface; see hostNet.isPublicAddr) that no database row gives to
 * the container holding it. A binding on the bridge gateway or another
 * private interface, such as a managed database server, is never a stray.
 * A stray is an unknown port, or a known port held by a different
 * container. A stray port is never accepted, even when a row names it: the
 * rule matches the port, not the container, so accepting it would admit
 * whichever container actually holds it.
 *
 * A published port is accepted on the protocol docker.js passes to `-p`, and
 * also on any protocol its own container still holds it on (a protocol change
 * not yet recreated). A reserved port is accepted only on what its container
 * actually holds when Docker can be read; the stored protocol is the fallback.
 */
export function computeDesired(rows, dockerRead, net = null) {
  const read = dockerRead?.ok === true;
  const containers = read ? dockerRead.containers : [];
  const held = new Map();
  for (const c of containers) {
    for (const b of c.bindings) {
      const k = `${b.proto}/${b.port}`;
      if (!held.has(k)) held.set(k, new Set());
      held.get(k).add(c.name);
    }
  }

  const owners = new Map();
  const add = (row, proto) => {
    const k = `${proto}/${row.port}`;
    if (!owners.has(k)) owners.set(k, { proto, port: row.port, slug: row.slug, env: row.env, reason: row.reason });
  };
  for (const row of rows) {
    if (!validEntry(row)) continue;
    if (row.reason === 'published' || !read) add(row, row.proto);
    if (!read) continue;
    const name = containerFor(row.slug, row.env);
    for (const p of ['tcp', 'udp']) {
      if (held.get(`${p}/${row.port}`)?.has(name)) add(row, p);
    }
  }

  const strays = [];
  const blocked = new Set();
  for (const c of containers) {
    for (const b of c.bindings) {
      if (!isPublicAddr(b.hostIp, net)) continue;
      const k = `${b.proto}/${b.port}`;
      const owner = owners.get(k);
      const ownerName = owner ? containerFor(owner.slug, owner.env) : null;
      if (owner && ownerName === c.name) continue;
      blocked.add(k);
      if (!strays.some(s => s.container === c.name && s.proto === b.proto && s.port === b.port)) {
        strays.push({
          container: c.name, appcrane: c.appcrane, proto: b.proto, port: b.port, host_ip: b.hostIp,
          claimed_by: owner ? { slug: owner.slug, env: owner.env } : null,
        });
      }
    }
  }

  const accept = [...owners.entries()]
    .filter(([k]) => !blocked.has(k))
    .map(([, v]) => v);
  const order = new Map(sortEntries(accept).map((e, i) => [`${e.proto}/${e.port}`, i]));
  accept.sort((a, b) => order.get(`${a.proto}/${a.port}`) - order.get(`${b.proto}/${b.port}`));
  strays.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto) || a.container.localeCompare(b.container));
  return { accept, strays, docker: read ? 'read' : 'unreadable', docker_error: read ? null : (dockerRead?.error || null) };
}
