import { SANDBOX_TENANT } from '../sandboxDb.js';
import { POLICY_ENGINES } from '../managedDbTls.js';
import { validPort, familyOf } from './dbRules.js';

// Which containers may open a connection to which managed database port, from
// AppCrane's own state. Only app environment containers are ever given a
// managed database credential (deployer.injectManagedDbForEnv, for deploys,
// restarts and recreates); AppCrane itself connects over 127.0.0.1 or docker
// exec, which never passes FORWARD.
//
// A row's scope decides which environment's container gets its credential:
//   tenant ''        production; sandbox too when the sandbox container was
//                    started in the shared scope
//   tenant sandbox   a sandbox container started in the sandbox scope;
//                    production too on postgres and mariadb, the
//                    engines a deployhub.json sandbox_url_env can hand it
//                    (managedDb.sandboxPeerAccess)
//   any other tenant no container is given it
// A shared server's port gets the union over every row on that engine; which
// database a login reaches stays the engine's job. A per-scope Redis port gets
// only its own row's containers.

export const SHARED_ENGINES = Object.freeze(['postgres', 'mariadb', 'mongo']);
export const APP_ENVS = Object.freeze(['production', 'sandbox']);

export const containerFor = (slug, env) => `appcrane-${slug}-${env}`;
export const anchorFor = (slug, env) => `crane-egress-anchor.${slug}.${env}`;

// The scope a container was started with is the label the run wrote
// (appcrane.db-scope=<tenant>, '' for the shared scope). A container started
// before the label existed falls back to the current setting: production is
// shared; sandbox is its own scope under "Separate sandbox database", and
// otherwise either scope, since a deployhub.json database is always separate
// in sandbox and that is not stored.
export const DB_SCOPE_LABEL = 'appcrane.db-scope';
export const fallbackScopes = (env, separate) => (env !== 'sandbox' ? [''] : separate === 1 ? [SANDBOX_TENANT] : ['', SANDBOX_TENANT]);

// Each candidate holds the row's credential when its scope is the row's
// tenant; peer: production on postgres and mariadb holds the sandbox row's
// credential too (sandbox_url_env), whatever its own scope.
function candidatesForRow(row) {
  const tenant = row.tenant || '';
  const sep = row.separate_sandbox_db === 1 ? 1 : 0;
  const c = (env, peer = false) => ({ name: containerFor(row.slug, env), slug: row.slug, env, tenant, peer, fallback: fallbackScopes(env, sep) });
  if (tenant === '') return [c('production'), c('sandbox')];
  if (tenant === SANDBOX_TENANT) return POLICY_ENGINES.includes(row.engine) ? [c('sandbox'), c('production', true)] : [c('sandbox')];
  return [];
}

/** [{ port, engine, kind: 'shared'|'redis', owner, candidates: [{name, slug, env, tenant, peer, fallback}] }] sorted by port. */
export function dbPortSpecs(db) {
  const servers = db.prepare('SELECT engine, host_port FROM managed_db_servers').all()
    .filter(s => SHARED_ENGINES.includes(s.engine) && validPort(Number(s.host_port)));
  const rows = db.prepare(`SELECT d.app_id, d.tenant, d.engine, d.host_port, a.slug,
                                  COALESCE(s.separate_sandbox_db, 0) AS separate_sandbox_db
                             FROM managed_databases d
                             JOIN apps a ON a.id = d.app_id
                        LEFT JOIN app_settings s ON s.app_id = d.app_id`).all();
  const specs = new Map();
  const spec = (port, engine, kind, owner) => {
    if (!specs.has(port)) specs.set(port, { port, engine, kind, owner, candidates: [] });
    return specs.get(port);
  };
  for (const s of servers) spec(Number(s.host_port), s.engine, 'shared', null);
  const sharedPort = new Map(servers.map(s => [s.engine, Number(s.host_port)]));
  for (const r of rows) {
    let target = null;
    if (r.engine === 'redis') {
      if (!validPort(Number(r.host_port))) continue;
      target = spec(Number(r.host_port), 'redis', 'redis', { slug: r.slug, tenant: r.tenant || '' });
    } else if (sharedPort.has(r.engine)) {
      target = specs.get(sharedPort.get(r.engine));
    }
    if (target) target.candidates.push(...candidatesForRow(r));
  }
  return [...specs.values()].sort((a, b) => a.port - b.port);
}

/** The containers that hold a credential for this port: [{name, slug, env, scope, scope_source}] by name. */
export function resolveContainers(spec, addrs) {
  const out = new Map();
  for (const c of spec.candidates) {
    const labelled = addrs.get(c.name)?.scope;
    const scopes = typeof labelled === 'string' ? [labelled] : c.fallback;
    if (!c.peer && !scopes.includes(c.tenant)) continue;
    if (!out.has(c.name)) out.set(c.name, { name: c.name, slug: c.slug, env: c.env, scope: typeof labelled === 'string' ? labelled : null, scope_source: typeof labelled === 'string' ? 'label' : 'setting' });
  }
  return [...out.values()].sort((x, y) => x.name.localeCompare(y.name));
}

/** Every container name any port may allow, for one Docker read. */
export function candidateNames(specs) {
  return [...new Set(specs.flatMap(s => s.candidates.map(c => c.name)))];
}

export const PS_ARGS = Object.freeze(['ps', '-a', '--no-trunc', '--format', '{{.Names}}']);
export const INSPECT_FORMAT = '{{.Id}}|{{.Name}}|{{.State.Status}}|{{.HostConfig.NetworkMode}}|{{range .NetworkSettings.Networks}}{{.IPAddress}},{{.GlobalIPv6Address}};{{end}}|{{range $k, $v := .Config.Labels}}{{if eq $k "' + DB_SCOPE_LABEL + '"}}={{$v}}{{end}}{{end}}';
const LIVE = new Set(['running', 'restarting', 'paused']);

/** Docker's inspect lines -> Map name -> { id, status, mode, ips, scope (null: no label) }. */
export function parseInspect(text) {
  const out = new Map();
  for (const line of String(text || '').split('\n')) {
    const [id, rawName, status, mode, nets, ...label] = line.trim().split('|');
    if (!id || !rawName) continue;
    const ips = [];
    for (const pair of String(nets || '').split(';')) {
      for (const ip of pair.split(',')) if (familyOf(ip.trim())) ips.push(ip.trim());
    }
    const l = label.join('|');
    out.set(rawName.replace(/^\//, ''), { id, status, mode: mode || '', ips, scope: l.startsWith('=') ? l.slice(1) : null });
  }
  return out;
}

/**
 * The addresses each candidate container connects from:
 *   Map name -> { state: 'absent'|'stopped'|'ip'|'unknown', ips }
 * An egress-enforced app runs in its anchor's network namespace
 * (--network container:<anchor>), so its addresses are the anchor's. 'unknown'
 * is a container that is running but whose address could not be read, and
 * every container when Docker could not be read at all.
 */
export async function readContainerAddrs(run, names) {
  const out = new Map();
  const unknown = (why) => { for (const n of names) out.set(n, { state: 'unknown', ips: [], why }); return out; };
  if (!names.length) return out;
  const ps = await run('docker', [...PS_ARGS]);
  if (ps.code !== 0) return unknown((ps.error || ps.stderr || 'docker ps failed').trim().split('\n')[0]);
  const exists = new Set(String(ps.stdout).split('\n').map(s => s.trim()).filter(Boolean));
  const wanted = new Set();
  for (const n of names) {
    if (!exists.has(n)) continue;
    wanted.add(n);
    const m = /^appcrane-(.+)-(production|sandbox)$/.exec(n);
    if (m && exists.has(anchorFor(m[1], m[2]))) wanted.add(anchorFor(m[1], m[2]));
  }
  let facts = new Map();
  let inspectError = null;
  if (wanted.size) {
    const r = await run('docker', ['inspect', '--format', INSPECT_FORMAT, ...wanted]);
    facts = parseInspect(r.stdout);
    if (r.code !== 0) inspectError = (r.error || r.stderr || 'docker inspect failed').trim().split('\n')[0];
  }
  const byId = new Map([...facts.values()].map(f => [f.id, f]));
  for (const n of names) {
    if (!exists.has(n)) { out.set(n, { state: 'absent', ips: [] }); continue; }
    const f = facts.get(n);
    if (!f) { out.set(n, { state: 'unknown', ips: [], why: inspectError || 'not in docker inspect output' }); continue; }
    if (!LIVE.has(f.status)) { out.set(n, { state: 'stopped', ips: [], scope: f.scope }); continue; }
    let ips = f.ips;
    if (f.mode.startsWith('container:')) {
      const ref = f.mode.slice('container:'.length);
      const peer = byId.get(ref) || facts.get(ref);
      ips = peer ? peer.ips : [];
    }
    out.set(n, ips.length ? { state: 'ip', ips: [...new Set(ips)].sort(), scope: f.scope } : { state: 'unknown', ips: [], scope: f.scope, why: 'running with no address Docker reports' });
  }
  return out;
}

/**
 * The chain plan: one entry per managed database port.
 *   state 'closed'  every container that should reach it has a known address
 *                   (or none is running); allow lists those addresses.
 *   state 'open'    at least one is starting (pending) or its address is
 *                   unknown: no lines for this port, so it fails open.
 */
export function computeDbPlan(specs, addrs, pending = new Set()) {
  return specs.map((s) => {
    const allow = new Set();
    const waiting = [];
    let running = 0;
    const containers = resolveContainers(s, addrs);
    for (const name of new Set(s.candidates.map(c => c.name))) {
      if (pending.has(name)) waiting.push({ container: name, why: 'starting' });
    }
    for (const c of containers) {
      if (pending.has(c.name)) continue;
      const a = addrs.get(c.name) || { state: 'unknown', ips: [], why: 'not read' };
      if (a.state === 'unknown') { waiting.push({ container: c.name, why: a.why || 'address unknown' }); continue; }
      if (a.state !== 'ip') continue;
      running += 1;
      for (const ip of a.ips) allow.add(ip);
    }
    return {
      port: s.port, engine: s.engine, kind: s.kind, owner: s.owner,
      state: waiting.length ? 'open' : 'closed',
      allow: waiting.length ? [] : [...allow].sort(),
      allowed_containers: running,
      expected: containers.map(c => c.name),
      scopes: Object.fromEntries(containers.map(c => [c.name, { scope: c.scope, source: c.scope_source }])),
      open_because: waiting,
    };
  });
}
