// The app capabilities a platform admin may require approval for, and the
// rules each one is checked by.
//
// Every entry has the same shape:
//   label, description         what the dashboard and the MCP tool show
//   defaultApprovalRequired    the policy until a platform admin changes it
//                              (settings key capability_approval_required:<id>)
//   whenOff                    what happens when approval is not required: the
//                              rule that applied before approvals existed
//   onExpiry / onRevoke        'revoke' removes the setting the grant covered,
//                              'flag' leaves it in place and only ends the grant
//   normalizeScope(input)      the validated scope of a request; throws a 400
//   covers(scopes, needed)     whether the active grants authorize `needed`
//                              (needed has the same shape as a scope)
//   example                    a scope to show in "how to request" messages
//
// AI use Annex III is listed for completeness but is not requestable here: it
// is already gated by the intake review (services/aiAct/classification.js), and
// a second gate would be a second place to approve the same thing.

import { AppError } from '../../utils/errors.js';
import { validateBypassPaths } from '../../utils/authBypassPaths.js';
import { AUTO_PORT_MIN, AUTO_PORT_MAX, PUBLIC_PORT_MIN, PUBLIC_PORT_MAX } from '../tcpIngress.js';

const ENGINES = ['postgres', 'mariadb', 'mongo', 'redis'];
const SECRET_PROVIDERS = ['vault', 'infisical', 'onepassword', 'awsssm'];
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const bad = (msg) => new AppError(msg, 400, 'VALIDATION');

function objectOf(input) {
  if (input == null) return {};
  if (typeof input !== 'object' || Array.isArray(input)) throw bad('scope must be an object');
  return input;
}

function onlyKeys(scope, keys) {
  const extra = Object.keys(scope).find((k) => !keys.includes(k));
  if (extra) throw bad(`scope.${extra} is not a field of this capability (allowed: ${keys.join(', ') || 'none'})`);
}

function listOf(scope, key, allowed, { max = 20 } = {}) {
  const v = scope[key];
  if (!Array.isArray(v) || v.length === 0) throw bad(`scope.${key} must be a non-empty array`);
  if (v.length > max) throw bad(`scope.${key} may name at most ${max} entries`);
  const out = [];
  for (const raw of v) {
    const s = String(raw ?? '').trim().toLowerCase();
    if (!allowed(s)) throw bad(`scope.${key}: ${JSON.stringify(raw)} is not allowed`);
    if (!out.includes(s)) out.push(s);
  }
  return out.sort();
}

function unionOf(scopes, key) {
  const all = new Set();
  for (const s of scopes) for (const v of s?.[key] || []) all.add(v);
  return all;
}

const flagOnly = { normalizeScope: (input) => { onlyKeys(objectOf(input), []); return {}; }, covers: (scopes) => scopes.length > 0 };

function portOrNull(scope, key) {
  const v = scope[key];
  if (v === undefined || v === null) return null;
  if (!Number.isInteger(v) || v < PUBLIC_PORT_MIN || v > PUBLIC_PORT_MAX) {
    throw bad(`scope.${key} must be an integer between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}, or null`);
  }
  return v;
}

const inAutoBand = (p) => Number.isInteger(p) && p >= AUTO_PORT_MIN && p <= AUTO_PORT_MAX;

function portScope(input) {
  const s = objectOf(input);
  onlyKeys(s, ['ingress_type', 'public_port', 'sandbox_public_port', 'data_plane_port', 'data_plane_protocol']);
  if (!['tcp', 'dual'].includes(s.ingress_type)) throw bad("scope.ingress_type must be 'tcp' or 'dual'");
  const protocol = s.data_plane_protocol ?? 'tcp';
  if (!['tcp', 'udp'].includes(protocol)) throw bad("scope.data_plane_protocol must be 'tcp' or 'udp'");
  if (s.ingress_type !== 'dual' && (s.data_plane_port != null || protocol !== 'tcp')) {
    throw bad("scope.data_plane_port and a udp data_plane_protocol apply only to ingress_type 'dual'");
  }
  return {
    ingress_type: s.ingress_type,
    public_port: portOrNull(s, 'public_port'),
    sandbox_public_port: portOrNull(s, 'sandbox_public_port'),
    data_plane_port: s.ingress_type === 'dual' ? portOrNull(s, 'data_plane_port') : null,
    data_plane_protocol: protocol,
  };
}

// One grant must cover the whole ingress shape: two half-matching grants do
// not add up to an approval of the combination nobody looked at.
function portCovered(g, n) {
  if (g.ingress_type !== n.ingress_type) return false;
  if (g.public_port == null ? !(n.public_port == null || inAutoBand(n.public_port)) : g.public_port !== n.public_port) return false;
  if (n.sandbox_public_port != null && g.sandbox_public_port !== n.sandbox_public_port) return false;
  if (n.ingress_type === 'dual' && g.data_plane_port != null && g.data_plane_port !== n.data_plane_port) return false;
  return (g.data_plane_protocol || 'tcp') === (n.data_plane_protocol || 'tcp');
}

const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
export const CONNECTION_PREFIX = 'connection:';
export const CONNECTION_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** A normalized path prefix: starts with '/', no '..', '.', '//', backslash, '%' or control characters. */
export function normalizePathPrefix(raw) {
  const p = String(raw ?? '').trim();
  if (!p.startsWith('/') || p.length > 512) return null;
  if (/[\\%?#\u0000-\u001f\u007f]/.test(p) || p.includes('//')) return null;
  if (p.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  return p;
}

/** Whether `path` (already normalized) falls under `prefix`: on a segment boundary unless the prefix ends with '/'. */
export function pathUnder(prefix, path) {
  if (prefix === '/' || prefix.endsWith('/')) return path.startsWith(prefix);
  return path === prefix || path.startsWith(`${prefix}/`);
}

function connectionScope(input) {
  const s = objectOf(input); onlyKeys(s, ['methods', 'path_prefixes']);
  const methods = listOf({ methods: Array.isArray(s.methods) ? s.methods.map((m) => String(m ?? '').toLowerCase()) : s.methods }, 'methods', (m) => HTTP_METHODS.includes(m.toUpperCase()), { max: HTTP_METHODS.length })
    .map((m) => m.toUpperCase()).sort();
  const raw = s.path_prefixes;
  if (!Array.isArray(raw) || raw.length === 0) throw bad('scope.path_prefixes must be a non-empty array');
  if (raw.length > 50) throw bad('scope.path_prefixes may name at most 50 entries');
  const prefixes = [];
  for (const r of raw) {
    const p = normalizePathPrefix(r);
    if (!p) throw bad(`scope.path_prefixes: ${JSON.stringify(r)} must start with '/' and hold no '..', '//', '%', '?', '#' or backslash`);
    if (!prefixes.includes(p)) prefixes.push(p);
  }
  return { methods, path_prefixes: prefixes.sort() };
}

// One grant must allow the method AND the path: a GET-only grant on /a and a
// POST grant on /b do not add up to POST on /a.
function connectionCovers(scopes, n) {
  return n.methods.every((m) => n.path_prefixes.every((p) => scopes.some((g) => (g.methods || []).includes(m)
    && (g.path_prefixes || []).some((gp) => pathUnder(gp, p)))));
}

const connectionDefs = new Map();
function connectionCapability(name) {
  if (!connectionDefs.has(name)) {
    connectionDefs.set(name, Object.freeze({
      label: `Connection: ${name}`,
      description: `The app calls the platform connection '${name}' through /api/service/connections/${name}/; AppCrane adds the credential. Scope: HTTP methods and path prefixes.`,
      defaultApprovalRequired: true,
      alwaysRequired: true,
      whenOff: 'never: a connection is reachable only within an approved grant',
      onExpiry: 'revoke', onRevoke: 'revoke',
      example: { methods: ['GET'], path_prefixes: ['/'] },
      connection: name,
      normalizeScope: connectionScope,
      covers: connectionCovers,
    }));
  }
  return connectionDefs.get(name);
}

// Egress hosts: a DNS name, '*.' plus a suffix (subdomains only, not the apex),
// either with ':port', or '*' for any public host. No IP literals: the proxy
// refuses them, so a grant naming one would authorize nothing.
const HOST_ENTRY_RE = /^(\*\.)?(?=.{1,253}(:|$))([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(:([1-9][0-9]{0,4}))?$/;
export function parseHostEntry(entry) {
  if (entry === '*') return { any: true };
  const m = HOST_ENTRY_RE.exec(entry);
  if (!m) return null;
  const port = m[6] ? Number(m[6]) : null;
  if (port !== null && port > 65535) return null;
  const host = entry.replace(/:[0-9]+$/, '');
  return { wildcard: host.startsWith('*.'), host: host.replace(/^\*\./, ''), port };
}

/** Whether host:port is allowed by one entry. An entry without a port allows 80 and 443. */
export function hostEntryAllows(entry, host, port) {
  const e = parseHostEntry(entry);
  if (!e) return false;
  if (e.any) return port === 80 || port === 443;
  if (e.port === null ? !(port === 80 || port === 443) : e.port !== port) return false;
  return e.wildcard ? host.endsWith(`.${e.host}`) : host === e.host;
}

export const CAPABILITIES = Object.freeze({
  managed_database: {
    label: 'Managed database',
    description: 'A database on the platform\'s shared Postgres, MariaDB or MongoDB server, or a Redis instance. Scope: which engines.',
    // Self-service by default (operator decision): listed so a platform admin
    // can see it, audit it and switch approval on.
    defaultApprovalRequired: false,
    whenOff: 'any assigned app user may provision one',
    onExpiry: 'flag', onRevoke: 'flag',
    example: { engines: ['postgres'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['engines']);
      return { engines: listOf(s, 'engines', (e) => ENGINES.includes(e), { max: ENGINES.length }) };
    },
    covers: (scopes, n) => { const u = unionOf(scopes, 'engines'); return n.engines.every((e) => u.has(e)); },
  },
  auth_bypass_paths: {
    label: 'Sign-in bypass paths',
    description: 'Path prefixes on this app that skip AppCrane sign-in. Scope: the exact prefixes.',
    defaultApprovalRequired: true,
    whenOff: 'the app owner sets them',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: { paths: ['/webhooks'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['paths']);
      let paths;
      try { paths = validateBypassPaths(s.paths); } catch (e) { throw bad(`scope.paths: ${e.message}`); }
      if (!paths || paths.length === 0) throw bad('scope.paths must be a non-empty array');
      return { paths: [...new Set(paths)].sort() };
    },
    covers: (scopes, n) => { const u = unionOf(scopes, 'paths'); return n.paths.every((p) => u.has(p)); },
  },
  headless: {
    label: 'Headless (no sign-in on any route)',
    description: 'auth_mode=headless: AppCrane sign-in is off for the whole app.',
    defaultApprovalRequired: true,
    whenOff: 'the app owner sets it',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: {},
    ...flagOnly,
  },
  public_visibility: {
    label: 'Public visibility',
    description: 'visibility=public: every AppCrane user sees and can open the app without being assigned.',
    defaultApprovalRequired: true,
    whenOff: 'the app owner sets it',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: {},
    ...flagOnly,
  },
  tcp_ports: {
    label: 'Raw TCP/UDP host port',
    description: 'ingress_type tcp or dual: a host port published with no AppCrane sign-in, TLS or request audit in front of it. Scope: the type and the ports.',
    defaultApprovalRequired: true,
    whenOff: 'only platform admins set it',
    onExpiry: 'flag', onRevoke: 'flag',
    example: { ingress_type: 'tcp', public_port: null },
    normalizeScope: portScope,
    covers: (scopes, n) => scopes.some((g) => portCovered(g, n)),
  },
  outbound_email: {
    label: 'Outbound e-mail',
    description: 'The app sends e-mail through POST /api/service/email. Scope: the recipient domains, or ["*"] for any registered user.',
    defaultApprovalRequired: true,
    whenOff: 'every app may send to registered platform users',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: { recipient_domains: ['example.test'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['recipient_domains']);
      const list = listOf(s, 'recipient_domains', (d) => d === '*' || DOMAIN_RE.test(d), { max: 50 });
      return { recipient_domains: list.includes('*') ? ['*'] : list };
    },
    covers(scopes, n) {
      const u = unionOf(scopes, 'recipient_domains');
      return u.has('*') || n.recipient_domains.every((d) => u.has(d));
    },
  },
  external_secret_connections: {
    label: 'External secret store connection',
    description: 'The app connects to its own Vault, Infisical, 1Password or AWS SSM. Scope: which providers.',
    defaultApprovalRequired: true,
    whenOff: 'the app owner adds them',
    onExpiry: 'flag', onRevoke: 'flag',
    example: { providers: ['vault'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['providers']);
      return { providers: listOf(s, 'providers', (p) => SECRET_PROVIDERS.includes(p), { max: SECRET_PROVIDERS.length }) };
    },
    covers: (scopes, n) => { const u = unionOf(scopes, 'providers'); return n.providers.every((p) => u.has(p)); },
  },
  custom_domain_unprotected: {
    label: 'Custom domain without AppCrane sign-in',
    description: 'A custom domain served with custom_domain_auth off: the app answers at the root of that domain with no AppCrane sign-in in front of it. A custom domain WITH sign-in needs no approval. Scope: the domain names.',
    defaultApprovalRequired: true,
    whenOff: 'the app owner sets the domain and turns its sign-in off',
    // Flag only: dropping a domain breaks every link and certificate pointed
    // at it, and forcing sign-in onto it breaks the machine clients that are
    // usually why it was unprotected. A platform admin turns custom_domain_auth
    // on (which needs no grant) or removes the domain deliberately.
    onExpiry: 'flag', onRevoke: 'flag',
    example: { domains: ['app.example.test'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['domains']);
      return { domains: listOf(s, 'domains', (d) => DOMAIN_RE.test(d), { max: 10 }) };
    },
    covers: (scopes, n) => { const u = unionOf(scopes, 'domains'); return n.domains.every((d) => u.has(d)); },
  },
  llm_gateway: {
    label: 'LLM gateway',
    description: 'The app calls the platform\'s Anthropic/OpenAI keys through the LLM gateway.',
    // Off by default: the platform admin already enables each provider, sets
    // every app's spend limits and the model allowlist per data
    // classification, so the owner's switch spends inside limits an admin set.
    defaultApprovalRequired: false,
    whenOff: 'the app owner or an app admin turns it on, inside the platform\'s spend limits',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: {},
    ...flagOnly,
  },
  egress: {
    label: 'Outbound internet (egress allow-list)',
    description: 'While egress enforcement is on for the app, its container reaches the internet only through AppCrane\'s egress proxy, and only these hosts. Scope: host names, *.suffix, host:port, or ["*"] for any public host.',
    defaultApprovalRequired: true,
    alwaysRequired: true,
    whenOff: 'egress enforcement is a platform setting; while it is off for an app, the app reaches any host',
    onExpiry: 'revoke', onRevoke: 'revoke',
    example: { hosts: ['api.example.test'] },
    normalizeScope(input) {
      const s = objectOf(input); onlyKeys(s, ['hosts']);
      const list = listOf(s, 'hosts', (h) => parseHostEntry(h) !== null, { max: 100 });
      return { hosts: list.includes('*') ? ['*'] : list };
    },
    covers(scopes, n) {
      const u = unionOf(scopes, 'hosts');
      return u.has('*') || n.hosts.every((h) => u.has(h));
    },
  },
});

export const EXTERNAL_GATES = Object.freeze({
  ai_annex_iii: {
    label: 'AI use: Annex III',
    description: 'Already gated by the intake review: production stays closed until a platform admin approves the intake.',
  },
});

export const CAPABILITY_IDS = Object.freeze(Object.keys(CAPABILITIES));

export const isConnectionCapability = (id) => typeof id === 'string' && id.startsWith(CONNECTION_PREFIX)
  && CONNECTION_NAME_RE.test(id.slice(CONNECTION_PREFIX.length));

/** The definition for a capability id, the dynamic connection:<name> ones included; null when unknown. */
export function capabilityDef(id) {
  if (Object.hasOwn(CAPABILITIES, id)) return CAPABILITIES[id];
  return isConnectionCapability(id) ? connectionCapability(id.slice(CONNECTION_PREFIX.length)) : null;
}

export function capabilityOf(id) {
  const c = capabilityDef(id);
  if (!c) {
    if (EXTERNAL_GATES[id]) throw bad(`${id} is approved through the intake review, not a capability request`);
    throw bad(`capability must be one of: ${CAPABILITY_IDS.join(', ')}, or ${CONNECTION_PREFIX}<connection name>`);
  }
  return c;
}
