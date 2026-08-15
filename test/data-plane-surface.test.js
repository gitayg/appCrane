import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';

// v2.45.0 dual ingress — the SURFACES that tell a human or an agent that an app
// has two planes with different security properties.
//
// The allocator/validator invariants live in test/tcp-ingress-schema.test.js and
// the v2.42.0 single-plane surface in test/tcp-ingress-surface.test.js. This file
// is about the three things v2.45.0 added and only these surfaces can get wrong:
//
//   1. A DATA plane published raw to a DIFFERENT container port. The whole
//      feature exists because the control plane must keep everything Caddy gives
//      it, so the surface has to say which half is defended and which is not. A
//      single badge, a single boolean or a single warning paragraph cannot: an
//      operator who reads "this app is behind AppCrane auth" about a dual app has
//      been told something true of one plane and false of the other.
//   2. A WIDENED explicit host-port range (1024-65535, vs the 31000-31999 band an
//      ALLOCATED port still comes from). Widening only helps if the surfaces
//      widened with it — an input still capped at 31999, or a JSON-Schema
//      `maximum` still at 31999, refuses 8080 before the server ever sees it, and
//      the operator is back to reconfiguring a client fleet. Widening also has to
//      NOT have quietly dropped the guards that were doing the real work, so the
//      claims the schema makes ("two apps cannot hold the same host port", "this
//      one is not globally unique") are asserted against behaviour, not just read.
//   3. data_plane_port = 3000. That publishes the CONTROL plane raw — the ordinary
//      HTTP origin, unauthenticated and unaudited — and the operator gets no
//      signal that they did it. Every surface that offers the field has to refuse
//      it WITH the reason, because a bare "invalid port" teaches nothing and the
//      next attempt is 3001.
//
// Every regex here is proven to FAIL on a near-miss, most of them on copy that
// genuinely ships in the same artifact. A phrase-matcher that cannot fail proves
// nothing about the phrase it is supposedly guarding.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const APPS_TSX = readFileSync(join(ROOT, 'studio-web/src/pages/Applications.tsx'), 'utf8');
const MCP_SRC = readFileSync(join(ROOT, 'server/services/mcpTools.js'), 'utf8');
const REST_SRC = readFileSync(join(ROOT, 'server/routes/apps.js'), 'utf8');

// The bundle PRODUCTION LOADS, resolved through index.html rather than by
// globbing the assets directory. A stale hashed bundle left behind by a rebuild
// satisfies a naive "does any bundle contain X" search while the page never
// loads it; reading only the referenced file makes that impossible here.
// (test/tcp-ingress-surface.test.js separately fails the leftover itself.)
const INDEX_HTML = readFileSync(join(ROOT, 'docs/admin-app/index.html'), 'utf8');
const BUNDLE_REF = INDEX_HTML.match(/<script[^>]+src="([^"]+\.js)"/)?.[1];
// Read defensively so a missing bundle surfaces as the assertion below rather
// than as an ENOENT at import time, which fails the whole FILE with a stack
// trace and no statement of what was wrong.
let BUNDLE = '';
try {
  BUNDLE = readFileSync(join(ROOT, 'docs/admin-app/assets', basename(BUNDLE_REF ?? '')), 'utf8');
} catch { /* asserted below */ }

test('index.html names the SPA bundle this file then greps', () => {
  // Precondition for every bundle assertion below: if this resolves to nothing,
  // the greps would all pass vacuously against an empty string.
  assert.ok(BUNDLE_REF, 'docs/admin-app/index.html loads no module script — nothing to assert against');
  assert.ok(BUNDLE.length > 100_000,
    `the bundle index.html points at (${BUNDLE_REF}) is ${BUNDLE.length} bytes — either it is ` +
    'missing from docs/admin-app/assets or it is not the built SPA. Every bundle assertion in ' +
    'this file would otherwise pass against an empty string.');
});

// ---------------------------------------------------------------------------
// 1. The built bundle carries the dual UI
// ---------------------------------------------------------------------------

test('the built bundle carries the dual-plane UI, not just the source', () => {
  for (const [phrase, why] of [
    ['CONTROL PLANE · defended', 'the side-by-side panel that says which plane keeps Caddy'],
    ['DATA PLANE · undefended', 'the other half of that contrast'],
    ['Data plane port', 'the platform-admin control for the container-side port'],
    ['dual — Caddy for HTTP', 'the third option in the ingress-type select'],
    ['DUAL :', 'the collapsed-row badge — the only thing a reader sees without a click'],
    ['1024-65535', 'the widened explicit host-port range as one greppable string'],
    ['31000-31999', 'the auto band, which must still be stated as a SEPARATE range'],
  ]) {
    assert.ok(BUNDLE.includes(phrase),
      `the built bundle has no "${phrase}" (${why}) — studio-web/ was changed but ` +
      'docs/admin-app/ was never rebuilt, so production serves a dashboard on which a dual ' +
      'app is indistinguishable from an ordinary Caddy-fronted one.');
  }
});

test('the bundle bounds the port inputs by the widened range, not the auto band', () => {
  // The two <input type=number> bounds are compiled to numeric literals. They are
  // the browser-side half of the widening: an input still capped at 31999 refuses
  // 8080 in the field, before any request is made, on a value the server accepts.
  assert.match(BUNDLE, /[=:]\s*1024\b/,
    'no 1024 literal in the bundle — the port inputs no longer carry the widened lower bound');
  assert.match(BUNDLE, /[=:]\s*65535\b/,
    'no 65535 literal in the bundle — the port inputs no longer carry the widened upper bound');
  assert.doesNotMatch(BUNDLE, /[=:]\s*31999\b/,
    'the bundle still bounds an input by 31999. The auto band is where an ALLOCATED port ' +
    'comes from, not the range an operator may name — a client fleet already configured for ' +
    '8080 cannot be expressed through a control that refuses it in the browser.');
});

// What the data plane GIVES UP. Sequenced rather than quoted whole so a copy-edit
// does not break it, but it demands all four losses in order — sign-in AND
// identity headers AND audit AND TLS — because any three of them is a warning
// that reads complete and is not.
const DATA_PLANE_LOSS =
  /Data plane:[\s\S]{0,260}published raw[\s\S]{0,80}no AppCrane sign-in[\s\S]{0,80}no identity headers[\s\S]{0,80}no request audit[\s\S]{0,80}no TLS from AppCrane/;

test('the bundle states what the DATA plane gives up, naming the app as the authenticator', () => {
  assert.match(BUNDLE, DATA_PLANE_LOSS,
    'the shipped dashboard no longer tells the reader that a dual app\'s data plane has no ' +
    'AppCrane sign-in, no identity headers, no request audit and no TLS. On a dual app that ' +
    'sentence is the whole warning: the app IS behind Caddy, on the plane the reader is ' +
    'looking at, and the exposure is the one they are not.');
  assert.match(BUNDLE, /the app authenticates every connection on it itself/,
    'the dual copy no longer says WHO authenticates the data plane. "Not behind AppCrane auth" ' +
    'without "the app owns it" reads as "nothing authenticates it", which is a different claim.');
});

test('the data-plane-loss matcher rejects near-misses, including one that ships', () => {
  // (a) A REAL near-miss from the same bundle: the CONTROL-plane half of the very
  //     same tooltip, which names identity headers and TLS in order to say they DO
  //     apply. If the matcher fired on this, the test above would pass on copy that
  //     described a dual app as fully defended.
  const CONTROL_HALF =
    'Control plane: ordinary HTTP on container port 3000, still served through Caddy with ' +
    'SSO, TLS, identity headers and logging intact.';
  assert.ok(BUNDLE.includes('still served through Caddy with SSO, TLS, identity headers and logging intact'),
    'the control-plane clause moved — pick another shipped near-miss to prove the matcher discriminates');
  assert.doesNotMatch(CONTROL_HALF, DATA_PLANE_LOSS,
    'the matcher fires on the clause that says the controls APPLY — it is matching vocabulary, not meaning');

  // (b) The plausible weakening: dual copy that names both planes and lists the
  //     losses only partially. Every term the matcher wants appears SOMEWHERE in
  //     it — but "identity headers" and "TLS" appear in the control-plane clause,
  //     where they are a promise rather than a loss.
  const HALF_TRUE_DUAL =
    'Dual ingress. Data plane: host port 8080 → container port 8081, published raw — ' +
    'no AppCrane sign-in. Control plane: ordinary HTTP through Caddy with SSO, TLS, ' +
    'identity headers and logging intact.';
  assert.doesNotMatch(HALF_TRUE_DUAL, DATA_PLANE_LOSS,
    'copy that admits only the missing sign-in satisfies the matcher — the reader would be ' +
    'left thinking the identity headers and the audit trail still cover the raw port');

  // (c) The v2.42.0 pure-tcp tooltip, which is complete about its losses but says
  //     nothing about two planes. A dual app rendered with it is under-described.
  const TCP_ONLY =
    'Raw TCP ingress on host port 8080 — this port does NOT go through AppCrane. No sign-in, ' +
    'no identity headers, no request audit, no TLS from AppCrane.';
  assert.doesNotMatch(TCP_ONLY, DATA_PLANE_LOSS,
    'the single-plane tcp tooltip satisfies a matcher meant to prove the DATA plane was ' +
    'distinguished from the control plane');
});

// The panel's job is a CONTRAST: one column keeps the controls, the other has
// none of them. The matcher demands the defended column state the controls it
// keeps and the undefended one disclaim them, in that order.
const TWO_PLANE_CONTRAST =
  /CONTROL PLANE · defended[\s\S]{0,900}TLS, AppCrane SSO[\s\S]{0,400}identity headers, security headers and access logs all apply[\s\S]{0,900}DATA PLANE · undefended[\s\S]{0,600}Caddy is not in this path, so none of the above applies/;

test('the bundle contrasts the defended plane with the undefended one', () => {
  assert.match(BUNDLE, TWO_PLANE_CONTRAST,
    'the two-plane panel no longer states, side by side, that the control plane keeps TLS, ' +
    'SSO, identity headers, security headers and access logs and that the data plane keeps ' +
    'none of them. Two boxes without that contrast look like two equal halves.');
  assert.match(BUNDLE, /This is also the plane the health check probes/,
    'the control-plane card no longer says it is the plane the health check probes — an ' +
    'operator whose data plane is dead and whose app still reads healthy has no explanation');
  assert.match(BUNDLE, /same process in the same container/,
    'the modal no longer says the two planes are one process. A panel that draws two boxes ' +
    'invites reading the split as a security boundary; it is a network-exposure boundary, and ' +
    'a flaw reachable on the data plane is reachable in the code serving the defended plane.');
});

test('the two-plane contrast matcher rejects a panel whose columns are swapped', () => {
  // The failure this exists to catch is not a missing panel — it is a panel that
  // labels the columns and then attaches the wrong properties to them.
  const SWAPPED =
    'CONTROL PLANE · defended — a direct Docker publish. Caddy is not in this path, so none ' +
    'of the above applies. DATA PLANE · undefended — TLS, AppCrane SSO, X-AppCrane-* ' +
    'identity headers, security headers and access logs all apply.';
  assert.doesNotMatch(SWAPPED, TWO_PLANE_CONTRAST,
    'the matcher accepts a panel that promises Caddy\'s controls on the DATA plane — it is ' +
    'checking that both labels exist, not that each carries the right claim');

  const LABELS_ONLY = 'CONTROL PLANE · defended / DATA PLANE · undefended';
  assert.doesNotMatch(LABELS_ONLY, TWO_PLANE_CONTRAST,
    'two bare labels satisfy the matcher, so a panel that names the planes and explains ' +
    'neither would pass');
});

// The 3000 refusal, stated with its REASON. Split out because "invalid port" is
// the version of this message that teaches nothing and gets 3001 typed next.
const UI_REFUSES_CONTROL_PLANE_PORT =
  /HTTP control plane Caddy proxies to[\s\S]{0,160}no TLS, no sign-in, no identity headers and no audit/;
const UI_ALERT_REFUSES_CONTROL_PLANE_PORT =
  /Publishing it raw would put the app's ordinary HTTP origin on the host with no TLS, no AppCrane sign-in, no identity headers and no request audit/;

test('the bundle refuses the control-plane port WITH the reason, in the standing copy and at the keystroke', () => {
  assert.match(BUNDLE, UI_REFUSES_CONTROL_PLANE_PORT,
    'the data-plane-port help text no longer explains why 3000 is refused. That sentence is ' +
    'the only place a reader who never types the value learns the port exists to keep the ' +
    'HTTP origin off the host.');
  assert.match(BUNDLE, UI_ALERT_REFUSES_CONTROL_PLANE_PORT,
    'the client-side refusal for data_plane_port=3000 no longer gives the reason (or is gone). ' +
    'The server refuses it either way — but a 400 arrives after the operator has decided the ' +
    'number, and this one arrives while they are choosing it.');
  assert.match(BUNDLE, /only the host port has to be unique/,
    'the UI no longer says the container-side port need not be globally unique. Sitting next ' +
    'to a field that IS unique, an operator will assume this one is too and invent a per-app ' +
    'numbering scheme to avoid a collision that cannot happen.');
});

test('the 3000-refusal matchers reject a bare rejection with no reason', () => {
  const NO_REASON = 'Data plane port cannot be 3000. Pick another port.';
  assert.doesNotMatch(NO_REASON, UI_REFUSES_CONTROL_PLANE_PORT,
    'a refusal with no reason satisfies the matcher — the copy could degrade to "invalid ' +
    'port" and this test would stay green');
  assert.doesNotMatch(NO_REASON, UI_ALERT_REFUSES_CONTROL_PLANE_PORT,
    'the alert matcher accepts a reasonless refusal');

  // A reason that names the control plane but not what is LOST by publishing it.
  const HALF_REASON =
    'Data plane port cannot be 3000: that is the HTTP control plane Caddy proxies to.';
  assert.doesNotMatch(HALF_REASON, UI_REFUSES_CONTROL_PLANE_PORT,
    'naming the control plane without naming the lost controls satisfies the matcher — ' +
    '"3000 is special" does not tell an operator what publishing it would hand out');
});

test('the App type and the row surfaces treat dual as a publishing type', () => {
  // The eight `=== \'tcp\'` comparisons this replaced were each a place a dual app
  // rendered as an ordinary Caddy-fronted app: no badge, no red icon, no modal
  // warning. The predicate is the fix; a reintroduced bare comparison is the
  // regression.
  assert.match(APPS_TSX, /ingress_type\?:\s*'http'\s*\|\s*'tcp'\s*\|\s*'dual'/,
    'the App interface no longer models dual, so the dashboard cannot render it as anything ' +
    'but an unrecognised string');
  assert.match(APPS_TSX, /data_plane_port\?:\s*number\s*\|\s*null/,
    'the App interface lost data_plane_port — the UI would have to derive the container side, ' +
    'and a derived port silently disagrees with the host');
  assert.match(APPS_TSX, /const publishesPort = \(t\?: string\): boolean => t === 'tcp' \|\| t === 'dual'/,
    'the publishesPort predicate is gone');

  // Not a style rule: any surviving `ingress_type === 'tcp'` that decides whether
  // to WARN is a dual app rendered as safe. Comparisons that pick between two
  // warnings are fine, so this asserts on the predicate being used at the places
  // that gate the warning at all.
  for (const gate of [
    "publishesPort(app.ingress_type) && (",     // the row badge
    'publishesPort(app.ingress_type)\n',        // the row toolbar icon colour
    'const published = publishesPort(curType)', // the modal's red exposure block
  ]) {
    assert.ok(APPS_TSX.includes(gate),
      `the surface gated by \`${gate.trim()}\` no longer uses publishesPort — if it went back ` +
      "to === 'tcp', a dual app shows no warning at all on that surface");
  }
});

// ---------------------------------------------------------------------------
// 2. The MCP tool surface
// ---------------------------------------------------------------------------

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-dataplane-surface-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { getToolCatalog, callTool } = await import('../server/services/mcpTools.js');
const {
  INGRESS_TYPES, CONTROL_PLANE_PORT,
  AUTO_PORT_MIN, AUTO_PORT_MAX, PUBLIC_PORT_MIN, PUBLIC_PORT_MAX,
  slotPortConflict,
} = await import('../server/services/tcpIngress.js');
const { isPortSafe } = await import('../server/services/blockedPorts.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const CATALOG = new Map(getToolCatalog().map(t => [t.name, t]));
const GET_TOOL = 'appcrane_get_app_ingress';
const SET_TOOL = 'appcrane_set_app_ingress';
const SET_SCHEMA = CATALOG.get(SET_TOOL).inputSchema;

test('the setter advertises the vocabulary itself, so dual is reachable through MCP', () => {
  assert.deepEqual(SET_SCHEMA.properties.ingress_type.enum, INGRESS_TYPES,
    'the MCP enum has drifted from INGRESS_TYPES. A copied array is how the setter ended up ' +
    'accepting a type its own schema denied existed: the handler validates against the shared ' +
    'vocabulary, so a type missing here is reachable by a client that skips schema validation ' +
    'and unreachable by one that does not.');
  assert.ok(INGRESS_TYPES.includes('dual'), 'dual is not in the shared vocabulary at all');
});

test('the setter schema advertises the WIDENED explicit host-port range', () => {
  const p = SET_SCHEMA.properties.public_port;
  assert.equal(p.minimum, PUBLIC_PORT_MIN,
    'public_port.minimum is not the explicit range floor');
  assert.equal(p.maximum, PUBLIC_PORT_MAX,
    `public_port.maximum is ${p.maximum}, not ${PUBLIC_PORT_MAX}. If it is still the auto band's ` +
    'ceiling, a schema-validating agent asked for 8080 refuses locally — the operator never ' +
    'reaches the server that would have accepted it, and the answer becomes "reconfigure your ' +
    'clients", which is the outcome the widening exists to avoid.');
  assert.notEqual(p.maximum, AUTO_PORT_MAX,
    'the schema still caps the explicit range at the auto band');
});

// The two ranges are DIFFERENT questions, and a description that gives one number
// teaches the wrong lesson whichever number it gives: the auto band alone makes
// 8080 look illegal, the wide range alone loses the predictable firewall block.
const DESCRIBES_BOTH_RANGES = new RegExp(
  `${AUTO_PORT_MIN}-${AUTO_PORT_MAX}[\\s\\S]{0,300}(?:explicitly NAMED|named explicitly|name one explicitly)` +
  `[\\s\\S]{0,80}${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}`,
);

test('the setter separates the allocation band from the range an operator may name', () => {
  assert.match(SET_SCHEMA.properties.public_port.description, DESCRIBES_BOTH_RANGES,
    'public_port\'s description no longer distinguishes the band an ALLOCATED port comes from ' +
    'from the range an operator may explicitly name');
  assert.match(CATALOG.get(SET_TOOL).description, DESCRIBES_BOTH_RANGES,
    'the tool description no longer makes the same split, so an agent reading tools/list ' +
    'still believes 31000-31999 is the only legal range');
  assert.match(CATALOG.get(SET_TOOL).description, /firewall/i,
    'the description no longer tells the caller that a port outside the auto band needs its ' +
    'own firewall rule — the one consequence of naming a port that AppCrane cannot enforce');
});

test('the both-ranges matcher rejects a description that states only one', () => {
  const AUTO_ONLY =
    'Omit public_port to have the lowest free port in 31000-31999 allocated. Two apps cannot ' +
    'hold the same host port.';
  assert.doesNotMatch(AUTO_ONLY, DESCRIBES_BOTH_RANGES,
    'the pre-widening description passes the matcher, so the surface could silently revert');

  const CONFLATED =
    'public_port may be anything in 31000-31999, and the underlying range is 1024-65535.';
  assert.doesNotMatch(CONFLATED, DESCRIBES_BOTH_RANGES,
    'a description that prints both numbers without saying which is allocated and which is ' +
    'named satisfies the matcher — the numbers alone are not the distinction');
});

// The data-plane field, and the refusal that keeps the control plane off the host.
const SCHEMA_REFUSES_CONTROL_PLANE_PORT = new RegExp(
  `NOT be ${CONTROL_PLANE_PORT}[\\s\\S]{0,300}no TLS[\\s\\S]{0,80}no forward_auth` +
  `[\\s\\S]{0,80}no identity headers[\\s\\S]{0,80}no request audit`,
);

test('the setter schema carries data_plane_port, bounded and explained', () => {
  const p = SET_SCHEMA.properties.data_plane_port;
  assert.ok(p, 'the MCP setter has no data_plane_port property, so a dual app cannot be ' +
    'configured through MCP at all — only through the SPA');
  // An integer OR null. null is not decoration: it is the only way to drop a
  // pinned data plane, and dropping it is REQUIRED to flip a dual app to 'tcp'
  // (which publishes the control-plane port instead). A schema that admitted
  // only integers would leave a schema-validating MCP client unable to perform
  // that transition at all, while the SPA and REST could.
  assert.deepEqual(p.type, ['integer', 'null'],
    'the setter schema no longer admits null for data_plane_port, so an MCP client that ' +
    'validates against it cannot drop a data plane — and therefore cannot move a dual app ' +
    'to ingress_type=tcp, which the server refuses while a data plane is still pinned');
  assert.equal(p.minimum, PUBLIC_PORT_MIN,
    'data_plane_port allows a port below 1024 — the floor keeps a data plane off the ports ' +
    'the platform itself reserves, and a clear refusal here becomes a confusing ' +
    '`docker run` failure later');
  assert.equal(p.maximum, PUBLIC_PORT_MAX);
  assert.match(p.description, SCHEMA_REFUSES_CONTROL_PLANE_PORT,
    `data_plane_port's description no longer states that ${CONTROL_PLANE_PORT} is refused and ` +
    'what publishing it would hand out. An agent that never reads the reason proposes it, ' +
    'gets a 400, and tries 3001 next.');
  assert.match(p.description, /not globally unique|two apps may each use the same container-side port/i,
    'the description no longer says the container side need not be unique, so an agent will ' +
    'invent a per-app numbering scheme to avoid a collision network namespaces make impossible');
  assert.equal(SET_SCHEMA.additionalProperties, false,
    'the setter accepts additionalProperties — an agent can smuggle unvalidated fields into ' +
    'the one call that opens a host port');
});

test('the schema 3000-refusal matcher rejects a description that only forbids the value', () => {
  const BARE = `data_plane_port must NOT be ${CONTROL_PLANE_PORT}.`;
  assert.doesNotMatch(BARE, SCHEMA_REFUSES_CONTROL_PLANE_PORT,
    'a bare prohibition passes the matcher, so the reason could be dropped without a failure');
  const WRONG_REASON =
    `data_plane_port must NOT be ${CONTROL_PLANE_PORT} because that port is already in use ` +
    'inside the container.';
  assert.doesNotMatch(WRONG_REASON, SCHEMA_REFUSES_CONTROL_PLANE_PORT,
    'a description that gives a PLAUSIBLE-BUT-WRONG reason ("already in use") passes. The ' +
    'refusal is not about a conflict — it is about publishing the defended plane raw.');
});

test('the read tool points an agent at the per-plane answer instead of the enum', () => {
  const desc = CATALOG.get(GET_TOOL).description;
  assert.ok(desc.includes('dual'), `${GET_TOOL} never mentions dual`);
  assert.match(desc, /exposure\.control_plane[\s\S]{0,80}exposure\.data_plane|control_plane[\s\S]{0,120}data_plane/,
    `${GET_TOOL} no longer names the two per-plane fields. An agent that reads only ` +
    'ingress_type gets one answer to a question that has two, and either ignores a raw port ' +
    'or reports a Caddy-fronted control plane as unguarded.');
});

// ---------------------------------------------------------------------------
// 3. Platform-admin gating, consistent with REST
// ---------------------------------------------------------------------------

function mkUser(name, role) {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  return { id, name, role };
}

// A GLOBAL admin is the near-miss that matters: 'admin' is the coarsest gate the
// MCP registry has, so this user passes canUseTool and reaches the handler. Only
// the explicit platform_admin check stands between them and a published port.
const platformAdmin = mkUser('dp-platformadmin', 'platform_admin');
const globalAdmin = mkUser('dp-globaladmin', 'admin'); // role:platform-admin-skipped
const owner = mkUser('dp-owner', 'user');

// Low slots on purpose: getPortsForSlot() is unbounded (sand_fe = 3000 + 2N), so
// a high slot would make 8080 a genuine slot collision and the assertions below
// would be testing the collision guard instead of the widened range.
let nextSlot = 300;
function mkApp(slug) {
  const id = db.prepare('INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,?)')
    .run(slug, slug, ++nextSlot, 'managed').lastInsertRowid;
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(id, owner.id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')")
    .run(id, owner.id);
  return id;
}
const APP_GATE = mkApp('dp-gate');
const APP_DUAL = mkApp('dp-dual');
const APP_SECOND = mkApp('dp-second');

const rowOf = (id) => db.prepare(
  'SELECT ingress_type, public_port, data_plane_port FROM apps WHERE id = ?').get(id);
const call = (user, name, args) => callTool(user, name, args);
const payload = async (user, name, args) =>
  JSON.parse((await call(user, name, args)).content[0].text);

const HOST_PORT = 8080;   // outside the auto band; the number a client fleet is pinned to
const DATA_PORT = 8081;   // the container-side listener

test('8080 is assignable in this database, so the tests below measure the range and not a collision', () => {
  // Stated rather than assumed. If a future fixture pushes max(slot) past ~2540,
  // sand_fe reaches 8080 and every "the wide range works" assertion below would
  // fail for a reason that has nothing to do with the widening.
  assert.equal(slotPortConflict(db, HOST_PORT), null,
    `port ${HOST_PORT} collides with a slot-derived backend port in this fixture — lower the ` +
    'slots used by mkApp() rather than weakening the assertions that depend on it');
  assert.ok(isPortSafe(HOST_PORT), `${HOST_PORT} is on the WHATWG blocked list`);
  assert.ok(HOST_PORT < AUTO_PORT_MIN || HOST_PORT > AUTO_PORT_MAX,
    `${HOST_PORT} is inside the auto band, so it proves nothing about explicitly named ports`);
});

test('a global admin cannot publish a data plane through MCP', async () => {
  const before = rowOf(APP_GATE);
  await assert.rejects(
    () => call(globalAdmin, SET_TOOL, {
      slug: 'dp-gate', ingress_type: 'dual', public_port: HOST_PORT, data_plane_port: DATA_PORT,
    }),
    /platform admin/i,
    'a global admin opened a host port by asking for dual instead of tcp. dual is the same ' +
    'exposure with an extra field, so it has to sit behind the same gate — a second type is ' +
    'exactly the sort of thing a gate written against one enum value misses.');
  assert.deepEqual(rowOf(APP_GATE), before,
    'the rejected call still moved the app row — the gate runs after the write');
});

// The REST gate has to engage on a data-plane CHANGE, not merely mention the field
// in its error message. Written as a predicate so it can be run against a
// deliberate near-miss that has the message and not the check.
function gatesDataPlaneChange(src) {
  const m = src.match(
    /if \(([^)]*wantsTypeChange[^)]*)\)\s*\{\s*if \(req\.user\.role !== 'platform_admin'\)/);
  return !!m && /wantsDataPlaneChange/.test(m[1]);
}

test('PUT /api/apps/:slug puts a data-plane change behind the same platform_admin gate', () => {
  assert.ok(gatesDataPlaneChange(REST_SRC),
    'the REST ingress gate no longer engages on a data_plane_port change. An app member who ' +
    'can already PUT other fields could then move the container-side port of a published data ' +
    'plane — repointing a raw, unauthenticated host port at a different listener inside the ' +
    'container, with no platform-admin involvement.');
});

test('the REST-gate predicate rejects a version that keeps the message but drops the check', () => {
  // The near-miss is the realistic one: someone adds data_plane_port to the error
  // string (so a grep for the field name in apps.js still hits) and forgets the
  // condition. A source check that looked only for the words would pass this.
  const NEAR_MISS = `
  if (wantsTypeChange || wantsPortChange || needsAllocation) {
    if (req.user.role !== 'platform_admin') {
      throw new AppError('Only platform admins can change ingress_type, public_port, sandbox_public_port or data_plane_port', 403, 'FORBIDDEN');
    }
    if (data_plane_port !== undefined) { updates.data_plane_port = data_plane_port; }
  }`;
  assert.ok(NEAR_MISS.includes('data_plane_port'),
    'the near-miss must contain the field name, or it does not test what it claims to');
  assert.equal(gatesDataPlaneChange(NEAR_MISS), false,
    'the predicate passes a gate that names data_plane_port in its message but never checks ' +
    'for a data-plane change — it is matching the apology, not the lock');
});

test('the MCP setter refuses before it reads anything, and both doors say the same thing', () => {
  const from = MCP_SRC.indexOf(`name: '${SET_TOOL}'`);
  assert.notEqual(from, -1, `${SET_TOOL} is no longer registered under that name`);
  const block = MCP_SRC.slice(from, from + 12000);
  assert.match(block, /handler: async \(user, args\) => \{\s*if \(user\.role !== 'platform_admin'\)/,
    'the platform_admin check is no longer the first thing the MCP setter does. Anything ' +
    'before it runs for a global admin, and this handler\'s later steps allocate ports and ' +
    'write columns.');

  const SHARED = 'Only platform admins can change ingress_type, public_port, sandbox_public_port or data_plane_port';
  assert.ok(MCP_SRC.includes(SHARED),
    'the MCP refusal no longer names data_plane_port, so a caller refused for touching it is ' +
    'told the wrong field is the problem');
  assert.ok(REST_SRC.includes(SHARED),
    'the REST refusal no longer names data_plane_port — the two doors now explain the same ' +
    '403 differently');
});

// ---------------------------------------------------------------------------
// 4. The surfaces make claims. The claims are true.
// ---------------------------------------------------------------------------

test('a platform admin can name a host port outside the auto band and get it', async () => {
  const out = await payload(platformAdmin, SET_TOOL, {
    slug: 'dp-dual', ingress_type: 'dual', public_port: HOST_PORT, data_plane_port: DATA_PORT,
  });
  assert.equal(out.ingress_type, 'dual');
  assert.equal(out.public_port, HOST_PORT,
    `the explicitly named host port was not honoured. ${HOST_PORT} is outside ${AUTO_PORT_MIN}-` +
    `${AUTO_PORT_MAX} on purpose: the clients are already configured for it, and refusing the ` +
    'number is refusing the use case.');
  assert.equal(out.data_plane_port, DATA_PORT);
  assert.deepEqual(rowOf(APP_DUAL),
    { ingress_type: 'dual', public_port: HOST_PORT, data_plane_port: DATA_PORT });

  assert.match(String(out.warning), /NOT behind AppCrane authentication/,
    'the setter returns no warning for dual, so an agent that publishes a data plane is never ' +
    'told the port is unauthenticated');
  assert.match(String(out.warning), new RegExp(`control plane on container port ${CONTROL_PLANE_PORT}`),
    'the dual warning never mentions the control plane, so the caller cannot tell whether the ' +
    'flip also changed how the app\'s normal URL is served');
  assert.match(String(out.warning), /health check/i,
    'the dual warning does not say which plane the health check probes — the one question an ' +
    'operator asks when the data plane is dead and the app still reads healthy');
});

test('the widened range did not remove the guards that were doing the work', async () => {
  // Narrowing was never what made this safe. These two fire at any value, and
  // they matter MORE now that any value can be asked for.
  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, {
      slug: 'dp-gate', ingress_type: 'dual', public_port: 6667, data_plane_port: DATA_PORT,
    }),
    /WHATWG blocked-ports list/,
    'a WHATWG-blocked port inside the widened range was accepted. Browsers and Node\'s fetch ' +
    'refuse to connect to it, so the app would be published on a port half its clients cannot ' +
    'reach, with no error anywhere.');
  assert.deepEqual(rowOf(APP_GATE), { ingress_type: 'http', public_port: null, data_plane_port: null },
    'the rejected call left state behind');

  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, {
      slug: 'dp-second', ingress_type: 'dual', public_port: HOST_PORT, data_plane_port: DATA_PORT,
    }),
    /already published by app "dp-dual"/,
    'two apps were allowed to hold the same HOST port. That is the duplication the partial ' +
    'unique index exists to forbid: the second container\'s `docker run` dies with "port is ' +
    'already allocated", and until it does, traffic reaches whichever app bound it first.');
});

test('two apps may share a CONTAINER-side port — the duplication deliberately not guarded', async () => {
  // Container network namespaces are separate, so this collides with nothing. A
  // uniqueness constraint here would forbid a legitimate and likely-common
  // configuration, and the UI and the schema both promise it is allowed.
  const out = await payload(platformAdmin, SET_TOOL, {
    slug: 'dp-second', ingress_type: 'dual', public_port: 8090, data_plane_port: DATA_PORT,
  });
  assert.equal(out.data_plane_port, DATA_PORT,
    'a second app was refused the same container-side port as the first. Nothing collides — ' +
    'and the surfaces tell operators it is fine, so the refusal would contradict the copy.');
  assert.equal(out.public_port, 8090);
});

test('data_plane_port = 3000 is refused, with the reason, and writes nothing', async () => {
  const before = rowOf(APP_GATE);
  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, {
      slug: 'dp-gate', ingress_type: 'dual', public_port: 8091, data_plane_port: CONTROL_PLANE_PORT,
    }),
    (e) => {
      assert.match(e.message, /control plane/i,
        'the refusal does not say 3000 is the control plane');
      assert.match(e.message, /no TLS[\s\S]{0,120}no forward_auth[\s\S]{0,120}no identity headers[\s\S]{0,120}no request audit/,
        'the refusal does not say what publishing the control plane raw would give away. ' +
        'Without that, the operator reads it as an arbitrary reserved number.');
      return true;
    },
    'data_plane_port=3000 was ACCEPTED. That publishes the app\'s HTTP control plane on a ' +
    'public port with no TLS, no forward_auth, no identity headers and no audit — the exact ' +
    'surface Caddy is in the path to protect — and no surface would report anything unusual.');
  assert.deepEqual(rowOf(APP_GATE), before, 'the refused call still wrote to the row');
});

test('dual without a data-plane port is refused rather than defaulted', async () => {
  const before = rowOf(APP_GATE);
  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, { slug: 'dp-gate', ingress_type: 'dual' }),
    /requires data_plane_port/,
    'dual with no data-plane port was accepted. The publish must target SOME container port ' +
    'and the only other one there is the control plane, so a default here is the 3000 case ' +
    'arrived at silently.');
  assert.deepEqual(rowOf(APP_GATE), before, 'the refused flip still moved the row');

  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, {
      slug: 'dp-gate', ingress_type: 'tcp', data_plane_port: DATA_PORT,
    }),
    /only applies to an app with ingress_type='dual'/,
    'a pure-tcp app accepted a data_plane_port. A tcp app IS its data plane — the container is ' +
    'told PORT=3000 and the whole of it is published — so a stored second number is a value ' +
    'nothing reads and that can silently disagree with what is actually published.');
});

test('the read tool answers the two-plane question per plane, not once', async () => {
  const out = await payload(owner, GET_TOOL, { slug: 'dp-dual' });
  assert.equal(out.ingress_type, 'dual');
  assert.equal(out.data_plane_port, DATA_PORT);
  assert.equal(out.exposure.published_as, `0.0.0.0:${HOST_PORT} -> container:${DATA_PORT}`,
    'published_as still reports the container side as the control-plane port. That is the ' +
    'v2.42.0 assumption the whole feature removes, and an operator debugging "my client ' +
    'connects but nothing answers" would be reading the wrong number.');

  assert.equal(out.exposure.behind_appcrane_auth, false,
    'a dual app reports itself as behind AppCrane auth. One boolean has to answer for both ' +
    'planes, so it has to answer with the unsafe one — a door exists that AppCrane does not guard.');
  assert.equal(out.exposure.control_plane.behind_appcrane_auth, true);
  assert.equal(out.exposure.control_plane.container_port, CONTROL_PLANE_PORT);
  assert.equal(out.exposure.data_plane.behind_appcrane_auth, false);
  assert.equal(out.exposure.data_plane.container_port, DATA_PORT);
  assert.equal(out.exposure.data_plane.host_port, HOST_PORT);

  const summary = String(out.exposure.summary);
  for (const claim of [/forward_auth/i, /identity header/i, /audit/i, /TLS/, /health check/i]) {
    assert.match(summary, claim,
      'the dual exposure summary no longer states the full loss on the data plane (and which ' +
      'plane the health check follows) — an agent reading only the enum assumes the platform ' +
      'still guards the door');
  }
  assert.match(summary, /same process in the same container/,
    'the summary no longer says the split is a network-exposure boundary and not a security ' +
    'one. Two named planes read as two isolated components unless the summary says otherwise.');
});

test('the audit entry records the data-plane port on both sides of the change', async () => {
  // The audit log is an operator surface too: "which port did this app publish, ' +
  // and to what inside the container" has to be answerable after the fact, from
  // the log alone, without the current row.
  const entry = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'app-ingress-change' AND app_id = ? ORDER BY id DESC LIMIT 1"
  ).get(APP_DUAL);
  assert.ok(entry, 'publishing a data plane through MCP wrote no app-ingress-change audit entry');
  const detail = JSON.parse(entry.detail);
  assert.equal(detail.from.ingress_type, 'http');
  assert.equal(detail.from.data_plane_port, null,
    'the audit entry does not record the previous data-plane port, so a change from one ' +
    'container-side port to another is unreadable from the log');
  assert.equal(detail.to.ingress_type, 'dual');
  assert.equal(detail.to.public_port, HOST_PORT);
  assert.equal(detail.to.data_plane_port, DATA_PORT);
});

test('flipping a dual app to http stops the publish and reports the port as still open', async () => {
  const out = await payload(platformAdmin, SET_TOOL, { slug: 'dp-dual', ingress_type: 'http' });
  assert.equal(out.ingress_type, 'http');
  assert.equal(out.public_port, null, 'an http app still reports a published port');
  assert.equal(out.data_plane_port, null,
    'an http app still reports a data-plane port in effect — the number survives the flip in ' +
    'the column on purpose, but reading it back as active says the app has a plane it does not');
  assert.equal(out.pending_port_release, HOST_PORT,
    'the flip reported nothing still open. The publish is a `docker run` flag, so the running ' +
    'container keeps binding the port until it is recreated — reporting the exposure as closed ' +
    'here is the false all-clear this field exists to prevent.');

  // The pin survives, so flipping back restores the numbers the clients use.
  const back = await payload(platformAdmin, SET_TOOL, { slug: 'dp-dual', ingress_type: 'dual' });
  assert.equal(back.public_port, HOST_PORT,
    'flipping back allocated a different host port — every client pinned to the old number ' +
    'would have to be reconfigured, which is the cost the pinned model exists to avoid');
  assert.equal(back.data_plane_port, DATA_PORT,
    'flipping back lost the container-side port, so dual could not be restored without ' +
    'retyping a number the operator may no longer remember');
});
