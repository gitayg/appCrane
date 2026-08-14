import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// TCP (layer-4) ingress — the two SURFACES that tell a human or an agent that an
// app has a second door (v2.42.0).
//
// The schema/allocator/authz invariants live in test/tcp-ingress-schema.test.js.
// This file covers what a person or an agent actually SEES, because for this
// feature the warning is not decoration — it is the control. AppCrane publishes
// the port and deliberately does NOT open the firewall, so between the flip and
// the exposure there is a human deciding whether to add a firewall rule. That
// human decides from what the dashboard and the tool descriptions told them.
//
// Three failure modes are pinned here:
//
//   1. A source-only UI change that was never rebuilt. studio-web/ is compiled
//      into docs/admin-app/ and THAT is what production serves, so every
//      assertion can pass against .tsx while the live dashboard shows nothing.
//      test/sso-token-referer.test.js exists for exactly this reason.
//   2. A warning that says less than the truth. Every regex below is proven to
//      FAIL on a near-miss — most of them on a near-miss that genuinely ships in
//      the same bundle — because a phrase-matcher that cannot fail proves nothing.
//   3. tcp ingress confused with auth_mode='headless'. Headless still goes
//      through Caddy and only skips forward_auth: it keeps TLS, security headers
//      and access logging. tcp keeps none of it. An agent that reaches for `tcp`
//      to make an app login-free opens a host port for no reason, so both tool
//      descriptions have to draw that line and the gate has to hold.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const APPS_TSX = readFileSync(join(ROOT, 'studio-web/src/pages/Applications.tsx'), 'utf8');
const MCP_SRC = readFileSync(join(ROOT, 'server/services/mcpTools.js'), 'utf8');
const REST_SRC = readFileSync(join(ROOT, 'server/routes/apps.js'), 'utf8');

// ---------------------------------------------------------------------------
// The shipped bundle
// ---------------------------------------------------------------------------

const ASSETS = join(ROOT, 'docs/admin-app/assets');
const BUNDLES = readdirSync(ASSETS).filter(f => f.endsWith('.js'));
const BUNDLE = BUNDLES.map(f => readFileSync(join(ASSETS, f), 'utf8')).join('\n');
const INDEX_HTML = readFileSync(join(ROOT, 'docs/admin-app/index.html'), 'utf8');

test('docs/admin-app ships exactly one SPA bundle and index.html points at it', () => {
  // Vite hashes the filename, so a rebuild leaves a second .js behind whenever
  // the stale one wasn't deleted. Two bundles means index.html loads one of
  // them and the other is dead weight that still satisfies a naive
  // "does any bundle contain X" search — which would make every assertion
  // below pass against a file production never loads.
  assert.equal(BUNDLES.length, 1,
    `expected one built .js under docs/admin-app/assets, found ${BUNDLES.length}: ${BUNDLES.join(', ')}. ` +
    'Delete the stale bundle — a leftover hash makes bundle assertions meaningless.');

  assert.ok(INDEX_HTML.includes(BUNDLES[0]),
    `docs/admin-app/index.html does not reference ${BUNDLES[0]} — the built bundle and the ` +
    'page that loads it are out of sync, so the shipped dashboard is stale.');
});

test('the built bundle carries the ingress modal, not just the source', () => {
  for (const phrase of [
    'This port is a second door',            // the modal's lead warning
    'unaudited egress path',                 // the motivating CONNECT-proxy consequence
    'Ingress type',                          // the platform-admin control
    '31000-31999',                           // the allocation range operators filter
  ]) {
    assert.ok(BUNDLE.includes(phrase),
      `the built bundle has no "${phrase}" — studio-web/ was changed but docs/admin-app/ ` +
      'was never rebuilt, so production shows the old dashboard with no ingress surface at all.');
  }
});

// The substance of the warning: a tcp port is not behind AppCrane authentication.
// Matched as a sequence rather than one quoted sentence so a copy-edit doesn't
// break it, but tight enough that a weaker claim cannot satisfy it: it demands
// the absence of sign-in AND of identity headers AND of AppCrane TLS.
const NOT_BEHIND_APPCRANE_AUTH =
  /no AppCrane sign-in[\s\S]{0,400}identity headers[\s\S]{0,400}no TLS from AppCrane/;

test('the bundle states that a tcp port is not behind AppCrane auth', () => {
  assert.match(BUNDLE, NOT_BEHIND_APPCRANE_AUTH,
    'the shipped dashboard no longer tells the reader that a tcp port has no AppCrane ' +
    'sign-in, no identity headers and no TLS from AppCrane. That sentence is the only ' +
    'thing standing between an admin flipping the toggle and an unauthenticated port.');
});

test('the "not behind AppCrane auth" matcher rejects a near-miss that also ships', () => {
  // Proof the matcher discriminates rather than just finding the word "AppCrane".
  //
  // (a) A REAL near-miss from the same bundle: the http branch of this very
  //     modal, which names identity headers and TLS in order to say they DO
  //     apply. If the regex matched this, the test above would pass on an app
  //     that is fully behind Caddy.
  const HTTP_BRANCH = 'HTTP through Caddy — SSO, TLS, identity headers, request logging all apply.';
  assert.ok(BUNDLE.includes(HTTP_BRANCH),
    'the http-branch line moved; pick another shipped near-miss to prove the matcher discriminates');
  assert.doesNotMatch(HTTP_BRANCH, NOT_BEHIND_APPCRANE_AUTH,
    'the matcher fires on the http branch, which says the opposite — it is matching ' +
    'vocabulary, not meaning');

  // (b) The confusion this feature is most likely to ship: headless wording,
  //     which drops the sign-in but keeps TLS and the headers. It must not
  //     satisfy a check meant to prove the tcp exposure was stated.
  const HEADLESS_WORDING =
    'auth_mode headless: no AppCrane sign-in is required, but the app is still served ' +
    'through Caddy, so TLS, security headers and X-AppCrane-* identity headers all still apply.';
  assert.doesNotMatch(HEADLESS_WORDING, NOT_BEHIND_APPCRANE_AUTH,
    'headless wording satisfies the tcp-exposure matcher — the two would be indistinguishable');
});

test('the bundle does not sell the firewall as a second, independent key', () => {
  // It was written as "two keys on purpose — a mis-click here cannot put an app
  // on the internet". That is false twice over on this deployment: a Docker
  // publish is a DNAT rule evaluated in FORWARD and never traverses INPUT, so a
  // plain `ufw deny` does not block it; and the host is behind SDP, so the
  // relevant boundary is the perimeter, not the internet. Telling an admin they
  // hold a second key they do not hold is worse than saying nothing.
  assert.doesNotMatch(BUNDLE, /two separate\s+keys|cannot put an app on the internet/,
    'the modal still claims the firewall is an independent second key — a ufw INPUT rule ' +
    'does not filter a Docker-published port');
  assert.match(BUNDLE, /DOCKER-USER/,
    'the modal no longer names the chain that actually filters a published port');
  assert.match(BUNDLE, /SDP/,
    'the modal no longer states what the real boundary is on this deployment');
});

test('the bundle tells a non-admin why ingress is not self-service', () => {
  assert.match(BUNDLE, /Only a platform admin can change ingress/,
    'a non-platform-admin opening the ingress modal gets no explanation — the fallback ' +
    'copy for the read-only case was dropped from the build');
});

test('the bundle carries the always-visible tcp badge, not only the modal', () => {
  // "This app answers on an unguarded host port" must be discoverable without a
  // click, so the badge lives in the collapsed row.
  assert.match(BUNDLE, /Raw TCP ingress on host port/,
    'the tcp row badge is gone from the build — a tcp app is now indistinguishable ' +
    'from an http one until someone opens the modal');
  assert.match(BUNDLE, /container:3000/,
    'the bundle no longer shows what the published port maps to');
});

// ---------------------------------------------------------------------------
// Where the warning sits in the modal
// ---------------------------------------------------------------------------

test('the App type carries ingress_type and public_port from the API', () => {
  // The UI must never derive a port. public_port is stored, not computed from
  // the slot, precisely so it survives a slot reassignment under clients pinned
  // to it — a UI that recomputed it would silently disagree with the host.
  assert.match(APPS_TSX, /ingress_type\?:\s*'http'\s*\|\s*'tcp'/,
    'the App interface lost ingress_type');
  assert.match(APPS_TSX, /public_port\?:\s*number\s*\|\s*null/,
    'the App interface lost public_port');
});

test('the exposure warning renders for readers, not only for platform admins', () => {
  // A viewer who cannot change ingress still needs to know the app has a door
  // AppCrane does not guard — arguably more than the admin who just set it.
  const modal = APPS_TSX.indexOf('{ingressApp && (() => {');
  assert.notEqual(modal, -1, 'the ingress modal moved — re-check this guard');
  const warning = APPS_TSX.indexOf('This port is a second door', modal);
  const gate = APPS_TSX.indexOf('isPlatformAdmin ?', modal);
  assert.notEqual(warning, -1, 'the ingress modal no longer states the exposure');
  assert.notEqual(gate, -1, 'the ingress modal no longer branches on isPlatformAdmin');
  assert.ok(warning < gate,
    'the exposure warning now sits inside the isPlatformAdmin branch, so an app owner ' +
    'or viewer opening the modal is told nothing about the unguarded port');
  assert.doesNotMatch(APPS_TSX.slice(modal, warning), /isPlatformAdmin/,
    'the warning is behind an isPlatformAdmin condition earlier in the modal');
});

test('the ingress controls themselves stay behind isPlatformAdmin', () => {
  const gate = APPS_TSX.indexOf('isPlatformAdmin ?');
  const select = APPS_TSX.indexOf('Ingress type for ${app.name}');
  assert.notEqual(select, -1, 'the ingress type control moved — re-check this guard');
  assert.ok(gate !== -1 && gate < select,
    'the ingress type select is rendered outside the isPlatformAdmin branch — the UI ' +
    'would offer a control the server refuses, which is how a non-admin learns the ' +
    'field exists and starts probing it');
});

// ---------------------------------------------------------------------------
// MCP tools
// ---------------------------------------------------------------------------

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tcping-surface-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
// appcrane_set_app_ingress reloads Caddy, which logs the whole generated
// Caddyfile at info in mock mode. Same code path, quieter output.
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { getToolCatalog, callTool } = await import('../server/services/mcpTools.js');
const { PUBLIC_PORT_MIN, PUBLIC_PORT_MAX } = await import('../server/services/tcpIngress.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const CATALOG = new Map(getToolCatalog().map(t => [t.name, t]));
const GET_TOOL = 'appcrane_get_app_ingress';
const SET_TOOL = 'appcrane_set_app_ingress';

function mkUser(name, role) {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  return { id, name, role };
}

// A GLOBAL admin is the near-miss that matters: the MCP registry's coarsest
// gate is 'admin', so this user passes canUseTool and reaches the handler. Only
// the explicit platform_admin check inside it stands between them and an open
// host port.
const platformAdmin = mkUser('surface-platformadmin', 'platform_admin');
const globalAdmin = mkUser('surface-globaladmin', 'admin'); // role:platform-admin-skipped
const owner = mkUser('surface-owner', 'user');
const outsider = mkUser('surface-outsider', 'user');

let nextSlot = 900;
function mkApp(slug) {
  return db.prepare('INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,?)')
    .run(slug, slug, ++nextSlot, 'managed').lastInsertRowid;
}
const APP_GATE = mkApp('surface-gate');
const APP_READ = mkApp('surface-read');

for (const appId of [APP_GATE, APP_READ]) {
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, owner.id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')")
    .run(appId, owner.id);
}

const rowOf = (id) => db.prepare('SELECT ingress_type, public_port FROM apps WHERE id = ?').get(id);
const call = (user, name, args) => callTool(user, name, args);
const payload = async (user, name, args) =>
  JSON.parse((await call(user, name, args)).content[0].text);

test('both ingress tools are registered', () => {
  assert.ok(CATALOG.has(GET_TOOL), `${GET_TOOL} is not in the MCP catalog`);
  assert.ok(CATALOG.has(SET_TOOL), `${SET_TOOL} is not in the MCP catalog`);
});

test('the read tool exposes no argument that could change anything', () => {
  const schema = CATALOG.get(GET_TOOL).inputSchema;
  assert.deepEqual(Object.keys(schema.properties), ['slug'],
    `${GET_TOOL} accepts more than a slug. It is the tool every app member can reach; ` +
    'any additional writable property turns a read into a mutation an owner could drive.');
  assert.equal(schema.additionalProperties, false,
    `${GET_TOOL} accepts additionalProperties, so an agent can smuggle unvalidated fields in`);
  assert.equal(CATALOG.get(GET_TOOL).requiredRole, 'any',
    `${GET_TOOL} is no longer readable by app members — the exposure of their own app ` +
    'became invisible to them');
});

test('the read tool performs no writes', () => {
  // The handler is not reachable off the catalog, so this reads the registered
  // block from source. Behaviour is asserted separately below.
  const from = MCP_SRC.indexOf(`name: '${GET_TOOL}'`);
  const to = MCP_SRC.indexOf(`name: '${SET_TOOL}'`);
  assert.ok(from !== -1 && to > from, 'the two ingress tools are no longer adjacent — re-check this slice');
  const block = MCP_SRC.slice(from, to);
  for (const write of ['UPDATE ', 'INSERT ', 'DELETE ', 'assignPublicPort', 'releasePublicPort', 'logAudit']) {
    assert.ok(!block.includes(write),
      `${GET_TOOL} contains "${write}" — the read tool now mutates state, and it is ` +
      'gated only by app access, not by platform_admin');
  }
});

test('reading ingress changes nothing on disk', async () => {
  const before = rowOf(APP_READ);
  await payload(owner, GET_TOOL, { slug: 'surface-read' });
  await payload(owner, GET_TOOL, { slug: 'surface-read' });
  assert.deepEqual(rowOf(APP_READ), before,
    'a read of the ingress moved the app row');
  const audits = db.prepare(
    "SELECT COUNT(*) c FROM audit_log WHERE action = 'app-ingress-change' AND app_id = ?"
  ).get(APP_READ).c;
  assert.equal(audits, 0, 'the read tool wrote an app-ingress-change audit entry');
});

test('the read tool refuses an app the caller has no access to', async () => {
  await assert.rejects(
    () => call(outsider, GET_TOOL, { slug: 'surface-read' }),
    /Forbidden|not found/i,
    'any user can read another app\'s published port, which is a map of the host\'s open ports');
});

test('a global admin cannot open a host port through MCP', async () => {
  const before = rowOf(APP_GATE);
  await assert.rejects(
    () => call(globalAdmin, SET_TOOL, { slug: 'surface-gate', ingress_type: 'tcp' }),
    /platform admin/i,
    'a global admin flipped an app to tcp. Publishing a host port is a platform-tier ' +
    'decision — every AppCrane control assumes Caddy is the only door, and this opens a ' +
    'second one the platform does not control.');
  assert.deepEqual(rowOf(APP_GATE), before,
    'the rejected call still moved the app row — the gate runs after the write');
});

test('the MCP gate matches the REST gate, in wording and in audit action', () => {
  // Two doors write the same field; an operator grepping the audit log by
  // action name has to see changes from both.
  assert.match(MCP_SRC, /user\.role !== 'platform_admin'/,
    'the MCP ingress handler no longer checks platform_admin explicitly');
  assert.match(REST_SRC, /req\.user\.role !== 'platform_admin'/,
    'PUT /api/apps/:slug no longer checks platform_admin for ingress fields');
  assert.ok(MCP_SRC.includes("'app-ingress-change'"),
    'the MCP write path stopped writing the dedicated app-ingress-change audit action');
  assert.ok(REST_SRC.includes("'app-ingress-change'"),
    'the REST write path stopped writing the dedicated app-ingress-change audit action');
});

test('a platform admin can open a port, and it is audited under app-ingress-change', async () => {
  const out = await payload(platformAdmin, SET_TOOL, { slug: 'surface-gate', ingress_type: 'tcp' });

  assert.equal(out.ingress_type, 'tcp');
  assert.ok(Number.isInteger(out.public_port), 'no port was allocated');
  assert.ok(out.public_port >= PUBLIC_PORT_MIN && out.public_port <= PUBLIC_PORT_MAX,
    `allocated port ${out.public_port} is outside ${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}, the one ` +
    'range an operator firewalls');
  assert.match(String(out.warning), /NOT behind AppCrane authentication/,
    'the setter returns no warning, so an agent that flips an app to tcp is never told ' +
    'the port is unauthenticated');
  assert.match(String(out.warning), /firewall/,
    'the setter no longer tells the caller that opening the firewall is a separate step');

  const entry = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'app-ingress-change' AND app_id = ? ORDER BY id DESC LIMIT 1"
  ).get(APP_GATE);
  assert.ok(entry, 'opening a host port through MCP wrote no app-ingress-change audit entry');
  assert.equal(entry.user_id, platformAdmin.id);
  const detail = JSON.parse(entry.detail);
  assert.equal(detail.from.ingress_type, 'http', 'the audit entry does not record the previous state');
  assert.equal(detail.to.ingress_type, 'tcp');
  assert.equal(detail.to.public_port, out.public_port);
});

test('the read tool spells out the exposure instead of returning a bare enum', async () => {
  const out = await payload(owner, GET_TOOL, { slug: 'surface-gate' });
  assert.equal(out.ingress_type, 'tcp');
  assert.equal(out.exposure.behind_appcrane_auth, false,
    'a tcp app reports itself as behind AppCrane auth');
  const summary = String(out.exposure.summary);
  for (const claim of [/forward_auth/i, /identity header/i, /audit/i, /TLS/, /egress/i]) {
    assert.match(summary, claim,
      'the exposure summary no longer states the full loss — an agent reading only the ' +
      'enum will assume the platform still guards the door');
  }
  // The firewall field must NOT sell itself as an independent second key: a ufw
  // INPUT rule does not filter a Docker publish, and this host is behind SDP, so
  // the boundary is the perimeter rather than the internet.
  const fw = String(out.exposure.firewall);
  assert.match(fw, /DOCKER-USER/,
    'the exposure no longer names the chain that actually filters a published port');
  assert.match(fw, /SDP/,
    'the exposure no longer states what the real boundary is on this deployment');
  assert.doesNotMatch(fw, /does NOT open the firewall/i,
    'the exposure still implies the host firewall is a second key AppCrane leaves unturned');

  const http = await payload(owner, GET_TOOL, { slug: 'surface-read' });
  assert.equal(http.ingress_type, 'http');
  assert.equal(http.exposure.behind_appcrane_auth, true,
    'an ordinary http app reports itself as NOT behind AppCrane auth');
  assert.equal(http.exposure.published_as, null);
});

// ---------------------------------------------------------------------------
// tcp ingress is not auth_mode='headless'
// ---------------------------------------------------------------------------

// Headless drops forward_auth and NOTHING else: the app is still served by
// Caddy, so TLS, security headers and access logs all survive. Both matchers
// below therefore key on that survival, not on the word "headless".
const HEADLESS_STILL_PROXIED = /headless[\s\S]{0,200}still goes through Caddy/;

test('both ingress tool descriptions separate tcp from auth_mode=headless', () => {
  for (const name of [GET_TOOL, SET_TOOL]) {
    const desc = CATALOG.get(name).description;
    assert.match(desc, HEADLESS_STILL_PROXIED,
      `${name}'s description no longer distinguishes tcp ingress from auth_mode='headless'. ` +
      'An agent that wants an app reachable without login will reach for tcp and open a ' +
      'host port for a problem headless already solves.');
    assert.match(desc, /TLS/,
      `${name}'s description no longer names what headless keeps and tcp loses`);
  }
});

test('the headless matcher rejects a description that conflates the two', () => {
  assert.doesNotMatch(
    'ingress_type=tcp is the headless option: headless publishes the container port ' +
    'directly on the host with Caddy out of the path.',
    HEADLESS_STILL_PROXIED,
    'the matcher accepts a description that says headless bypasses Caddy — exactly the ' +
    'confusion it exists to catch');
  assert.doesNotMatch(
    'auth_mode can be authenticated, headless or bypass.',
    HEADLESS_STILL_PROXIED,
    'the matcher fires on any mention of the word headless');
});

test('appcrane_set_app_meta points a non-HTTP app at the ingress tool by its real name', () => {
  // set_app_meta is the owner-facing tool an agent lands on when it wants to
  // change how an app is reached. Its headless paragraph is the hand-off; a
  // dangling tool name there sends the agent nowhere.
  const meta = CATALOG.get('appcrane_set_app_meta');
  assert.ok(meta, 'appcrane_set_app_meta is gone — re-check this guard');
  assert.ok(meta.description.includes(SET_TOOL),
    `appcrane_set_app_meta no longer names ${SET_TOOL}, so an agent holding a non-HTTP app ` +
    'has no pointer from the tool it is already reading to the one it needs');
  assert.match(meta.description, /still served BY CADDY/i,
    'appcrane_set_app_meta no longer says a headless app is still served by Caddy, which ' +
    'is the whole distinction from tcp ingress');
});

test('the ingress setter refuses a public_port on an http app', async () => {
  await assert.rejects(
    () => call(platformAdmin, SET_TOOL, { slug: 'surface-read', ingress_type: 'http', public_port: PUBLIC_PORT_MIN }),
    /only applies/i,
    'a port can be pinned onto an app whose traffic still goes through Caddy, leaving a ' +
    'stored port nothing publishes');
  assert.equal(rowOf(APP_READ).public_port, null, 'the rejected call still stored a port');
});
