import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import express from 'express';

// App-defined roles, delivery side (v2.41.0).
//
// An app invents its own vocabulary — approver, auditor, reviewer — AppCrane
// stores it, and the app enforces it. AppCrane is the AUTHORITY; the app is the
// ENFORCER. Three surfaces carry the answer: /api/me's `app_roles`, the
// X-AppCrane-App-Roles response header from /api/identity/verify, and the
// Caddy strip/copy that makes that header trustworthy.
//
// THE RULE THESE TESTS PIN: an app-defined role must never confer an AppCrane
// privilege, and an AppCrane privilege must never confer an app-defined role.
// The second half is the one that gets "helpfully" broken: a platform_admin
// short-circuit on the role lookup would read as generous and would silently
// hand every app's highest in-app powers to anyone with a platform role, from a
// vocabulary the app owner typed into a settings form. Grants are explicit only.
//
// The header half is a privilege wire. If a client could send
// X-AppCrane-App-Roles, every hosted app's authorization would be self-service —
// so the strip is asserted per handle block, not "somewhere in the file". The
// v2.40.0 route{} regression is re-checked here for the same reason: a strip
// written outside route{} compiles BELOW forward_auth and deletes the identity
// that copy_headers just wrote, which is a shape that reads correctly on disk
// and delivers nothing.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-approles-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkApp = (name, slug, slot, extra = {}) => {
  const id = db.prepare(
    `INSERT INTO apps (name,slug,slot,source_type,auth_mode,auth_bypass_paths,domain,visibility)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(name, slug, slot, 'managed',
        extra.auth_mode ?? 'forward_auth',
        extra.auth_bypass_paths ?? null,
        extra.domain ?? null,
        extra.visibility ?? 'private').lastInsertRowid;
  for (const env of extra.envs ?? ['production', 'sandbox']) {
    db.prepare('INSERT INTO deployments (app_id, env, status) VALUES (?,?,?)').run(id, env, 'live');
  }
  return id;
};

// The four route shapes an app can be proxied through, plus a second app so
// "roles are per-app" is testable rather than asserted.
const APP_A = mkApp('Alpha', 'ar-alpha', 1);
const APP_B = mkApp('Beta', 'ar-beta', 2, { envs: ['production'] });
mkApp('Headless', 'ar-headless', 3, { auth_mode: 'headless' });
mkApp('Bypass', 'ar-bypass', 4, { auth_bypass_paths: JSON.stringify(['/ws/runner']) });
mkApp('Custom', 'ar-custom', 5, { domain: 'arcustom.test.local', envs: ['production'] });

let seq = 0;
function mkUser(craneRole) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const uid = db.prepare(
    'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
  ).run(`ar${n}`, `ar${n}@t.test`, craneRole, hashApiKey(key)).lastInsertRowid;
  const token = `ar-tok-${n}`;
  db.prepare(
    "INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))"
  ).run(uid, hashApiKey(token));
  return { uid, key, token };
}

const defineRole = (appId, key) =>
  db.prepare('INSERT INTO app_defined_roles (app_id, key, label) VALUES (?,?,?)')
    .run(appId, key, key).lastInsertRowid;

const grantRole = (appId, roleId, uid) =>
  db.prepare('INSERT INTO app_role_grants (role_id, user_id, app_id) VALUES (?,?,?)')
    .run(roleId, uid, appId);

const seatOnApp = (appId, uid, appRole) => {
  db.prepare('INSERT OR IGNORE INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, uid);
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, uid, appRole);
};

// The SAME key 'auditor' is defined on BOTH apps. That is what makes the
// cross-app test sharp: a lookup that forgot to scope by app_id, or that
// resolved by key alone, would hand app B's identity to a grant issued on app A
// and the two would be indistinguishable if the vocabularies were disjoint.
const A_AUDITOR  = defineRole(APP_A, 'auditor');
const A_APPROVER = defineRole(APP_A, 'approver');
const A_ZEBRA    = defineRole(APP_A, 'zebra');
defineRole(APP_B, 'auditor');
const B_REVIEWER = defineRole(APP_B, 'reviewer');

// Holds three roles on app A, none on app B. Granted auditor → zebra → approver
// on purpose: sorted is approver,auditor,zebra, so neither insertion order NOR
// its reverse matches. A fixture that merely "looks scrambled" is not enough —
// three items inserted in reverse-sorted order come back sorted under any
// descending scan, and the sort assertion passes while nothing sorts.
const MULTI = mkUser('user');
grantRole(APP_A, A_AUDITOR, MULTI.uid);
grantRole(APP_A, A_ZEBRA, MULTI.uid);
grantRole(APP_A, A_APPROVER, MULTI.uid);
seatOnApp(APP_A, MULTI.uid, 'user');
seatOnApp(APP_B, MULTI.uid, 'user');

// A member of app A with no app-defined roles at all.
const PLAIN = mkUser('user');
seatOnApp(APP_A, PLAIN.uid, 'user');

// A platform_admin with no grant anywhere. resolveAppRole short-circuits them to
// 'admin' on every app; app-defined roles must NOT follow.
const PADMIN = mkUser('platform_admin');

// A platform_admin who WAS explicitly granted one role — proves the empty result
// above is a missing grant, not a blanket exclusion of admins. Seated on the app
// with bare membership because that is the precondition the grant API enforces:
// a grant is only live while its holder is a member, so a grant row without an
// app_users row is a state no caller can reach.
const PADMIN_GRANTED = mkUser('platform_admin');
db.prepare('INSERT OR IGNORE INTO app_users (app_id,user_id) VALUES (?,?)').run(APP_A, PADMIN_GRANTED.uid);
grantRole(APP_A, A_APPROVER, PADMIN_GRANTED.uid);

// Holds a role on app B only — the mirror of MULTI, so a leak in either
// direction is caught.
const BONLY = mkUser('user');
grantRole(APP_B, B_REVIEWER, BONLY.uid);
seatOnApp(APP_A, BONLY.uid, 'user');
seatOnApp(APP_B, BONLY.uid, 'user');

const { generateCaddyfile } = await import('../server/services/caddy.js');
const CF = generateCaddyfile();

// ---------------------------------------------------------------------------
// /api/me — the callback surface. Real route, real DB.
// ---------------------------------------------------------------------------

const meRouter = (await import('../server/routes/me.js')).default;
const identityRouter = (await import('../server/routes/identity.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use('/api', meRouter);
api.use('/api/identity', identityRouter);
api.use(errorHandler);

const server = await new Promise(resolve => {
  const s = api.listen(0, '127.0.0.1', () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); });

async function me(user, slug) {
  const r = await fetch(`${BASE}/api/me${slug ? `?app=${slug}` : ''}`, {
    headers: { 'X-API-Key': user.key },
  });
  return { status: r.status, body: await r.json() };
}

test('/api/me returns the keys the user holds, sorted', async () => {
  const r = await me(MULTI, 'ar-alpha');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.app_roles, ['approver', 'auditor', 'zebra'],
    'app_roles must be the sorted key list — apps compare these strings directly, ' +
    'and an unstable order turns any cached/diffed comparison into a false change');
});

test('/api/me returns [] — not null, not absent — for a member holding none', async () => {
  const r = await me(PLAIN, 'ar-alpha');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(Array.isArray(r.body.app_roles), 'app_roles must always be an array in app context');
  assert.deepEqual(r.body.app_roles, []);
});

test('roles do not cross app boundaries, even on a shared key name', async () => {
  // MULTI holds 'auditor' on app A. App B also DEFINES 'auditor'. If the lookup
  // resolved by key, or forgot g.app_id, app B would be told this person is an
  // auditor there — a role its own code enforces — because of a grant issued by
  // a different app's owner.
  const r = await me(MULTI, 'ar-beta');
  assert.deepEqual(r.body.app_roles, [],
    "a grant on app A was reported as a role on app B");
});

test('and the leak is not one-directional', async () => {
  const onB = await me(BONLY, 'ar-beta');
  assert.deepEqual(onB.body.app_roles, ['reviewer'], 'test premise broken: no grant on app B');
  const onA = await me(BONLY, 'ar-alpha');
  assert.deepEqual(onA.body.app_roles, []);
});

test('a platform_admin with no explicit grant holds NOTHING', async () => {
  // The rule this exists for. resolveAppRole short-circuits a platform_admin to
  // app_role 'admin' on every app, and folding app-defined roles into that same
  // short-circuit is the obvious "helpful" edit. It would hand every hosted
  // app's most privileged in-app role — whatever the app owner named it — to
  // anyone holding a platform role, and it is the implicit role collapse that
  // once made an app deny its own owner.
  const r = await me(PADMIN, 'ar-alpha');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.user.role, 'platform_admin', 'test premise broken');
  assert.equal(r.body.app_role, 'admin', 'test premise broken: the platform short-circuit is gone');
  assert.deepEqual(r.body.app_roles, [],
    'a platform_admin was handed app-defined roles nobody granted them');
});

test('an explicitly granted platform_admin gets exactly that grant', async () => {
  // The complement: the emptiness above is a missing grant, not admins being
  // excluded. Grants are explicit — in both directions.
  const r = await me(PADMIN_GRANTED, 'ar-alpha');
  assert.deepEqual(r.body.app_roles, ['approver']);
});

test('app-defined roles change nothing about the AppCrane tier', async () => {
  // The separation, observed from the wire: MULTI holds three app roles and is
  // still a plain platform 'user' seated as 'user' on the app. That combination
  // is the entire feature — if either field moved, an app owner would be
  // authoring AppCrane privileges through their own settings form.
  const r = await me(MULTI, 'ar-alpha');
  assert.equal(r.body.user.role, 'user');
  assert.equal(r.body.app_role, 'user');
  assert.equal(r.body.app_roles.length, 3, 'test premise broken');
});

test('no app context means no app_roles field at all', async () => {
  const r = await me(MULTI, null);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(!('app_roles' in r.body), 'app_roles leaked into the global-only payload');
  assert.ok(!('app_role' in r.body), 'test premise broken: app context resolved anyway');
});

test('the -sandbox suffix resolves to the same app and the same keys', async () => {
  // Sandbox runs at /<slug>-sandbox/* but grants are keyed to the base app. If
  // the fallback did not apply to the role lookup, every sandbox would report an
  // empty set and an app would behave differently in its own test environment.
  const r = await me(MULTI, 'ar-alpha-sandbox');
  assert.equal(r.body.app, 'ar-alpha', 'test premise broken: suffix fallback did not resolve');
  assert.deepEqual(r.body.app_roles, ['approver', 'auditor', 'zebra']);
});

// ---------------------------------------------------------------------------
// X-AppCrane-App-Roles — the header /verify issues and Caddy copies.
// ---------------------------------------------------------------------------

async function verify(user, slug) {
  const r = await fetch(`${BASE}/api/identity/verify?app=${slug}&prefix=/${slug}`, {
    headers: { Authorization: `Bearer ${user.token}` },
    redirect: 'manual',
  });
  return {
    status: r.status,
    appRoles: r.headers.get('x-appcrane-app-roles'),
    appRole: r.headers.get('x-appcrane-app-role'),
    isAdmin: r.headers.get('x-appcrane-is-admin'),
  };
}

test('/verify emits the keys comma-separated and sorted', async () => {
  const r = await verify(MULTI, 'ar-alpha');
  assert.equal(r.status, 200);
  assert.equal(r.appRoles, 'approver,auditor,zebra');
});

test('the header is OMITTED, not empty, when the user holds none', async () => {
  // An app's natural read is `header?.split(',')`. An empty string splits to
  // [''] — one phantom role named '' that no app defines, and any `includes()`
  // gate written against it behaves unpredictably. Absence is unambiguous.
  const r = await verify(PLAIN, 'ar-alpha');
  assert.equal(r.status, 200);
  assert.equal(r.appRoles, null,
    `X-AppCrane-App-Roles was present as ${JSON.stringify(r.appRoles)}; it must be absent`);
});

test('a denied user is told nothing about what they hold', async () => {
  // The header is emitted after the app_role === 'none' denial, so a 403 never
  // carries it. The user under test HOLDS grants — a stranger with none would
  // pass this even if the emission were hoisted above the denial, because there
  // would be nothing to leak.
  //
  // Dangling grants are not hypothetical: revoking app access does not delete
  // app_role_grants, so "app_role none, grants intact" is exactly the state a
  // removed member is left in.
  const revoked = mkUser('user');
  grantRole(APP_A, A_AUDITOR, revoked.uid);
  grantRole(APP_A, A_ZEBRA, revoked.uid);
  const r = await verify(revoked, 'ar-alpha');
  assert.equal(r.status, 403, 'test premise broken: this user was not denied');
  assert.equal(r.appRoles, null,
    `a denied response carried app-defined roles (${r.appRoles}) — someone who cannot ` +
    "enter the app just learned its role vocabulary from the 403");
});

test('/verify agrees with /api/me, key for key', async () => {
  // Two surfaces answering the same question must not drift. A second hand-rolled
  // query in either place is how they would.
  const h = (await verify(MULTI, 'ar-alpha')).appRoles.split(',');
  const j = (await me(MULTI, 'ar-alpha')).body.app_roles;
  assert.deepEqual(h, j);
});

test('/verify keeps App-Role and Is-Admin untouched by app-defined roles', async () => {
  const r = await verify(MULTI, 'ar-alpha');
  assert.equal(r.appRole, 'user', 'app-defined roles moved the AppCrane per-app tier');
  assert.equal(r.isAdmin, '0',
    "holding an app-defined role called anything at all must not set the platform's admin bit");
});

test('a platform_admin gets no roles on the header either', async () => {
  const r = await verify(PADMIN, 'ar-alpha');
  assert.equal(r.appRole, 'admin', 'test premise broken');
  assert.equal(r.appRoles, null, 'the global-admin short-circuit leaked into app-defined roles');
});

test('/verify scopes to the resolved app', async () => {
  assert.equal((await verify(MULTI, 'ar-beta')).appRoles, null);
  assert.equal((await verify(BONLY, 'ar-beta')).appRoles, 'reviewer');
});

// ---------------------------------------------------------------------------
// Caddy. The header is only trustworthy if a client cannot send it, on EVERY
// route that can reach a container — including the routes that run no
// forward_auth, where a forged value has nothing to overwrite it.
// ---------------------------------------------------------------------------

function braceBlocks(text, re) {
  const blocks = [];
  let m;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) {
    const start = m.index;
    let depth = 0, i = text.indexOf('{', start), end = i;
    for (; i < text.length; i++) {
      if (text[i] === '{') depth++;
      else if (text[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    blocks.push({ path: m[1] || '(catch-all)', body: text.slice(start, end + 1) });
  }
  return blocks;
}

const HANDLES = braceBlocks(CF, /^\s*handle ([^\s{]*)\s*\{$/gm);
// Custom-domain apps are site blocks, not handle blocks; a helper that only
// walked `handle` would skip the one route shape with no forward_auth at all.
const SITES = braceBlocks(CF, /^(\S+) \{$/gm).filter(s => s.path !== 'crane.test.local');
const proxiesToApp = b => /reverse_proxy 127\.0\.0\.1:(4\d{3}|[5-9]\d{3})/.test(b.body)
  && !/reverse_proxy 127\.0\.0\.1:5001/.test(b.body);

test('the generated Caddyfile actually contains the routes under test', () => {
  // Guards every per-block loop below against passing vacuously.
  const paths = HANDLES.map(b => b.path);
  for (const p of ['/ar-alpha*', '/ar-alpha-sandbox*', '/ar-headless*', '/ar-headless-sandbox*',
                   '/ar-bypass*', '/ar-bypass/ws/runner*', '/ar-bypass-sandbox/ws/runner*']) {
    assert.ok(paths.includes(p), `handle ${p} missing from generated config`);
  }
  assert.ok(SITES.some(s => s.path === 'arcustom.test.local'), 'custom-domain site block missing');
});

test('EVERY app-proxying block strips a client-supplied X-AppCrane-App-Roles', () => {
  // Asserting "the string appears in the file" would pass with one route covered
  // and every other one open. The bypass and headless routes are the dangerous
  // ones: they never call /verify, so nothing overwrites what the client sent.
  const all = [...HANDLES.filter(proxiesToApp), ...SITES];
  assert.ok(all.length >= 8, `expected several app-proxying blocks, got ${all.length}`);
  const unstripped = all
    .filter(b => !b.body.includes('request_header -X-AppCrane-App-Roles\n'))
    .map(b => b.path);
  assert.deepEqual(unstripped, [],
    'these routes deliver a client-supplied X-AppCrane-App-Roles straight to the app ' +
    `container, making every in-app permission check self-service:\n  ${unstripped.join('\n  ')}`);
});

test('the strip travels with the rest of the identity list, not on its own', () => {
  // IDENTITY_HEADERS is one array driving both the strip and the copy. If
  // App-Roles were stripped by a second, separate mechanism it would drift out
  // of one of them — which is the documented history of both duplicated security
  // rules in this file.
  for (const b of [...HANDLES.filter(proxiesToApp), ...SITES]) {
    assert.ok(b.body.includes('request_header -X-AppCrane-User-Role\n'),
      `${b.path}: test premise broken, no identity strip here at all`);
    assert.ok(b.body.includes('request_header -X-AppCrane-App-Roles\n'),
      `${b.path}: App-Roles is stripped separately from the identity list, or not at all`);
  }
});

test('forward_auth copies the platform value back', () => {
  const authed = HANDLES.filter(b => /forward_auth/.test(b.body));
  assert.ok(authed.length >= 2, `expected forward_auth routes, got ${authed.length}`);
  for (const b of authed) {
    assert.match(b.body, /copy_headers [^\n]*\bX-AppCrane-App-Roles\b/,
      `handle ${b.path} strips App-Roles but never copies the platform's value back — ` +
      'the app would never receive its own roles');
  }
});

test('no route sets X-AppCrane-App-Roles to a constant', () => {
  // The value is per-user and comes only from /verify. A Caddyfile-level
  // `request_header X-AppCrane-App-Roles "..."` would hand every visitor the
  // same roles.
  assert.doesNotMatch(CF, /request_header \+?X-AppCrane-App-Roles "/,
    'app-defined roles must be issued per request by /verify, never stamped by the proxy');
});

// ---------------------------------------------------------------------------
// v2.40.0 regression. Adding a header to IDENTITY_HEADERS is exactly the kind of
// edit that could reintroduce the shape where the strips sit outside route{}.
// ---------------------------------------------------------------------------

test('the identity strip is still written INSIDE route{}, above forward_auth', () => {
  // Caddy sorts directives by its own fixed order, not file order, and
  // forward_auth sorts AHEAD of request_header. A strip written as a direct child
  // of `handle` therefore compiles BELOW forward_auth and deletes every header
  // copy_headers just wrote — including the new one. The file reads correctly and
  // the app receives nothing.
  for (const b of HANDLES.filter(x => /forward_auth/.test(x.body))) {
    const route = b.body.match(/route \{[\s\S]*?\n {8}\}/);
    assert.ok(route, `handle ${b.path}: forward_auth is not wrapped in route{}`);
    const inner = route[0];
    assert.ok(inner.includes('forward_auth'), `handle ${b.path}: route{} does not contain forward_auth`);
    const strip = inner.indexOf('request_header -X-AppCrane-App-Roles');
    const fa = inner.indexOf('forward_auth');
    assert.notEqual(strip, -1,
      `handle ${b.path}: the App-Roles strip is outside route{} — it will compile below ` +
      'forward_auth and delete the identity that was just copied');
    assert.ok(strip < fa,
      `handle ${b.path}: the App-Roles strip is written after forward_auth inside route{}, ` +
      'so it eats the platform value');
  }
});

test('the cc_token strip still runs AFTER forward_auth, inside the same route', () => {
  // The other half of the ordering, load-bearing in the opposite direction:
  // request_header sorts after forward_auth but BEFORE route, so a cookie strip
  // left at handle level compiles ahead of the whole route and /verify never sees
  // cc_token — which 302s every logged-in browser visitor into a login loop.
  for (const b of HANDLES.filter(x => /forward_auth/.test(x.body))) {
    const inner = b.body.match(/route \{[\s\S]*?\n {8}\}/)[0];
    const cookie = inner.indexOf('request_header Cookie');
    const fa = inner.indexOf('forward_auth');
    assert.notEqual(cookie, -1, `handle ${b.path}: the cc_token strip left the route block`);
    assert.ok(cookie > fa,
      `handle ${b.path}: cc_token is stripped before forward_auth runs, so /verify sees no ` +
      'session and redirects every browser visitor to /login');
  }
});

// ---------------------------------------------------------------------------
// Real Caddy. The deploy path gates on `caddy adapt`; a file it refuses does not
// break routing, it means the change silently never applies.
// ---------------------------------------------------------------------------

const DOCKER = (() => {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; }
  catch { return false; }
})();
const noDocker = DOCKER ? false : 'docker unavailable';
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-approles-caddy-'));

function adapt() {
  const p = join(SCRATCH, 'Caddyfile');
  writeFileSync(p, CF);
  return execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
    { stdio: 'pipe', timeout: 120000 }).toString();
}

test('the generated Caddyfile passes real `caddy adapt`', { skip: noDocker }, () => {
  // execFileSync throws on any non-zero exit, so reaching the end is exit 0.
  const out = adapt();
  assert.ok(out.length > 0, 'adapt produced no JSON');
});

test('adapted JSON: App-Roles is deleted BEFORE forward_auth on every authed route',
  { skip: noDocker }, () => {
  // Only the handler order in the adapted JSON is the order Caddy runs. The
  // static route{} assertion above is a proxy for this one; this is the ground
  // truth, and it is what would have caught the v2.40.0 defect.
  const cfg = JSON.parse(adapt());

  function chain(handlers, acc = []) {
    for (const h of handlers || []) {
      if (h.handler === 'subroute') {
        for (const rt of h.routes || []) chain(rt.handle, acc);
        continue;
      }
      if (h.handler === 'headers') {
        for (const d of h.request?.delete || []) acc.push(`del:${d.toLowerCase()}`);
        for (const k of Object.keys(h.request?.set || {})) acc.push(`set:${k.toLowerCase()}`);
        continue;
      }
      // forward_auth adapts to a reverse_proxy carrying handle_response.
      acc.push(h.handle_response ? 'forward_auth' : h.handler);
    }
    return acc;
  }
  function routesMatching(routes, needle, acc = []) {
    for (const rt of routes || []) {
      if (JSON.stringify(rt.match || '').includes(needle)) acc.push(rt);
      for (const h of rt.handle || []) if (h.routes) routesMatching(h.routes, needle, acc);
    }
    return acc;
  }

  for (const slug of ['/ar-alpha*', '/ar-alpha-sandbox*']) {
    const [rt] = routesMatching(cfg.apps.http.servers.srv0.routes, `"${slug}"`);
    assert.ok(rt, `${slug} route missing from adapted JSON`);
    const ops = chain(rt.handle);
    const fa = ops.indexOf('forward_auth');
    assert.notEqual(fa, -1, `${slug}: no forward_auth in the adapted config`);
    const del = ops.lastIndexOf('del:x-appcrane-app-roles');
    assert.notEqual(del, -1, `${slug}: the App-Roles strip vanished on adapt`);
    assert.ok(del < fa,
      `${slug}: App-Roles is deleted BELOW forward_auth (${ops.join(' → ')}). ` +
      'The platform value copy_headers writes is deleted before the app proxy runs.');
  }
});

test('adapted JSON: routes with no forward_auth still delete App-Roles',
  { skip: noDocker }, () => {
  // Headless, per-path bypass and the custom domain never verify anyone. They
  // are where a forged header survives if the strip is missing, because there is
  // no copy_headers behind it to overwrite the client's value.
  const cfg = JSON.parse(adapt());
  const deletesAppRoles = (node) => JSON.stringify(node).toLowerCase().includes('x-appcrane-app-roles');

  function routesMatching(routes, needle, acc = []) {
    for (const rt of routes || []) {
      if (JSON.stringify(rt.match || '').includes(needle)) acc.push(rt);
      for (const h of rt.handle || []) if (h.routes) routesMatching(h.routes, needle, acc);
    }
    return acc;
  }

  const servers = Object.values(cfg.apps.http.servers);
  for (const needle of ['/ar-headless*', '/ar-bypass/ws/runner*']) {
    const found = servers.flatMap(s => routesMatching(s.routes, `"${needle}"`));
    assert.ok(found.length > 0, `${needle} missing from adapted JSON`);
    assert.ok(found.some(deletesAppRoles), `${needle}: no App-Roles strip survived adapt`);
  }

  const custom = servers.flatMap(s => routesMatching(s.routes, 'arcustom.test.local'));
  assert.ok(custom.length > 0, 'custom-domain route missing from adapted JSON');
  assert.ok(custom.some(deletesAppRoles), 'custom domain: no App-Roles strip survived adapt');
});
