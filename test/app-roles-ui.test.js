import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// App-defined roles, admin SPA side (v2.41.0).
//
// The whole point of the feature is that AppCrane's own per-app tier and the
// roles an app invents for itself stay two different things. In the UI that
// separation is one character wide: /api/apps/:slug/roles sets the platform
// tier, /api/apps/:slug/app-roles edits the app's own vocabulary. A modal
// wired to the wrong one would look correct, save without error, and silently
// rewrite the platform's authorization instead of the app's — so the endpoint
// is asserted structurally rather than eyeballed.
//
// studio-web/ is TypeScript compiled into docs/admin-app/, and THAT is what is
// served. A source-only change that was never rebuilt ships nothing, so the
// built bundle is checked too (same reasoning as test/sso-token-referer.test.js).

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const MODAL = readFileSync(join(ROOT, 'studio-web/src/components/AppAccessModal.tsx'), 'utf8');
const APPLICATIONS = readFileSync(join(ROOT, 'studio-web/src/pages/Applications.tsx'), 'utf8');
const ADMIN_API = readFileSync(join(ROOT, 'studio-web/src/adminApi.ts'), 'utf8');
const SERVICE = readFileSync(join(ROOT, 'server/services/appDefinedRoles.js'), 'utf8');
const ROUTES = readFileSync(join(ROOT, 'server/routes/appRoles.js'), 'utf8');

const ASSETS_DIR = join(ROOT, 'docs/admin-app/assets');
const INDEX_HTML = readFileSync(join(ROOT, 'docs/admin-app/index.html'), 'utf8');

/** Body of a top-level `async function <name>` in the modal, up to the next one. */
function fnBody(src, name) {
  const start = src.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `AppAccessModal no longer defines ${name}() — re-check this guard`);
  const next = src.indexOf('\n  async function ', start + 1);
  return src.slice(start, next === -1 ? src.length : next);
}

// ---------------------------------------------------------------- built output

test('exactly one SPA bundle ships — no stale sibling left in docs/admin-app', () => {
  // Vite hashes the filename, so a rebuild without emptyOutDir leaves the old
  // bundle sitting next to the new one. Both then get served as static files,
  // and any assertion that greps "the bundle" starts reading whichever it finds
  // first. index.html is the only thing that says which is live.
  const bundles = readdirSync(ASSETS_DIR).filter(f => f.endsWith('.js'));
  assert.equal(bundles.length, 1,
    `expected one .js bundle under docs/admin-app/assets, found ${bundles.length}: ` +
    `${bundles.join(', ')} — delete the stale one(s), rebuild with emptyOutDir`);
  assert.ok(INDEX_HTML.includes(bundles[0]),
    `docs/admin-app/index.html does not reference ${bundles[0]} — the shipped ` +
    'page loads a bundle that is not on disk');
});

test('the shipped bundle carries the app-roles UI, not just the source tree', () => {
  const bundles = readdirSync(ASSETS_DIR).filter(f => f.endsWith('.js'));
  const built = readFileSync(join(ASSETS_DIR, bundles[0]), 'utf8');

  // Minification renames `slug` to a single letter but leaves the literal
  // segments of the template alone, so the paths survive verbatim apart from
  // the interpolation. Matching on those is what proves the modal was compiled
  // in, rather than that some unrelated string happens to appear.
  const built_paths = new Set(
    [...built.matchAll(/\/api\/apps\/\$\{[^}]+\}\/app-roles[^`"']*/g)]
      .map(m => m[0].replace(/\$\{[^}]+\}/g, '${}')),
  );

  for (const expected of [
    '/api/apps/${}/app-roles',            // list + create
    '/api/apps/${}/app-roles/${}',        // update + delete
    '/api/apps/${}/app-roles/members',    // members read
    '/api/apps/${}/app-roles/members/${}', // grant write
  ]) {
    assert.ok(built_paths.has(expected),
      `the built bundle never calls ${expected} — docs/admin-app/ is stale, ` +
      'rebuild studio-web before committing');
  }
});

// ---------------------------------------------------------- the endpoint split

test('the modal talks to /app-roles, never to the platform-tier /roles route', () => {
  // /api/apps/:slug/roles (server/routes/users.js) writes app_user_roles — who
  // may deploy, read env, delete. Pointing this modal at it would turn an
  // app-owner's "define a role" form into an edit of AppCrane's own authz.
  const APP_ROLES = /`\/api\/apps\/\$\{slug\}\/app-roles/;
  assert.match(MODAL, APP_ROLES, 'AppAccessModal calls no /app-roles endpoint at all');

  // Non-vacuity: the platform-tier path must NOT satisfy the regex above, or
  // the assertion would pass on exactly the mistake it exists to catch.
  assert.doesNotMatch('`/api/apps/${slug}/roles`', APP_ROLES,
    'the /app-roles matcher also accepts the platform-tier path — it proves nothing');

  const paths = [...MODAL.matchAll(/adminApi\.\w+(?:<[^<>]*>)?\(\s*`([^`]+)`/g)].map(m => m[1]);
  assert.ok(paths.length >= 5, `expected the modal to make several API calls, found ${paths.length}`);

  for (const p of paths) {
    // The read-only platform-tier chip is sourced from identity/users, which is
    // a read. Everything else must be an app-roles path.
    const allowed = p.startsWith('/api/apps/${slug}/app-roles')
      || p === '/api/apps/${slug}/identity/users';
    assert.ok(allowed, `AppAccessModal calls ${p} — not an app-defined-role endpoint`);
  }
  assert.ok(!paths.includes('/api/apps/${slug}/roles'),
    'AppAccessModal writes the platform tier — that belongs to the Users modal');
});

test('every path the modal calls is actually declared by the app-roles router', () => {
  // Catches a rename on either side: a modal calling /app-roles/grants, or a
  // router that moved /members, both fail here rather than at runtime with a 404.
  const declared = new Set(
    [...ROUTES.matchAll(/router\.\w+\(\s*'\/:slug\/(app-roles[^']*)'/g)]
      .map(m => '/' + m[1].replace(/:\w+/g, '${}')),
  );
  // Four distinct paths across five routes — GET and POST share /app-roles.
  assert.ok(declared.size >= 4, `expected the router to declare several app-roles paths, found ${declared.size}`);

  const called = [...MODAL.matchAll(/adminApi\.\w+(?:<[^<>]*>)?\(\s*`([^`]+)`/g)]
    .map(m => m[1])
    .filter(p => p.includes('/app-roles'))
    .map(p => p.replace('/api/apps/${slug}', '').replace(/\$\{[^}]+\}/g, '${}'));

  // Non-vacuity: with no calls extracted the loop below asserts nothing, so an
  // empty or endpoint-free modal would pass the test named "every path the
  // modal calls is declared".
  assert.ok(called.length >= 4,
    `expected the modal to call several app-roles paths, found ${called.length}`);

  for (const p of called) {
    assert.ok(declared.has(p),
      `AppAccessModal calls ${p}, which server/routes/appRoles.js does not declare. ` +
      `Declared: ${[...declared].join(', ')}`);
  }
});

test('adminApi exposes the patch verb the update endpoint needs', () => {
  // The role update is PATCH; before v2.41.0 adminApi had no patch helper, so a
  // half-landed change would compile as `adminApi.patch is not a function`.
  assert.match(ADMIN_API, /const patch = <T>\(path: string, body: unknown\) =>/);
  assert.match(ADMIN_API, /export const adminApi = \{[^}]*\bpatch\b/,
    'adminApi defines patch but never exports it');
});

// ------------------------------------------------------- the key is immutable

test('the edit flow cannot send a role key', () => {
  // updateRole() rewrites label/description only, and the route 400s with
  // KEY_IMMUTABLE if a key is present at all: the key is the string the hosted
  // app compares against, so rewriting it would re-point every existing grant
  // at a permission the app has never heard of. The UI must make that
  // unreachable, not merely surface the error.
  const save = fnBody(MODAL, 'saveEdit');
  const KEY_FIELD = /\bkey\s*:/;

  // Non-vacuity: the matcher must fire on a body that does carry a key.
  assert.match('{ key: keyTrimmed, label }', KEY_FIELD,
    'the key-field matcher cannot detect a key in a request body');

  assert.match(save, /adminApi\.patch/, 'saveEdit no longer PATCHes the role');
  assert.doesNotMatch(save, KEY_FIELD,
    'saveEdit sends a key field; the server rejects it with KEY_IMMUTABLE and ' +
    'the key must not be editable in the first place');
  assert.match(save, /label:/, 'saveEdit sends no label');
  assert.match(save, /description:/, 'saveEdit sends no description');

  // No edit state exists for the key, so there is nothing to bind an input to.
  assert.doesNotMatch(MODAL, /setEditKey|\[editKey/,
    'the modal holds editable key state — the key must be immutable after creation');
});

test('the key is presented as immutable, and the create form says so up front', () => {
  assert.match(MODAL, /title="Immutable[^"]*Delete and recreate/,
    'the key cell no longer explains that the key cannot be changed');
  assert.match(MODAL, /can never be changed/,
    'the create form no longer warns that the key is permanent before it is chosen');
  // Editing seeds label and description only.
  assert.match(MODAL, /setEditLabel\(role\.label\)/);
  assert.match(MODAL, /setEditDesc\(role\.description \|\| ''\)/);
});

// ------------------------------------------------------------- delete is loud

test('deleting a role tells the operator how many people lose it', () => {
  // The grants cascade. The count has to come from the live members list this
  // screen mutates, not from a member_count fetched before any chip was toggled,
  // or the confirmation understates the blast radius.
  const remove = fnBody(MODAL, 'removeRole');

  const holders = remove.indexOf('holdersOf(role)');
  const confirmAt = remove.indexOf('confirm(');
  assert.notEqual(holders, -1, 'removeRole never counts the holders of the role it deletes');
  assert.notEqual(confirmAt, -1, 'removeRole deletes without confirming');
  assert.ok(holders < confirmAt, 'the holder count is computed after the confirmation, too late to appear in it');

  const COUNT_IN_TEXT = /\$\{n\}\s/;
  assert.doesNotMatch('`Delete the role?`', COUNT_IN_TEXT,
    'the count matcher accepts a message with no count in it');
  assert.match(remove, COUNT_IN_TEXT,
    'the count is computed but never interpolated into the message shown to the operator');

  assert.match(remove, /confirm\(`[^`]*\$\{who\}/,
    'the sentence naming the affected people is not part of the confirm() text');
  assert.match(remove, /will lose it/,
    'the confirmation does not say the holders lose the role');
  assert.match(remove, /grants are not restored if you recreate the key/,
    'the confirmation does not warn that recreating the key does not restore grants');
});

test('holder counts are live, falling back to the server count only when members failed to load', () => {
  const start = MODAL.indexOf('function holdersOf(');
  assert.notEqual(start, -1, 'holdersOf() is gone — the delete count would go stale');
  const body = MODAL.slice(start, MODAL.indexOf('\n  }', start));
  assert.match(body, /members\.filter\(m => m\.app_roles\.includes\(role\.key\)\)\.length/,
    'holdersOf no longer derives the count from the members list this screen mutates');
  assert.match(body, /if \(!members\) return role\.member_count/,
    'holdersOf has no fallback for a failed members fetch');
});

// -------------------------------------------------- client mirrors the server

test('the form\'s copy of the server validation rules has not drifted', () => {
  // These are duplicated so the form can refuse before the POST. The server is
  // the enforcer, but a drifted client either blocks a legal key or promises a
  // key the server will reject — and RESERVED_KEYS specifically is the list
  // that stops an app owner naming their role after an AppCrane one.
  const serverPattern = /export const ROLE_KEY_PATTERN = (\S+);/.exec(SERVICE)[1];
  const clientPattern = /^const ROLE_KEY_PATTERN = (\S+)$/m.exec(MODAL)[1];
  assert.equal(clientPattern, serverPattern,
    'AppAccessModal\'s key pattern differs from server/services/appDefinedRoles.js');

  const parseList = s => JSON.parse(/RESERVED_KEYS = (\[[^\]]*\])/.exec(s)[1].replace(/'/g, '"'));
  assert.deepEqual(parseList(MODAL), parseList(SERVICE),
    'the reserved-key list drifted — a key AppCrane reserves is offered in the form, or vice versa');

  const serverMax = /export const MAX_ROLES_PER_APP = (\d+);/.exec(SERVICE)[1];
  const clientMax = /^const MAX_ROLES_PER_APP = (\d+)$/m.exec(MODAL)[1];
  assert.equal(clientMax, serverMax, 'the per-app role cap drifted from the server');
});

test('the reserved list actually covers AppCrane\'s own vocabulary', () => {
  // Belt to the drift test's braces: equality with the server would still pass
  // if both sides dropped a word. These are the strings AppCrane's own authz
  // compares against, and an app-defined role must never be able to spell one.
  const reserved = JSON.parse(/RESERVED_KEYS = (\[[^\]]*\])/.exec(MODAL)[1].replace(/'/g, '"'));
  for (const word of ['owner', 'admin', 'user', 'viewer', 'none', 'platform_admin']) { // role:platform-admin-skipped
    assert.ok(reserved.includes(word), `'${word}' is an AppCrane role name but is not reserved`);
  }
});

// ---------------------------------------------------------------- the wiring

test('Manage opens the Access modal for a specific app', () => {
  // A component nobody renders is a component nobody can report as broken.
  assert.match(APPLICATIONS, /import \{ AppAccessModal \} from '\.\.\/components\/AppAccessModal'/);
  assert.match(APPLICATIONS, /onClick=\{\(\) => setAccessModalApp\(app\)\}/,
    'no control in the app row opens the Access modal');
  assert.match(APPLICATIONS, /<AppAccessModal\b/, 'AppAccessModal is imported but never rendered');
  assert.match(APPLICATIONS, /slug=\{accessModalApp\.slug\}/,
    'the Access modal is not scoped to the app whose row was clicked');
});

test('the Access modal is separate from the Users modal, which still owns the tier', () => {
  // Two editable surfaces for the same chip is the conflation the feature is
  // meant to prevent, so the tier stays read-only here and Users keeps the PUT.
  assert.match(APPLICATIONS, /`\/api\/apps\/\$\{[^}]+\}\/roles`|\/roles`/,
    'nothing in Manage writes the platform tier any more — the Users modal lost its endpoint');
  assert.doesNotMatch(MODAL, /adminApi\.(put|post|patch|del)[^\n]*identity\/users/,
    'the Access modal writes to the tier endpoint; it must only read it');
  assert.match(MODAL, /Read-only here — change it in Users\./,
    'the tier chip no longer tells the operator where the tier is actually set');
});

test('no app-defined role is used to decide what the UI itself allows', () => {
  // The rule the whole feature rests on: an app-defined role confers nothing in
  // AppCrane. If this screen ever gated a control on someone holding a key, it
  // would be teaching operators that these roles mean something on the platform.
  // The only gate is the server's 403.
  const gates = [...MODAL.matchAll(/(?:disabled|hidden)=\{([^}]*)\}/g)].map(m => m[1]);
  assert.ok(gates.length, 'expected some disabled= expressions in the modal');
  for (const g of gates) {
    assert.doesNotMatch(g, /app_roles/,
      `a control is gated on \`${g}\` — an app-defined role must never enable or ` +
      'disable anything inside AppCrane');
  }
});
