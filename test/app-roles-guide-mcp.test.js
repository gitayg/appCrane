import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// App-defined roles (v2.41.0) reach app authors through exactly two surfaces:
// the onboarding guide that appcrane_get_guide serves to the agents writing the
// apps, and the MCP tool descriptions an agent picks from. Both are documents,
// and documents in this repo have drifted from the code before with nothing
// catching it — guide-identity-accuracy.test.js exists because three claims in
// the same guide had outlived their implementation.
//
// So nothing here matches a hopeful phrase. The reserved-key list, the key
// grammar, the role cap and the authorization tiers are all EXTRACTED from the
// implementation and compared; add a reserved word to appDefinedRoles.js without
// touching the guide and this file goes red. Every detector is also proven to
// fire on the wrong text and stay quiet on the right one, because a regex that
// cannot fail proves nothing.
//
// The stakes are specific: an app-defined role must never confer an AppCrane
// privilege. An agent that confuses appcrane_create_app_role with
// appcrane_grant_app_access hands out deploy/env/delete power while intending to
// hand out an app label, and the tool description is the only thing standing in
// the way.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GUIDE_PATH = 'server/services/guides/onboarding.md';
const guide = readFileSync(join(ROOT, GUIDE_PATH), 'utf8');
const mcpSrc = readFileSync(join(ROOT, 'server/services/mcpTools.js'), 'utf8');
const restSrc = readFileSync(join(ROOT, 'server/routes/appRoles.js'), 'utf8');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-approles-doc-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);

const { initDb } = await import('../server/db.js');
initDb();

const { getToolCatalog } = await import('../server/services/mcpTools.js');
const { RESERVED_KEYS, MAX_ROLES_PER_APP, ROLE_KEY_PATTERN } =
  await import('../server/services/appDefinedRoles.js');

const CATALOG = new Map(getToolCatalog().map(t => [t.name, t]));
const NEW_TOOLS = ['appcrane_list_app_roles', 'appcrane_create_app_role', 'appcrane_set_user_app_roles'];

// ---------------------------------------------------------------------------
// Shared extraction. Markdown emphasis and backticks are noise for matching;
// line structure is not (a table row is one claim), so normalize per line and
// split only on sentence ends.
// ---------------------------------------------------------------------------
function lineStatements(text) {
  const out = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/`/g, '').replace(/\*\*/g, '').replace(/\s+/g, ' ').trim();
    if (!line) return;
    for (const s of line.split(/(?<=[.;])\s+/)) {
      const t = s.trim();
      if (t) out.push({ line: i + 1, text: t });
    }
  });
  return out;
}

// Line units alone miss any claim the author hard-wrapped across two lines —
// which in this guide includes the "do not reach for appcrane_grant_app_access"
// warning. So also read the text as reflowed paragraphs, and let the detectors
// see both views.
function paragraphStatements(text) {
  const out = [];
  const lines = text.split('\n');
  let buf = [];
  let start = 1;
  const flush = () => {
    if (!buf.length) return;
    const para = buf.join(' ').replace(/`/g, '').replace(/\*\*/g, '').replace(/\s+/g, ' ').trim();
    for (const s of para.split(/(?<=[.;])\s+/)) {
      const t = s.trim();
      if (t) out.push({ line: start, text: t });
    }
    buf = [];
  };
  lines.forEach((raw, i) => {
    if (!raw.trim()) { flush(); return; }
    if (!buf.length) start = i + 1;
    buf.push(raw.trim());
  });
  flush();
  return out;
}

function statements(text) {
  const seen = new Set();
  return [...lineStatements(text), ...paragraphStatements(text)].filter(s => {
    if (seen.has(s.text)) return false;
    seen.add(s.text);
    return true;
  });
}

function balancedBody(src, fromIndex) {
  const open = src.indexOf('{', fromIndex);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error('unbalanced braces');
}

// `X-AppCrane-App-Role` is a strict prefix of `X-AppCrane-App-Roles`, which is
// the entire hazard this section documents — so the singular matcher has to
// refuse the plural rather than count it as a mention.
const SINGULAR = /X-AppCrane-App-Role(?![-\w])/;
const PLURAL = /X-AppCrane-App-Roles(?![-\w])/;

test('the guide loaded and contains the app-defined-roles material (guards every check below)', () => {
  assert.ok(guide.length > 5000, `${GUIDE_PATH} looks empty or truncated`);
  assert.match(guide, PLURAL, 'X-AppCrane-App-Roles is not documented at all');
  assert.match(guide, SINGULAR, 'X-AppCrane-App-Role is not documented at all');
});

test('the header matchers tell singular from plural (non-vacuity)', () => {
  assert.equal(SINGULAR.test('X-AppCrane-App-Roles: approver'), false,
    'the singular matcher counts a plural mention — every check below would pass on a guide ' +
    'that documents only the new header');
  assert.equal(PLURAL.test('X-AppCrane-App-Role: admin'), false);
  assert.equal(SINGULAR.test('X-AppCrane-App-Role: admin'), true);
  assert.equal(PLURAL.test('X-AppCrane-App-Roles: approver,auditor'), true);
});

// ---------------------------------------------------------------------------
// (1) Both headers documented, and told apart. Matching on substance, not on
// one author's sentence: the claim is "the singular one is AppCrane's fixed
// tier over platform power; the plural one is the app's own vocabulary".
// ---------------------------------------------------------------------------
const APPCRANE_OWNED = /\b(appcrane'?s?|platform'?s?|fixed|not yours|built[- ]in)\b/i;
const PLATFORM_POWER = /\b(deploy|env|environment|delete|members?)\b/i;
const APP_OWNED = /\b(your|yours|app[- ]defined|invent\w*|freely|whatever fits)\b/i;
const CONTRAST = /\b(singular|plural|differ\w*|not the same|two (entirely )?different|confus\w*|one letter apart)\b/i;

function describesSingularAsPlatformTier(text) {
  return statements(text).some(s =>
    SINGULAR.test(s.text) && !PLURAL.test(s.text)
    && APPCRANE_OWNED.test(s.text) && PLATFORM_POWER.test(s.text));
}

function describesPluralAsAppOwned(text) {
  return statements(text).some(s => PLURAL.test(s.text) && APP_OWNED.test(s.text));
}

// The two must be contrasted in one place, close enough together that a reader
// meets the distinction rather than assembling it from two distant sections.
function contrastsTheTwoHeaders(text) {
  const flat = text.replace(/`/g, '').replace(/\*\*/g, '').replace(/\s+/g, ' ');
  for (const m of flat.matchAll(/X-AppCrane-App-Roles(?![-\w])/g)) {
    const win = flat.slice(Math.max(0, m.index - 600), m.index + 600);
    if (SINGULAR.test(win) && CONTRAST.test(win)) return true;
  }
  return false;
}

test('the three distinction detectors fire on the right text and not the wrong (non-vacuity)', () => {
  assert.equal(describesSingularAsPlatformTier(
    '`X-AppCrane-App-Role` (singular): AppCrane\'s fixed tier — who may deploy, read env, delete.'), true);
  assert.equal(describesSingularAsPlatformTier(
    '`X-AppCrane-App-Role` is a header your app can read on every request.'), false,
    'naming the header is not describing it as AppCrane\'s tier over platform power');
  assert.equal(describesSingularAsPlatformTier(
    '`X-AppCrane-App-Roles` are AppCrane\'s own fixed permissions for deploy and delete.'), false,
    'the plural header must never satisfy the singular check — that mix-up is the bug');

  assert.equal(describesPluralAsAppOwned(
    '`X-AppCrane-App-Roles` carries the roles your app invented for itself.'), true);
  assert.equal(describesPluralAsAppOwned(
    '`X-AppCrane-App-Roles` is a comma-separated header, sorted, no spaces.'), false,
    'describing the wire format is not saying whose vocabulary it is');

  assert.equal(contrastsTheTwoHeaders(
    '`X-AppCrane-App-Role` (singular) is the platform tier; `X-AppCrane-App-Roles` (plural) is yours.'), true);
  assert.equal(contrastsTheTwoHeaders(
    'Both `X-AppCrane-App-Role` and `X-AppCrane-App-Roles` are set on authenticated requests.'), false,
    'listing the two headers side by side without contrasting them is exactly the doc that ' +
    'lets an author read one as a plural spelling of the other');
  assert.equal(contrastsTheTwoHeaders(
    'The plural `X-AppCrane-App-Roles` header lists app-defined keys.'), false,
    'a contrast word with no singular header nearby is not a contrast');
});

test('the guide documents the singular header as AppCrane\'s own tier', () => {
  assert.ok(describesSingularAsPlatformTier(guide),
    'nothing in the guide says X-AppCrane-App-Role is AppCrane\'s fixed tier governing deploy / env / ' +
    'delete. Without that, an app author has no way to know the plural header is a different system');
});

test('the guide documents the plural header as the app\'s own vocabulary', () => {
  assert.ok(describesPluralAsAppOwned(guide),
    'nothing in the guide attributes X-AppCrane-App-Roles to the app itself — an author who reads it ' +
    'as another platform-issued permission will look for AppCrane meaning in keys AppCrane never reads');
});

test('the guide contrasts the two headers in one place', () => {
  assert.ok(contrastsTheTwoHeaders(guide),
    'the singular and plural headers are never set against each other within reading distance. ' +
    'One letter apart, two authorization systems: the distinction has to be made where the reader is');
});

// ---------------------------------------------------------------------------
// (2) platform_admin holds no app-defined role implicitly. This is the claim
// that inverted once already (implicit role collapse is what had an app deny its
// own owner), so the guide has to state it rather than leave it inferable.
// ---------------------------------------------------------------------------
const PA_SUBJECT = /\b(platform[_ ]?admins?|global admins?|platform staff)\b/i;
const HOLDING = /\b(hold\w*|have|has|receive\w*|get|gets|granted|grants?|imply|implies|implicit\w*|automatic\w*|inherit\w*)\b/i;
const APP_ROLE_REF = /\b(app[- ]defined roles?|app_roles|your roles|these roles|role keys?)\b/i;
const NEGATED = /\b(not|never|no|no longer|isn'?t|doesn'?t|don'?t|without|until|nobody)\b/i;

function deniesImplicitPlatformAdminRoles(text) {
  return statements(text).filter(s =>
    PA_SUBJECT.test(s.text) && HOLDING.test(s.text) && APP_ROLE_REF.test(s.text) && NEGATED.test(s.text));
}

function claimsImplicitPlatformAdminRoles(text) {
  return statements(text).filter(s =>
    PA_SUBJECT.test(s.text) && HOLDING.test(s.text) && APP_ROLE_REF.test(s.text) && !NEGATED.test(s.text));
}

test('the implicit-grant detectors are not vacuous', () => {
  assert.equal(deniesImplicitPlatformAdminRoles(
    'A `platform_admin` does NOT implicitly hold your roles.').length, 1);
  // A restatement in different words must count too — the test asserts the
  // claim, not one phrasing of it.
  assert.equal(deniesImplicitPlatformAdminRoles(
    'Global admins never automatically receive app-defined roles.').length, 1);
  assert.equal(deniesImplicitPlatformAdminRoles(
    'Platform staff arrive with no app_roles until someone grants them one.').length, 1);
  // The opposite claim must not be mistaken for the retraction.
  assert.equal(deniesImplicitPlatformAdminRoles(
    'A platform_admin implicitly holds every app-defined role on every app.').length, 0);
  assert.equal(claimsImplicitPlatformAdminRoles(
    'A platform_admin implicitly holds every app-defined role on every app.').length, 1);
  // And unrelated true statements about platform admins stay out of both.
  assert.equal(deniesImplicitPlatformAdminRoles(
    'A platform_admin does not need an app_user_roles row to administer the platform.').length, 0);
});

test('the guide states that a platform_admin holds no app-defined role implicitly', () => {
  const said = deniesImplicitPlatformAdminRoles(guide);
  assert.ok(said.length >= 1,
    'the guide never tells an app author that platform staff arrive holding nothing. Grants are ' +
    'explicit only — an app that assumes otherwise will trust a platform admin its owner never approved');
});

test('the guide does not also claim the opposite somewhere else', () => {
  const bad = claimsImplicitPlatformAdminRoles(guide);
  assert.deepEqual(bad.map(b => `${GUIDE_PATH}:${b.line}: ${b.text}`), [],
    'a statement reads as "platform admins hold app-defined roles", which no code path implements');
});

// ---------------------------------------------------------------------------
// (3) THE COUPLING TEST: the reserved-key list in the guide is compared against
// the list the API actually enforces. Add a reserved word to appDefinedRoles.js
// and this fails until the guide moves with it.
// ---------------------------------------------------------------------------
function reservedListsIn(text) {
  const flat = text.replace(/\s+/g, ' ');
  const lists = [];
  for (const m of flat.matchAll(/\b(reserved|rejected)\b/gi)) {
    const win = flat.slice(Math.max(0, m.index - 220), m.index + 220);
    const keys = [...new Set([...win.matchAll(/`([a-z][a-z0-9_-]*)`/g)].map(x => x[1]))].sort();
    if (keys.length) lists.push(keys);
  }
  return lists;
}

const RESERVED_SORTED = [...RESERVED_KEYS].sort();

test('the reserved-list extractor is not vacuous', () => {
  const complete = 'Reserved and rejected: `owner`, `admin`, `user`, `viewer`, `none`, `platform_admin`.';
  assert.ok(reservedListsIn(complete).some(l => l.join() === RESERVED_SORTED.join()),
    'the extractor cannot even read a correctly written list');
  // One word short must NOT match — that is the drift this test exists to catch.
  const short = 'Reserved and rejected: `owner`, `admin`, `user`, `viewer`, `none`.';
  assert.ok(!reservedListsIn(short).some(l => l.join() === RESERVED_SORTED.join()),
    'a list missing platform_admin still counted as complete');
  assert.equal(reservedListsIn('No keys are listed near this reserved word.').length, 0);
});

test('the guide enumerates exactly the reserved keys the API rejects', () => {
  assert.ok(RESERVED_KEYS.length >= 5, 'RESERVED_KEYS looks wrong — the comparison below would be weak');
  const lists = reservedListsIn(guide);
  assert.ok(lists.some(l => l.join() === RESERVED_SORTED.join()),
    `the guide never lists exactly the keys appDefinedRoles.js rejects (${RESERVED_SORTED.join(', ')}). ` +
    `Lists found near "reserved"/"rejected": ${JSON.stringify(lists)}. An app owner who reads a stale ` +
    'list picks a key, the API 400s, and the guide is the thing that lied');

  // The coupling proven in situ, in both directions of drift.
  const last = RESERVED_SORTED[RESERVED_SORTED.length - 1];
  const guideMissingOne = guide.split(`\`${last}\``).join('');
  assert.ok(!reservedListsIn(guideMissingOne).some(l => l.join() === RESERVED_SORTED.join()),
    `dropping \`${last}\` from the real guide still passed — this test is not reading the guide`);
  const codeGainsOne = [...RESERVED_SORTED, 'superuser'].sort();
  assert.ok(!reservedListsIn(guide).some(l => l.join() === codeGainsOne.join()),
    'adding a reserved word in appDefinedRoles.js must fail this test until the guide is updated too');
});

test('the guide quotes the key grammar the API enforces, character for character', () => {
  const flat = guide.replace(/\s+/g, ' ');
  assert.ok(flat.includes(`/${ROLE_KEY_PATTERN.source}/`),
    `the guide does not contain /${ROLE_KEY_PATTERN.source}/ — keys travel in an HTTP header, so the ` +
    'grammar is a wire contract, not a style rule');
  // Non-vacuity: a near-miss grammar must not satisfy the same check.
  assert.ok(!'/^[a-z][a-z0-9_-]{0,63}$/'.includes(`/${ROLE_KEY_PATTERN.source}/`));
});

test('the guide states the per-app role cap the API enforces', () => {
  const flat = guide.replace(/[`*]/g, '').replace(/\s+/g, ' ');
  assert.match(flat, new RegExp(`\\b${MAX_ROLES_PER_APP}\\b[^.]{0,40}roles? per app`, 'i'),
    `appDefinedRoles.js caps an app at ${MAX_ROLES_PER_APP} roles but the guide does not say so`);
  // Non-vacuity: the cap has to be the real number, not any number.
  assert.ok(!new RegExp(`\\b${MAX_ROLES_PER_APP}\\b[^.]{0,40}roles? per app`, 'i')
    .test('at most 99 roles per app'));
});

// ---------------------------------------------------------------------------
// (4) The MCP tools: they exist, they are told apart from the platform-tier
// tools in their own descriptions, and their authorization matches REST's.
// ---------------------------------------------------------------------------
test('the three app-defined-role tools are in the MCP catalog', () => {
  for (const name of NEW_TOOLS) {
    assert.ok(CATALOG.has(name), `${name} is not registered — an agent cannot call what tools/list omits`);
    assert.ok((CATALOG.get(name).description || '').length > 120,
      `${name} has a description too short to distinguish it from anything`);
  }
  assert.ok(CATALOG.has('appcrane_grant_app_access'),
    'appcrane_grant_app_access is gone — the tool these must be distinguished FROM');
});

// A description earns its keep only if it names the platform-tier tool it is not
// and says what that other tool controls. "Manage roles for an app" is the
// description that gets an agent to hand out deploy rights by mistake.
const PLATFORM_TIER_TOOL = /appcrane_(grant_app_access|list_app_members)/;
const DISCLAIMS = /\b(NOT|not|never|neither|nor|instead)\b/;
const PLATFORM_CAPABILITY = /\b(deploy|env|delete|per-app tier|AppCrane privileges?|AppCrane permissions?|platform)\b/i;

function distinguishesFromPlatformTier(desc) {
  return PLATFORM_TIER_TOOL.test(desc) && DISCLAIMS.test(desc) && PLATFORM_CAPABILITY.test(desc);
}

test('the description detector rejects the descriptions that would be dangerous (non-vacuity)', () => {
  assert.equal(distinguishesFromPlatformTier('Define a new role for an app.'), false);
  assert.equal(distinguishesFromPlatformTier(
    'Define a role. See also appcrane_grant_app_access.'), false,
    'merely cross-referencing the platform-tier tool, with no statement of the difference, passed');
  assert.equal(distinguishesFromPlatformTier(
    'Define a role the app enforces itself. This does NOT grant AppCrane privileges; ' +
    'to change who may deploy or delete, use appcrane_grant_app_access.'), true);
});

test('every new tool description tells an agent it is not the platform-tier tool', () => {
  for (const name of NEW_TOOLS) {
    assert.ok(distinguishesFromPlatformTier(CATALOG.get(name).description),
      `${name}'s description does not name a platform-tier tool (appcrane_grant_app_access / ` +
      'appcrane_list_app_members) and disclaim it. An agent picking by name alone hands out real ' +
      'deploy/env/delete power while meaning to hand out an app label');
  }
});

test('the mutating tools name appcrane_grant_app_access specifically', () => {
  // Reading the wrong roster is a confusion; writing the wrong system is an
  // escalation, so the two write tools must point at the write tool they are not.
  for (const name of ['appcrane_create_app_role', 'appcrane_set_user_app_roles']) {
    assert.match(CATALOG.get(name).description, /appcrane_grant_app_access/,
      `${name} never mentions appcrane_grant_app_access — the tool an agent would otherwise reach for`);
  }
});

test('the create tool quotes the same reserved keys and cap the code enforces', () => {
  const desc = CATALOG.get('appcrane_create_app_role').description;
  for (const key of RESERVED_KEYS) {
    assert.match(desc, new RegExp(`\\b${key}\\b`),
      `appcrane_create_app_role does not tell the agent that '${key}' is rejected — it will find out ` +
      'by 400, having already told a user the role exists');
  }
  assert.match(desc, new RegExp(`\\b${MAX_ROLES_PER_APP}\\b`),
    'the per-app role cap is not in the description');
  assert.match(desc, new RegExp(ROLE_KEY_PATTERN.source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    'the key grammar in the description is not the one the code enforces');
});

// --- authorization: the MCP surface must answer the same as REST -----------
function tiersIn(body) {
  return [...new Set([...body.matchAll(/'(owner|admin|user|viewer|none)'/g)].map(m => m[1]))].sort();
}

// Both gates destructure in their parameter list, so the body is the brace
// AFTER the parameter list closes — not the first brace after the name.
function functionBody(src, marker) {
  const at = src.indexOf(marker);
  assert.notEqual(at, -1, `${marker} not found`);
  let depth = 0;
  let i = src.indexOf('(', at);
  for (; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')' && --depth === 0) break;
  }
  return balancedBody(src, i);
}

const mcpGateBody = functionBody(mcpSrc, 'function requireAppRoleTier');
const restGateBody = functionBody(restSrc, 'function requireAppRoleAdmin');

function toolSource(name) {
  const at = mcpSrc.indexOf(`name: '${name}'`);
  assert.notEqual(at, -1, `${name} not found in mcpTools.js`);
  const next = mcpSrc.indexOf("name: 'appcrane_", at + 10);
  return mcpSrc.slice(at, next === -1 ? mcpSrc.length : next);
}

test('the tier extractor is not vacuous', () => {
  assert.deepEqual(tiersIn("if (tier !== 'owner') deny();"), ['owner']);
  assert.deepEqual(tiersIn("if (tier !== 'owner' && tier !== 'admin') deny();"), ['admin', 'owner']);
  assert.notDeepEqual(tiersIn("if (tier !== 'owner') deny();"), ['admin', 'owner']);
});

test('the MCP write gate demands the same per-app tiers as the REST write gate', () => {
  assert.deepEqual(tiersIn(mcpGateBody), tiersIn(restGateBody),
    'requireAppRoleTier in server/services/mcpTools.js and requireAppRoleAdmin in ' +
    'server/routes/appRoles.js accept different tiers. One resource must not give two answers ' +
    'depending on which door the caller used');
  assert.deepEqual(tiersIn(restGateBody), ['admin', 'owner'],
    'managing an app\'s own permission vocabulary is no longer restricted to that app\'s owner/admin');
});

test('both gates resolve the tier with roleForUserOnApp, so neither admits an unassigned global admin', () => {
  for (const [where, body] of [['mcpTools.js', mcpGateBody], ['appRoles.js', restGateBody]]) {
    assert.match(body, /roleForUserOnApp/,
      `the ${where} gate no longer uses roleForUserOnApp — that resolver is what keeps a platform ` +
      'key from authoring an app\'s permission vocabulary without being assigned to the app');
  }
  // isAppAdmin() short-circuits on any AppCrane global admin. Using it here
  // would make MCP laxer than REST, where requireAppUser demands assignment
  // from every role including platform_admin (v2.39.0).
  for (const name of NEW_TOOLS) {
    const src = toolSource(name);
    assert.ok(!/\bisAppAdmin\s*\(/.test(src),
      `${name} gates on isAppAdmin, which admits a global admin who is not assigned to the app. ` +
      'The REST route for the same data does not');
    assert.match(src, /requireAppRoleTier\(/,
      `${name} does not call the app-defined-role gate at all`);
  }
});

test('requiredRole leaves the decision to the handler gate, on every one of the three', () => {
  for (const name of NEW_TOOLS) {
    assert.equal(CATALOG.get(name).requiredRole, 'any',
      `${name} declares requiredRole '${CATALOG.get(name).requiredRole}'. 'any' is the value that ` +
      'defers to requireAppRoleTier in the handler; anything else either hides the tool from the app ' +
      'owners who should have it or implies a gate the handler is not applying');
  }
});

test('the read/write split matches between MCP and REST', () => {
  const manageFlag = name => {
    const m = /requireAppRoleTier\([^)]*manage:\s*(true|false)/.exec(toolSource(name));
    assert.ok(m, `${name} does not pass an explicit manage flag`);
    return m[1] === 'true';
  };
  assert.equal(manageFlag('appcrane_list_app_roles'), false,
    'listing an app\'s roles should need membership, not the owner/admin tier');
  // v2.41.2: the tool still ENTERS on membership, but the roster inside it is
  // tier-gated at the point of use — a member gets the catalog, an owner/admin
  // also gets `members`. The manage flag alone therefore no longer describes
  // what the tool returns, so assert the second gate exists.
  assert.match(toolSource('appcrane_list_app_roles'), /roleForUserOnApp\(/,
    'appcrane_list_app_roles no longer checks the tier before returning the roster — ' +
    'any member can enumerate their colleagues');
  assert.equal(manageFlag('appcrane_create_app_role'), true,
    'a plain member must not be able to invent a role — that is authoring the app\'s permission model');
  assert.equal(manageFlag('appcrane_set_user_app_roles'), true,
    'a plain member must not be able to grant themselves a role');

  // The REST side of the same split, read out of the route declarations.
  const routes = [...restSrc.matchAll(/router\.(get|post|patch|delete|put)\('([^']+)'([^\n]*)/g)]
    .map(m => ({ method: m[1], path: m[2], guards: m[3] }));
  assert.ok(routes.length >= 5, `expected the app-roles routes, found ${routes.length}`);
  for (const r of routes) {
    assert.match(r.guards, /requireAppUser/,
      `${r.method.toUpperCase()} ${r.path} is not gated on app membership`);
    // v2.41.2: the split is no longer "writes gated, reads open". It is
    // "mutations and ROSTER reads gated; the role catalog open to members".
    // A roster — names, emails, tiers — is what every other roster read in
    // AppCrane already gates, and shipping it one level lower here let any
    // member enumerate their colleagues.
    const isRoster = r.path.endsWith('/members') || r.path.includes('/members/');
    if (r.method !== 'get' || isRoster) {
      assert.match(r.guards, /requireAppRoleAdmin/,
        `${r.method.toUpperCase()} ${r.path} exposes or mutates app-defined roles without the owner/admin gate`);
    } else {
      assert.ok(!/requireAppRoleAdmin/.test(r.guards),
        `${r.method.toUpperCase()} ${r.path} demands owner/admin to read the role catalog. ` +
        'A member needs the catalog to read their own roles; only the roster is privileged.');
    }
  }
});

test('the routes live under /app-roles, never /roles (the platform-tier path)', () => {
  const paths = [...restSrc.matchAll(/router\.\w+\('([^']+)'/g)].map(m => m[1]);
  assert.ok(paths.length >= 5, 'no routes extracted');
  for (const p of paths) {
    assert.match(p, /\/app-roles(\/|$)/,
      `${p} does not sit under /app-roles. /:slug/roles is taken by server/routes/users.js and sets ` +
      'AppCrane\'s own per-app tier — the two must not collide in the URL space either');
  }
  // Non-vacuity: the platform-tier path must fail the same check.
  assert.ok(!/\/app-roles(\/|$)/.test('/:slug/roles'));
});

test('the guide points at /app-roles and warns off the platform-tier tool', () => {
  assert.match(guide.replace(/\s+/g, ' '), /\/app-roles/,
    'the REST path is not documented, so an app owner cannot manage roles without the MCP');
  const warned = statements(guide).filter(s =>
    /appcrane_grant_app_access/.test(s.text)
    && /\b(not|never|instead|do not|don'?t)\b/i.test(s.text)
    && PLATFORM_CAPABILITY.test(s.text));
  assert.ok(warned.length >= 1,
    'the guide never warns that appcrane_grant_app_access is the wrong tool for app-defined roles — ' +
    'it is the tool with a similar name and real platform power');
});
