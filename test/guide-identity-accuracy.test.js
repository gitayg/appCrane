import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// The identity contract in server/services/guides/guides/onboarding.md is not
// prose decoration: appcrane_get_guide serves it to the AI agents that write the
// apps, so a wrong sentence there becomes a wrong app. Four debugging sessions
// in one week traced back to three claims in that file that the code had
// outgrown — most damagingly "a platform_admin always reads as
// X-AppCrane-App-Role: admin on every app", which is false whenever an explicit
// app_user_roles row exists (resolveAppRole returns the explicit row FIRST), and
// which is why an app's Settings page told its own owner "Admin access
// required".
//
// A doc test that only greps for a hopeful phrase rots as fast as the doc did.
// So every check here either (a) derives the expected statement from the real
// implementation — resolveAppRole's branch order, the modes Caddy actually
// stamps, the expression /verify uses for X-AppCrane-Is-Admin — or (b) is
// proven non-vacuous against the exact text it replaced. If someone reorders
// resolveAppRole or changes the header semantics, these fail and the doc has to
// move with the code.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GUIDE_PATH = 'server/services/guides/onboarding.md';
const guide = readFileSync(join(ROOT, GUIDE_PATH), 'utf8');
const identitySrc = readFileSync(join(ROOT, 'server/routes/identity.js'), 'utf8');

// The sentences this file replaced, kept verbatim so every detector below can be
// shown to fire on the wrong text. A regex that cannot fail proves nothing.
const RETRACTED_GUIDE_CLAIM =
  '**Platform admin collapse:** a `platform_admin` always reads as ' +
  '`X-AppCrane-App-Role: admin` on every app — same short-circuit `/verify` and `/api/me` use.';
const RETRACTED_README_CLAIM =
  'Per-app role. Platform admins collapse to `admin` on every app — branch on ' +
  '`X-AppCrane-User-Role` if you specifically need to target platform admins.';
// A restatement in different words: the detectors must catch the CLAIM, not one
// author's phrasing of it.
const REWORDED_CLAIM =
  'A global admin is resolved to X-AppCrane-App-Role: admin on every app, so ' +
  'there is no need to look at app_user_roles.';

// ---------------------------------------------------------------------------
// Statement extraction. Markdown emphasis and backticks are noise for matching,
// but line structure matters (tables are one claim per line), so normalize per
// line and then split on sentence ends only — never on ':', which would sever
// "reads as X-AppCrane-App-Role: admin" into two harmless halves.
// ---------------------------------------------------------------------------
function statements(text) {
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

const GUIDE_STATEMENTS = statements(guide);

test('the guide loaded and is the identity guide (guards every check below)', () => {
  assert.ok(guide.length > 5000, `${GUIDE_PATH} looks empty or truncated`);
  assert.ok(GUIDE_STATEMENTS.length > 200, 'statement extraction produced nothing');
  assert.match(guide, /X-AppCrane-App-Role/, 'this is not the guide that documents identity headers');
});

// ---------------------------------------------------------------------------
// (1) The retracted claim: platform admin collapses to `admin` everywhere.
// ---------------------------------------------------------------------------
const SUBJECT = /\b(platform[_ ]?admins?|global admins?)\b/i;
const EVERYWHERE = /\b(every app|all apps|always|collapses?d?|flattens?e?d?)\b/i;
const READS_ADMIN = new RegExp(
  '(app[- ]?role[^.]{0,40}\\badmin\\b' +
  '|\\badmin\\b[^.]{0,40}\\bapp[- ]?role\\b' +
  '|\\b(reads?|resolves?|maps?|flattens?|collapses?|becomes?) (as|to)[^.]{0,20}\\badmin\\b)', 'i');
const NEGATED = /\b(not|never|no longer|isn'?t|doesn'?t|don'?t|rather than|instead of|reduced)\b/i;

function collapseClaims(text) {
  return statements(text).filter(s =>
    SUBJECT.test(s.text) && EVERYWHERE.test(s.text) && READS_ADMIN.test(s.text) && !NEGATED.test(s.text));
}

test('the detector fires on the exact text that was wrong (non-vacuity)', () => {
  assert.equal(collapseClaims(RETRACTED_GUIDE_CLAIM).length, 1, 'detector missed the old guide sentence');
  assert.equal(collapseClaims(RETRACTED_README_CLAIM).length, 1, 'detector missed the old README cell');
  assert.equal(collapseClaims(REWORDED_CLAIM).length, 1, 'detector only catches one phrasing — reword-proof it');
  // ...and stays quiet on true statements about the same subject, so a passing
  // guide is not just a guide that stopped mentioning platform admins.
  assert.equal(collapseClaims(
    'A platform_admin does not flatten to admin on every app.').length, 0);
  assert.equal(collapseClaims(
    'Branch on X-AppCrane-User-Role === platform_admin when you mean platform staff.').length, 0);
});

test('the guide no longer claims a platform admin reads as admin on every app', () => {
  const bad = collapseClaims(guide);
  assert.deepEqual(bad.map(b => `${GUIDE_PATH}:${b.line}: ${b.text}`), [],
    'this claim is false whenever an explicit app_user_roles row exists — ' +
    'resolveAppRole returns that row before the global-admin fallback');
});

test('the guide explicitly retracts it rather than going silent', () => {
  // Deleting the sentence would pass the test above while leaving an app author
  // who read the old guide with no correction. Require a negated restatement.
  const retractions = GUIDE_STATEMENTS.filter(s =>
    SUBJECT.test(s.text) && EVERYWHERE.test(s.text) && READS_ADMIN.test(s.text) && NEGATED.test(s.text));
  assert.ok(retractions.length >= 1,
    'no statement tells the reader that platform admins do NOT flatten to admin on every app');
});

// ---------------------------------------------------------------------------
// (2) THE LOAD-BEARING TEST: the documented precedence is read out of the real
// resolveAppRole. This is the drift that nothing caught.
// ---------------------------------------------------------------------------
function balancedBody(src, fromIndex) {
  const open = src.indexOf('{', fromIndex);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error('unbalanced braces');
}

const resolveAppRoleBody = (() => {
  const at = identitySrc.indexOf('const resolveAppRole');
  assert.notEqual(at, -1, 'resolveAppRole not found in server/routes/identity.js');
  return balancedBody(identitySrc, at);
})();

// Each rung of the precedence ladder, identified by what it looks at rather than
// by line number.
const RUNGS = [
  ['explicit', /app_user_roles/],
  ['global', /crane_role\s*===\s*'(admin|platform_admin)'/],
  ['public', /visibility\s*===\s*'public'/],
  ['none', /return\s*'none'/],
];

function ladderFromCode(body) {
  return RUNGS
    .map(([name, re]) => {
      const m = re.exec(body);
      assert.ok(m, `resolveAppRole no longer has a "${name}" branch — the guide's ordered list must be rewritten`);
      return { name, at: m.index };
    })
    .sort((a, b) => a.at - b.at)
    .map(r => r.name);
}

// The guide's numbered list, classified with the same vocabulary. Order of the
// tests matters: item 2 mentions `admin` too, so match app_user_roles first.
function ladderFromGuide(text) {
  const anchor = text.search(/resolves in this order/i);
  assert.notEqual(anchor, -1,
    'the guide does not spell out resolveAppRole\'s precedence at all — an app author cannot ' +
    'know that an explicit per-app row beats the global-admin fallback');
  const items = [...text.slice(anchor).matchAll(/^\s*\d+\.\s+(.+)$/gm)].slice(0, RUNGS.length)
    .map(m => m[1].replace(/`/g, '').replace(/\*\*/g, ''));
  assert.equal(items.length, RUNGS.length, `expected ${RUNGS.length} numbered precedence items, got ${items.length}`);
  return items.map(item => {
    if (/app_user_roles/i.test(item)) return 'explicit';
    if (/(global|platform_admin)/i.test(item)) return 'global';
    if (/public/i.test(item)) return 'public';
    if (/\bnone\b/i.test(item)) return 'none';
    return `unclassified(${item.slice(0, 40)})`;
  });
}

test('the code really does check the explicit per-app row before the global short-circuit', () => {
  const ladder = ladderFromCode(resolveAppRoleBody);
  assert.equal(ladder[0], 'explicit',
    'resolveAppRole was reordered: the explicit app_user_roles lookup no longer runs first. ' +
    'That is a behavior change for every hosted app — update the guide in the same commit');
  assert.ok(ladder.indexOf('explicit') < ladder.indexOf('global'),
    'explicit per-app row must precede the global-admin fallback');
});

test('the guide describes the SAME precedence the code implements', () => {
  assert.deepEqual(ladderFromGuide(guide), ladderFromCode(resolveAppRoleBody),
    'the guide\'s ordered list has drifted from resolveAppRole in server/routes/identity.js');
});

test('the precedence extractors are not vacuous', () => {
  // A resolveAppRole with the branches swapped back to the pre-v2.7.21 order
  // must produce a different ladder — otherwise the comparison above is theatre.
  const swapped = `{
    if (session.crane_role === 'admin' || session.crane_role === 'platform_admin') return 'admin';
    const r = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ?').get(id);
    if (r?.app_role) return r.app_role;
    if (appRecord.visibility === 'public') return 'viewer';
    return 'none';
  }`;
  assert.deepEqual(ladderFromCode(swapped), ['global', 'explicit', 'public', 'none']);
  assert.notDeepEqual(ladderFromCode(swapped), ladderFromCode(resolveAppRoleBody));
  // And a guide that lists them in the wrong order must not classify as correct.
  assert.deepEqual(ladderFromGuide([
    'resolves in this order:', '',
    '1. global admin / platform_admin wins;',
    '2. else an explicit app_user_roles row;',
    '3. else visibility public gives viewer;',
    '4. else none.',
  ].join('\n')), ['global', 'explicit', 'public', 'none']);
});

// ---------------------------------------------------------------------------
// (3) Role ordering and the `=== 'admin'` defect.
// ---------------------------------------------------------------------------
const ORDER = ['none', 'viewer', 'user', 'admin', 'owner'];

test('the guide states the role ordering, lowest to highest', () => {
  const flat = guide.replace(/`/g, '').replace(/\s+/g, ' ');
  assert.ok(flat.includes(ORDER.join(' < ')),
    `guide must state the ordering "${ORDER.join(' < ')}" — without it an app author cannot know owner outranks admin`);
  // Non-vacuity: the same check must reject a wrong ordering.
  assert.ok(!'none < viewer < user < owner < admin'.includes(ORDER.join(' < ')));
});

test('the guide ships a rank table covering every role the platform can emit', () => {
  const m = /RANK\s*=\s*\{([^}]*)\}/.exec(guide);
  assert.ok(m, 'no RANK table in the guide — the "at least X" gate has nothing to stand on');
  const ranks = Object.fromEntries([...m[1].matchAll(/(\w+)\s*:\s*(\d+)/g)].map(([, k, v]) => [k, Number(v)]));
  assert.deepEqual(Object.keys(ranks).sort(), [...ORDER].sort(), 'RANK table is missing a role');
  for (let i = 1; i < ORDER.length; i++) {
    assert.ok(ranks[ORDER[i]] > ranks[ORDER[i - 1]],
      `RANK says ${ORDER[i]} is not above ${ORDER[i - 1]}`);
  }
  // Pin the vocabulary to the code: every literal resolveAppRole can return, plus
  // every value app_user_roles.app_role is allowed to hold, must be ranked.
  const emitted = [...resolveAppRoleBody.matchAll(/return\s*'([a-z]+)'/g)].map(x => x[1]);
  assert.ok(emitted.length >= 2, 'no role literals found in resolveAppRole — extractor broke');
  for (const role of emitted) {
    assert.ok(role in ranks, `/verify can emit App-Role '${role}' but the guide's RANK table omits it`);
  }
});

test('the guide names `=== \'admin\'` as the bug it is', () => {
  const warned = GUIDE_STATEMENTS.filter(s =>
    /===\s*'admin'/.test(s.text) && /\b(bug|wrong|never|denies|deny|do not|don'?t|incorrect)\b/i.test(s.text));
  assert.ok(warned.length >= 1,
    'nothing in the guide warns that comparing the per-app role to \'admin\' locks out owners — ' +
    'that exact comparison caused the "Admin access required" report');
  // Non-vacuity: a guide that merely *shows* the comparison must not pass.
  assert.equal(statements("if (appRole === 'admin') showAdminUI()").filter(s =>
    /===\s*'admin'/.test(s.text) && /\b(bug|wrong|never|denies|deny|do not|don'?t|incorrect)\b/i.test(s.text)).length, 0);
});

// ---------------------------------------------------------------------------
// (4) cc_token — v2.39.0 stripped it silently; the guide has to say so.
// ---------------------------------------------------------------------------
test('the guide tells apps never to read identity out of the cc_token cookie', () => {
  const warned = GUIDE_STATEMENTS.filter(s =>
    /cc_token/.test(s.text)
    && /\b(never|not|no longer|strips?|stripped|must not|cannot|can'?t)\b/i.test(s.text)
    && /\b(identity|session|cookie|reach|read)\b/i.test(s.text));
  assert.ok(warned.length >= 1,
    'the guide never warns against deriving identity from cc_token — at least one fleet app was doing ' +
    'exactly that and got no notice when v2.39.0 started stripping the cookie');
  assert.match(guide, /cc_token/,
    'the cookie is not mentioned at all');
});

// ---------------------------------------------------------------------------
// (5) The two headers 2.40.0 adds, checked against what the code emits.
// ---------------------------------------------------------------------------
test('the guide documents X-AppCrane-Auth-Mode and X-AppCrane-Is-Admin', () => {
  for (const h of ['X-AppCrane-Auth-Mode', 'X-AppCrane-Is-Admin']) {
    assert.match(guide, new RegExp(h),
      `${h} is not documented — an app author has no way to learn it exists`);
  }
});

// The value /verify puts on the wire for X-AppCrane-Is-Admin, read out of the
// source rather than assumed, so the doc is pinned to the real definition.
const isAdminDeps = (() => {
  const m = /res\.setHeader\(\s*['"]X-AppCrane-Is-Admin['"]\s*,([^;]*)\);/.exec(identitySrc);
  assert.ok(m, 'X-AppCrane-Is-Admin is not emitted by server/routes/identity.js');
  const expr = m[1];
  const ids = [...new Set(expr.match(/[A-Za-z_$][\w$]*/g) || [])];
  const resolved = ids.map(id => {
    const d = new RegExp(`const\\s+${id}\\s*=([^;]*);`).exec(identitySrc);
    return d ? d[1] : '';
  }).join(' ') + ' ' + expr;
  return {
    onAppRole: /appRole/.test(resolved),
    onGlobalRole: /crane_role/.test(resolved),
    countsOwner: /'owner'/.test(resolved),
    // Whether the global-role term is a FALLBACK for "this /verify call carried
    // no ?app= at all" rather than a term OR-ed into the per-app answer. A
    // conditional on appRole in the emitted expression means App-Role decides
    // whenever there IS an app, so the guide's App-Role-only definition holds
    // for every request an app can actually receive. Plain
    // `isPlatformAdmin || isAppAdmin` has no such gate and does not qualify.
    globalOnlyWithoutApp: /appRole\s*\?/.test(expr),
  };
})();

test('the guide\'s definition of X-AppCrane-Is-Admin matches what /verify computes', () => {
  const doc = GUIDE_STATEMENTS.filter(s => /X-AppCrane-Is-Admin/.test(s.text)).map(s => s.text).join(' ');
  assert.ok(doc.length > 0, 'X-AppCrane-Is-Admin appears nowhere in a prose statement');

  if (isAdminDeps.countsOwner) {
    assert.match(doc, /\bowner\b/i,
      'the header counts owner as admin but the guide does not say so');
  }
  if (isAdminDeps.onGlobalRole && !isAdminDeps.globalOnlyWithoutApp) {
    // An UNGATED global-role term means /verify ORs in the caller's PLATFORM
    // role, so a global admin holding an explicit `user` row on an app still
    // receives Is-Admin: 1 while App-Role: user — two platform-issued headers
    // contradicting each other. Any app that believes the guide's "1 when
    // App-Role is admin or owner" will disagree with the platform for exactly
    // the users the explicit-row precedence exists to serve.
    assert.match(doc, /(platform[_ ]?admin|global admin|platform-wide|crane_role)/i,
      'server/routes/identity.js computes X-AppCrane-Is-Admin as (global admin) OR (per-app admin/owner), ' +
      'but the guide defines it purely in terms of X-AppCrane-App-Role. One of the two has to change: ' +
      'either document the global-admin term, or drop it from the header so the header means ' +
      '"may administer THIS app" as documented');
  }
});

test('X-AppCrane-Is-Admin defers to the per-app role whenever there is an app', () => {
  // The guide documents this header purely in terms of X-AppCrane-App-Role, and
  // presents `atLeast(appRole,'admin')` and `Is-Admin === '1'` as identical. That
  // is only true while the global-role term stays gated behind "no app context".
  // Ungate it and a platform admin an app owner deliberately demoted to `user`
  // gets the admin UI the platform just took away from them.
  assert.ok(isAdminDeps.onAppRole,
    'X-AppCrane-Is-Admin no longer depends on the per-app role at all');
  assert.ok(!isAdminDeps.onGlobalRole || isAdminDeps.globalOnlyWithoutApp,
    'X-AppCrane-Is-Admin ORs the global crane_role into the per-app answer. An explicit ' +
    'app_user_roles row must win (resolveAppRole\'s v2.7.21 precedence), so the global role may ' +
    'only be consulted when there is no ?app= context and appRole is null');

  // Non-vacuity: the shape this replaced must still be caught.
  assert.equal(/appRole\s*\?/.test(" isPlatformAdmin || isAppAdmin ? '1' : '0'"), false);
  assert.equal(/appRole\s*\?/.test(" (appRole ? isAppAdmin : isPlatformAdmin) ? '1' : '0'"), true);
});

// ---------------------------------------------------------------------------
// (6) Auth-Mode values, checked against a Caddyfile actually generated by
// server/services/caddy.js — the doc's whole job here is to explain what shows
// up on the wire.
// ---------------------------------------------------------------------------
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-guide-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const CUSTOM_DOMAIN = 'custom.test.local';
const mkApp = (name, slug, slot, extra = {}) => {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,auth_mode,auth_bypass_paths,domain) VALUES (?,?,?,?,?,?,?)'
  ).run(name, slug, slot, 'managed', extra.auth_mode ?? 'authenticated',
    extra.auth_bypass_paths ?? null, extra.domain ?? null).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO deployments (app_id, env, status) VALUES (?,?,?)').run(id, env, 'live');
  }
};
mkApp('Normal', 'normal', 1);
mkApp('Headless', 'headless', 2, { auth_mode: 'headless' });
mkApp('Bypass', 'bypass', 3, { auth_bypass_paths: JSON.stringify(['/ws/runner']) });
mkApp('Custom', 'custom', 4, { domain: CUSTOM_DOMAIN });

const { generateCaddyfile } = await import('../server/services/caddy.js');
const caddyfile = generateCaddyfile();

const stampedModes = [...new Set(
  [...caddyfile.matchAll(/request_header X-AppCrane-Auth-Mode "([^"]+)"/g)].map(m => m[1]))].sort();

test('the Caddyfile under test actually stamps auth modes (guards the checks below)', () => {
  assert.ok(caddyfile.includes('/normal*'), 'generation produced no app routes');
  assert.ok(stampedModes.length >= 2, `expected several auth-mode stamps, got ${JSON.stringify(stampedModes)}`);
});

test('every auth mode Caddy stamps is documented, and no phantom mode is', () => {
  for (const mode of stampedModes) {
    assert.match(guide, new RegExp(`\`${mode}\``),
      `Caddy stamps X-AppCrane-Auth-Mode: ${mode} but the guide never mentions that value`);
  }
  const documented = [...new Set(
    [...guide.matchAll(/X-AppCrane-Auth-Mode[^\n]*/g)]
      .flatMap(m => [...m[0].matchAll(/`(authenticated|headless|bypass)`/g)].map(x => x[1])))].sort();
  assert.deepEqual(documented, stampedModes,
    'the set of modes the guide documents differs from the set Caddy emits');
});

// The custom-domain claim. Caddy emits a standalone site block per custom
// domain; whatever it stamps there is what that app sees.
function siteBlock(text, domain) {
  const at = text.indexOf(`\n${domain} {`);
  assert.notEqual(at, -1, `no site block for ${domain}`);
  return balancedBody(text, at);
}

test('what the guide says a custom-domain app receives is what Caddy sends it', () => {
  const block = siteBlock(caddyfile, CUSTOM_DOMAIN);
  const stamped = /request_header X-AppCrane-Auth-Mode "([^"]+)"/.exec(block);

  const claimsNothingArrives = s =>
    /custom domain/i.test(s.text)
    && (/\bno\b[^.]{0,60}X-AppCrane-Auth-Mode/i.test(s.text)
      || /X-AppCrane-Auth-Mode[^.]{0,60}\b(either|absent|missing|not set|not present)\b/i.test(s.text));

  // Non-vacuity: the detector must fire on the wrong sentence and stay quiet on
  // a corrected one.
  assert.equal(statements(
    'Two more cases produce no headers and no `X-AppCrane-Auth-Mode` either: the app is served on a ' +
    '**custom domain**, or you are hitting the container directly.').filter(claimsNothingArrives).length, 1);
  assert.equal(statements(
    'On a custom domain the app still receives `X-AppCrane-Auth-Mode: bypass`, but no identity.'
  ).filter(claimsNothingArrives).length, 0);

  if (stamped) {
    const bad = GUIDE_STATEMENTS.filter(claimsNothingArrives);
    assert.deepEqual(bad.map(b => `${GUIDE_PATH}:${b.line}: ${b.text}`), [],
      `server/services/caddy.js stamps X-AppCrane-Auth-Mode: ${stamped[1]} on the ${CUSTOM_DOMAIN} site ` +
      'block, so a custom-domain app DOES receive the header. An author who believes the guide will ' +
      'read the absence of identity as "AppCrane is not proxying me" — the same class of ' +
      'four-causes-one-symptom confusion this header was added to end');
    assert.match(guide, new RegExp(`\`${stamped[1]}\``));
  }
});

// ---------------------------------------------------------------------------
// (7) Headless: forward_auth never runs, so nothing verifies identity there.
// Whether Caddy also strips client-supplied X-AppCrane-* on those routes decides
// how strongly the guide has to word it.
// ---------------------------------------------------------------------------
test('the guide warns that identity on a headless/bypass request is unverified', () => {
  const headlessBlockStrips = (() => {
    const at = caddyfile.indexOf('handle /headless* {');
    if (at === -1) return null;
    return /request_header -X-AppCrane-User-Role/.test(balancedBody(caddyfile, at));
  })();

  const warned = GUIDE_STATEMENTS.filter(s =>
    /X-AppCrane-User|identity/i.test(s.text)
    && /\b(untrusted|unverified|not verified|nothing verified|do not trust|never trust)\b/i.test(s.text));
  assert.ok(warned.length >= 1,
    'the guide never tells a headless or bypass app that any X-AppCrane-* on its requests is unverified' +
    (headlessBlockStrips === false
      ? ' — and Caddy does NOT strip client-supplied X-AppCrane-* on the headless route, so a curl can put them there'
      : ''));

  // Non-vacuity.
  assert.equal(statements('The app receives identity headers from AppCrane.').filter(s =>
    /X-AppCrane-User|identity/i.test(s.text)
    && /\b(untrusted|unverified|not verified|nothing verified|do not trust|never trust)\b/i.test(s.text)).length, 0);
});

// ---------------------------------------------------------------------------
// (8) The SSO misconception that opened session one.
// ---------------------------------------------------------------------------
test('the guide states that identity injection does not depend on SSO', () => {
  const flat = guide.replace(/`/g, '').replace(/\*\*/g, '').replace(/\s+/g, ' ');
  assert.match(flat, /\b(SSO|SAML|OIDC|IdP)\b[^.]{0,200}\b(not|only one way|never the explanation|others)\b/i,
    'nothing corrects "no SSO means no identity headers" — /api/identity/verify also accepts X-API-Key and ' +
    'a local-login session, so SSO is only one way a session exists');
  // The alternatives have to be named, not just implied.
  assert.match(flat, /X-API-Key/, 'the API-key path to a verified session is not documented');
});
