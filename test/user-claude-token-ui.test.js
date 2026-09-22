/**
 * The UI for the per-user Claude token.
 *
 * /api/me/claude-token shipped in v2.81.0 with tests, a migration, and no way
 * for anyone to reach it: nothing in studio-web called it, so the README's
 * "saves it under their own settings" pointed at a page that did not exist.
 *
 * studio-web is built separately and the browser is the only place the card and
 * the route meet, so every assertion here is a place where the two AGREE TODAY
 * and where a change on either side produces a page that compiles, builds,
 * renders, and quietly does the wrong thing. tsc sees none of it.
 *
 * The write-only assertions are the ones that matter most. The server is
 * careful never to return a stored token; a client that kept one in state, or
 * echoed it back into the field after saving, would hand that property back at
 * the last step.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');

const card     = web('components/ClaudeTokenCard.tsx');
const settings = web('pages/Settings.tsx');
const adminApp = web('AdminApp.tsx');
const meRoute  = readFileSync(new URL('../server/routes/me.js', import.meta.url), 'utf8');
const store    = readFileSync(new URL('../server/services/userClaudeToken.js', import.meta.url), 'utf8');

// ------------------------------------------------------------- the contract

test('the card calls all three routes the server exposes', () => {
  for (const verb of ['get', 'put', 'del']) {
    assert.match(card, new RegExp(`adminApi\\.${verb}<[^>]*>\\('/api/me/claude-token'`),
      `the card does not ${verb.toUpperCase()} /api/me/claude-token`);
  }
  assert.match(meRoute, /router\.get\('\/me\/claude-token'/);
  assert.match(meRoute, /router\.put\('\/me\/claude-token'/);
  assert.match(meRoute, /router\.delete\('\/me\/claude-token'/);
});

test('PUT sends the body field the route reads', () => {
  assert.match(meRoute, /const token = req\.body\?\.token/,
    'the route changed its field name — the card below has to follow');
  assert.match(card, /'\/api\/me\/claude-token', \{ token \}/,
    'a body keyed anything but `token` is a 400 and the save just looks broken');
});

test('the card reads the two fields the meta actually has', () => {
  assert.match(store, /return \{ present: !!row, expiresAt: row \? row\.expires_at : null \}/,
    'the meta shape changed');
  assert.match(card, /present:\s+boolean/);
  assert.match(card, /expiresAt: string \| null/);
});

// --------------------------------------------------------------- write-only

test('no route returns the token, so the card must not try to render one', () => {
  // The store's only reader of the plaintext is getUserClaudeToken, which the
  // route file never imports. If that ever changes, the assertions below stop
  // being the whole story.
  assert.doesNotMatch(meRoute, /getUserClaudeToken/,
    'the route imports the plaintext reader — re-audit what it sends');
  assert.doesNotMatch(card, /meta[.?]*\.token|\.token\b(?!s)/,
    'the card reads a `token` field off a server response that never carries one');
});

test('a successful save clears the field instead of echoing what was typed', () => {
  assert.match(card, /await adminApi\.put<TokenMeta>\([\s\S]{0,120}?\)\n[\s\S]{0,400}?setToken\(''\)/,
    'the pasted value must be dropped from state on success — nothing can read it back, ' +
    'so a field still holding it is the only copy on the page');
  assert.doesNotMatch(card, /value=\{[^}]*meta/, 'the input is bound to server meta, not to local state');
});

test('the input is masked and kept out of autofill', () => {
  assert.match(card, /type="password"/);
  assert.match(card, /autoComplete="off"/);
});

// ------------------------------------------------------------- the paste

test('the card sends the paste verbatim and shows the server\'s rejection', () => {
  // The server refuses whitespace, CR/LF, NUL and >4096 chars. A client that
  // trims or strips stores a token that differs from the one Anthropic issued,
  // and the failure moves from this form to a container spawn months later.
  assert.match(card, /\{ token \}/);
  assert.doesNotMatch(card, /token\.trim\(\)|token\.replace\(/,
    'the card repairs the paste before sending — the server must be the one to judge it');
  assert.match(card, /e instanceof Error \? e\.message : 'Save failed'/,
    'the rejection shown must be the server\'s own message');
  assert.match(store, /token must be printable ASCII with no spaces/,
    'the validator message moved — the card relays whatever it says, but this pins the source');
});

// ------------------------------------------------------------ what it says

test('the card names the command and quotes the plan requirement', () => {
  assert.match(card, /claude setup-token/);
  assert.match(card, /Pro, Max,\s*\n?\s*Team or Enterprise plan/,
    'the plan requirement must be stated — `claude setup-token` produces nothing on a free account');
  assert.match(card, /free Claude account cannot produce one/);
});

test('the card explains what the token is for, in the app\'s own terms', () => {
  assert.match(card, /run on your own Claude subscription instead of a\s*\n?\s*platform-wide API key/);
});

test('the card surfaces the expiry and warns before it lapses', () => {
  assert.match(store, /DEFAULT_TOKEN_LIFETIME_DAYS = 365/, 'the documented lifetime changed');
  assert.match(card, /EXPIRY_WARN_DAYS = 30/);
  assert.match(card, /nothing refreshes it|Nothing renews it/i,
    'the token does not auto-renew and the person is the only one who can replace it');
  assert.match(card, /EXPIRED/, 'an already-expired token must read differently from a healthy one');
});

test('daysUntil is what the warning is computed from', async () => {
  const { daysUntil, EXPIRY_WARN_DAYS } = await importCard();
  const now = Date.parse('2026-01-01T00:00:00.000Z');
  assert.equal(daysUntil(null, now), null);
  assert.equal(daysUntil('not-a-date', now), null);
  assert.equal(daysUntil('2026-01-11T00:00:00.000Z', now), 10);
  assert.equal(daysUntil('2025-12-31T00:00:00.000Z', now), -1, 'a past expiry must be negative, not zero');
  assert.ok(daysUntil('2026-01-20T00:00:00.000Z', now) <= EXPIRY_WARN_DAYS, '19 days out must warn');
  assert.ok(daysUntil('2026-06-01T00:00:00.000Z', now) > EXPIRY_WARN_DAYS, '5 months out must not warn');
});

// daysUntil is pure and has no JSX in its path, so it is transcribed rather
// than compiled — importing the .tsx would need the whole vite toolchain.
async function importCard() {
  const src = card.slice(card.indexOf('export function daysUntil'));
  const body = src.slice(0, src.indexOf('\n}\n') + 3)
    .replace('export function daysUntil(iso: string | null, now: number = Date.now()): number | null',
             'function daysUntil(iso, now = Date.now())');
  const mod = await import(
    'data:text/javascript,' + encodeURIComponent(`${body}\nexport { daysUntil };\nexport const EXPIRY_WARN_DAYS = 30;`)
  );
  // The constant is duplicated above, so prove the source still agrees with it.
  assert.match(card, /export const EXPIRY_WARN_DAYS = 30/);
  return mod;
}

// ------------------------------------------------------------ reachability

test('Account is a Settings tab, and an ungated one', () => {
  assert.match(settings, /import \{ ClaudeTokenCard \} from '\.\.\/components\/ClaudeTokenCard'/);
  assert.match(settings, /const VALID_TABS: Tab\[\] = \['account',/,
    "'account' must be a valid hash or /settings#account falls through to Security");
  assert.match(adminApp, /\{ id: 'account',\s+label: 'Account',\s+href: '#account' \}/,
    'the sub-nav entry must carry no role flag — Layout hides platformAdminOnly/adminOnly/ownerOrAdmin entries');
  assert.match(adminApp, /const valid = \['account',/,
    'SettingsRoute must accept #account or the sub-nav never highlights it');
});

test('a non-platform-admin actually gets the card rendered', () => {
  // Settings has two return paths. The platform-admin one renders every tab
  // through panel(); the other renders MCP (+ Skills) only — and a personal
  // credential page that only platform admins can open is the one shape of
  // this feature that would be useless.
  assert.match(settings, /const showAccount = tab === 'account'/);
  assert.match(settings, /\{showAccount && <AccountTab \/>\}/,
    'the non-platform-admin branch must render the Account tab');
  assert.match(settings, /\{panel\('account', <AccountTab \/>\)\}/,
    'the platform-admin branch must render it too');
});
