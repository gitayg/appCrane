import { test } from 'node:test';
import assert from 'node:assert/strict';
import { slugContentCategory } from '../server/utils/slugContent.js';
import { slugRefusal } from '../server/utils/slugPolicy.js';

// What an app slug may say. Tokens by default, so words that merely contain a
// sequence stay allowed; substrings only for terms no ordinary word contains.

const OWNER = { id: 1, role: 'user' };
const PLATFORM = { id: 2, role: 'platform_admin' };

test('offensive slugs are refused, including common evasions', () => {
  for (const s of [
    'fuck', 'my-fuck-app', 'fuckery', 'f-u-c-k', 'fuuuuck', 'fuuucking-app',
    'sh1t', '5h1t-list', 'a55', 'asss', 'c-u-n-t', 'n1gger', 'b1tch', 'wh0re-house', 'p0rn-hub', 'the-rapist',
  ]) {
    assert.equal(slugContentCategory(s), 'offensive', `'${s}' was allowed`);
    assert.ok(slugRefusal(s, PLATFORM), `'${s}' was allowed for a platform admin — the offensive list applies to everyone`);
  }
});

test('ordinary words that contain those letters are allowed', () => {
  // Justification, per word: each is an English word or place whose letters
  // include a listed term, and refusing it would be the Scunthorpe problem.
  for (const s of [
    'class', 'assess', 'assets', 'scunthorpe', 'therapist', 'cockpit-tools', 'peacock', 'grape',
    'sussex', 'snigger', 'analysis', 'raccoon', 'as-is', 'dickens', 'spice', 'cumulus', 'passport',
    'shiitake', 'classic-cars', 'hello-world', 'my-app', 'hr-dashboard',
  ]) {
    assert.equal(slugContentCategory(s), null, `'${s}' was refused`);
    assert.equal(slugRefusal(s, OWNER), null, `'${s}' was refused by the policy`);
  }
});

test('trust-signal slugs are refused for owners and allowed for platform admins', () => {
  for (const s of ['admin', 'admin-panel', '4dmin', 'l0gin-helper', 'sign-in', 'log-in', 'pass-word', 'appcranehelp',
    'official-app', 'secure-billing', 'it-support', 'oauth-callback', 'root']) {
    assert.equal(slugContentCategory(s), 'impersonation', `'${s}' was not flagged`);
    assert.ok(slugRefusal(s, OWNER), `'${s}' was allowed for an owner`);
  }
  assert.equal(slugRefusal('appcrane-ping', PLATFORM), null, 'a platform admin may use the trust-signal words');
});

test('the refusal never repeats the matched word', () => {
  for (const s of ['my-fuck-app', 'admin-panel']) {
    const msg = slugRefusal(s, OWNER);
    assert.ok(msg && !msg.includes(s) && !/fuck/.test(msg), msg);
  }
});
