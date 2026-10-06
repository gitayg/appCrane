import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Security audit 2026-10-06, M4: SSO linked a local account by e-mail with no
// email_verified check, and re-linked an account already bound to another SSO
// identity: any IdP identity asserting a victim's e-mail became the victim.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-ssolink-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { findOrLinkSsoUser } = await import('../server/services/ssoLink.js');

let n = 0;
const mkUser = (email, extra = {}) => db.prepare(
  'INSERT INTO users (name,email,role,active,api_key_hash,sso_sub,saml_name_id) VALUES (?,?,?,1,?,?,?)'
).run(email, email, extra.role || 'user', `h${++n}`, extra.sso_sub || null, extra.saml_name_id || null).lastInsertRowid;
const subOf = (id) => db.prepare('SELECT sso_sub s FROM users WHERE id = ?').get(id).s;

test('a known subject signs in as its own account', () => {
  const id = mkUser('a@acme.test', { sso_sub: 'sub-a' });
  assert.equal(findOrLinkSsoUser(db, { column: 'sso_sub', subject: 'sub-a', email: 'other@acme.test', emailVerified: false }).id, id);
});

test('a verified e-mail links an account that has no SSO identity yet', () => {
  const id = mkUser('b@acme.test');
  assert.equal(findOrLinkSsoUser(db, { column: 'sso_sub', subject: 'sub-b', email: 'b@acme.test', emailVerified: true }).id, id);
  assert.equal(subOf(id), 'sub-b');
});

test('an unverified e-mail does not link an existing account', () => {
  const id = mkUser('c@acme.test');
  assert.throws(() => findOrLinkSsoUser(db, { column: 'sso_sub', subject: 'attacker', email: 'c@acme.test', emailVerified: false }), /did not verify/);
  assert.equal(subOf(id), null);
});

test('an account already bound to another SSO identity is never moved, even with a verified e-mail', () => {
  const id = mkUser('admin@acme.test', { role: 'platform_admin', sso_sub: 'sub-real-admin' });
  assert.throws(() => findOrLinkSsoUser(db, { column: 'sso_sub', subject: 'attacker', email: 'admin@acme.test', emailVerified: true }), /already linked/);
  assert.equal(subOf(id), 'sub-real-admin');
});

test('the operator can allow unverified links for an IdP that never sends email_verified', () => {
  const id = mkUser('d@acme.test');
  assert.equal(findOrLinkSsoUser(db, { column: 'sso_sub', subject: 'sub-d', email: 'd@acme.test', emailVerified: false, allowUnverified: true }).id, id);
});

test('SAML: an account bound to another NameID is never moved', () => {
  const id = mkUser('e@acme.test', { saml_name_id: 'nameid-real' });
  assert.throws(() => findOrLinkSsoUser(db, { column: 'saml_name_id', subject: 'nameid-attacker', email: 'e@acme.test', emailVerified: true }), /already linked/);
  assert.equal(db.prepare('SELECT saml_name_id s FROM users WHERE id = ?').get(id).s, 'nameid-real');
});

test('both SSO routes link only through findOrLinkSsoUser', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'routes');
  for (const f of ['oidc.js', 'saml.js']) {
    const src = readFileSync(join(root, f), 'utf8');
    assert.match(src, /findOrLinkSsoUser\(/, `${f} does not use the shared linking rule`);
    assert.doesNotMatch(src, /UPDATE users SET (sso_sub|saml_name_id) = \?/, `${f} still links accounts on its own`);
  }
});
