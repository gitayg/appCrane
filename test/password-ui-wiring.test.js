import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// The dashboard's password forms: Settings -> Account changes the caller's own
// password, Users sets another user's. tsc cannot check that errors surface or
// that the fields carry the eye toggle.

const SRC = fileURLToPath(new URL('../studio-web/src/', import.meta.url));
const web = (p) => readFileSync(join(SRC, p), 'utf8');

const users = web('pages/Users.tsx');
const settings = web('pages/Settings.tsx');
const modal = web('components/SetUserPasswordModal.tsx');
const card = web('components/ChangePasswordCard.tsx');

test('Users no longer prompts for a password or swallows the server\'s answer', () => {
  assert.doesNotMatch(users, /prompt\(/, 'Users.tsx still uses window.prompt');
  assert.doesNotMatch(users, /\/password`[^\n]*\.catch\(\(\) => \{\}\)/, 'the set-password call still swallows errors');
  assert.match(users, /<SetUserPasswordModal user=\{passwordUser\}/);
  assert.match(users, /onClick=\{\(\) => setPasswordUser\(u\)\}/);
});

test('the admin set-password modal shows the server error and a success message', () => {
  assert.match(modal, /adminApi\.put\(`\/api\/users\/\$\{user\.id\}\/password`, \{ password: pw \}\)/);
  assert.doesNotMatch(modal, /\.catch\(\(\) => \{\}\)/);
  assert.match(modal, /catch \(e\) \{\s*setMsg\(\{ ok: false, text: e instanceof Error \? e\.message/);
  assert.match(modal, /Password set for \$\{user\.name\}; their sessions were signed out\./);
  assert.equal((modal.match(/<PasswordInput /g) || []).length, 2, 'new + confirm are not both PasswordInput');
  assert.match(modal, /MIN_LENGTH = 12/);
});

test('the Account tab has the change-password card, with PasswordInput fields', () => {
  const account = settings.slice(settings.indexOf('function AccountTab()'), settings.indexOf('type Tab ='));
  assert.match(account, /<ChangePasswordCard \/>/, 'Account tab does not render the password card');
  assert.equal((card.match(/<PasswordInput /g) || []).length, 3, 'current + new + confirm are not all PasswordInput');
  assert.match(card, /hasPassword && \(\s*<div[^>]*>\s*<label[^>]*>Current password/, 'current password is not gated on has_password');
  assert.match(card, /'\/api\/identity\/set-password'/);
  assert.match(card, /current_password: current, password: next/);
  assert.match(card, /localStorage\.setItem\('cc_identity_token', r\.token\)/, 'the fresh token is not stored');
  assert.match(card, /\/api\/settings\/auth_sso_only/, 'SSO-only instances are not detected');
  assert.match(card, /catch \(e\) \{\s*setMsg\(\{ ok: false, text: e instanceof Error \? e\.message/);
});
