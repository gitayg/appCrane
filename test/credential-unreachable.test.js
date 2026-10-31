import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A probe that got no answer is not a dead credential. app.opswat.com mailed
// "credential stopped working … expired, rotated or revoked" for one
// "fetch failed" on 30 Oct 2026; a network blip now alerts only after an hour,
// and says the provider is unreachable rather than blaming the token.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-credunreach-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const C = await import('../server/services/credentialChecker.js');

const state = () => JSON.parse(getDb().prepare("SELECT value FROM settings WHERE key = 'credcheck_state'").get()?.value || '{}');
const probe = (results) => ({ name: 'GitHub service account', fix: 'Settings → GitHub', href: '/settings#github', run: async () => results.shift() });
const reset = () => getDb().prepare("DELETE FROM settings WHERE key = 'credcheck_state'").run();

test('network errors are told apart from a rejected credential', () => {
  for (const e of ['fetch failed', 'connect ECONNREFUSED 1.2.3.4:443', 'getaddrinfo ENOTFOUND api.github.com', 'GitHub API 502: Bad Gateway', 'The operation was aborted due to timeout']) {
    assert.equal(C.isUnreachable(e), true, e);
  }
  for (const e of ['GitHub API 401: Bad credentials', 'GitHub API 403: Resource not accessible', 'github service token is not configured', '']) {
    assert.equal(C.isUnreachable(e), false, e);
  }
});

test('a short outage never marks the credential failing; an hour of it does', async () => {
  reset();
  const p = probe([...Array(C.UNREACHABLE_ALERT_AFTER)].map(() => ({ ok: false, error: 'fetch failed' })));
  for (let i = 1; i < C.UNREACHABLE_ALERT_AFTER; i++) {
    await C.runCredentialCheckOnce([p]);
    assert.deepEqual(state()[p.name], { ok: true, unreachable: i });
  }
  await C.runCredentialCheckOnce([p]);
  assert.equal(state()[p.name].ok, false);
  assert.ok(state()[p.name].lastAlertAt, 'alerted once it lasted an hour');
});

test('one success in between resets the count', async () => {
  reset();
  const p = probe([{ ok: false, error: 'fetch failed' }, { ok: false, error: 'fetch failed' }, { ok: true }, { ok: false, error: 'fetch failed' }]);
  for (let i = 0; i < 4; i++) await C.runCredentialCheckOnce([p]);
  assert.deepEqual(state()[p.name], { ok: true, unreachable: 1 });
});

test('a rejected credential still alerts on the first check', async () => {
  reset();
  const p = probe([{ ok: false, error: 'GitHub API 401: Bad credentials' }]);
  await C.runCredentialCheckOnce([p]);
  assert.equal(state()[p.name].ok, false);
  assert.ok(state()[p.name].lastAlertAt);
});

test('the unreachable alert does not tell the admin the token expired', () => {
  const p = { name: 'GitHub service account', fix: 'Settings → GitHub', href: '/settings#github' };
  const a = C.buildFailureAlert(p, { error: 'fetch failed' }, Date.UTC(2026, 9, 30));
  assert.match(a.subject, /UNREACHABLE/);
  assert.match(a.body, /could not reach GitHub service account/);
  assert.doesNotMatch(a.body, /expired, was rotated, or was revoked/);
  const b = C.buildFailureAlert(p, { error: 'GitHub API 401: Bad credentials' }, Date.UTC(2026, 9, 30));
  assert.match(b.subject, /FAILING/);
  assert.match(b.body, /expired, was rotated, or was revoked/);
});
