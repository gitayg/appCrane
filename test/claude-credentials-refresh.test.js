import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Several holders of one app's Claude login at once (services/claudeCredentials.js).
//
// The long-lived app container (builder/appContainer.js) keeps one tmpfile copy
// for as long as it lives; every per-turn container (a Crew coder turn, Improve,
// Ask) takes its own. Claude Code refreshes the OAuth token inside whichever
// container hits expiry and rewrites its own copy, and the refresh rotates the
// refresh token: the old one is dead from then on. Before v2.131.0 each copy
// was written back to the DB blindly and only when its holder ended, so
//   - a holder kept a dead refresh token after another holder rotated, and
//   - a holder ending later overwrote a newer rotation with an older one.
// The "CLI" here is a write to the holder's tmpfile, which is all the real one
// does to the bind-mounted file.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-claude-creds-refresh-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setCredentials, clearCredentials, prepareClaudeCredentialsMount, syncClaudeCredentials } = await import('../server/services/claudeCredentials.js');
const { decrypt } = await import('../server/services/encryption.js');

const cred = (n) => ({ claudeAiOauth: { accessToken: `at-${n}`, refreshToken: `rt-${n}`, expiresAt: 1_000_000 + n } });
const refreshOf = (text) => JSON.parse(text).claudeAiOauth.refreshToken;
const held = (m) => refreshOf(readFileSync(m.tmpFile, 'utf8'));
const stored = (slug) => refreshOf(decrypt(db.prepare('SELECT claude_credentials_encrypted AS c FROM apps WHERE slug = ?').get(slug).c));
const cliRefreshes = (m, n) => writeFileSync(m.tmpFile, JSON.stringify(cred(n)));

let seq = 0;
function freshApp(n) {
  const slug = `refresh-${++seq}`;
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'managed')").run(slug, slug, seq);
  setCredentials(slug, cred(n));
  return slug;
}

test('a turn that rotates the login hands the new refresh token to the app container still running', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  const turn = prepareClaudeCredentialsMount(slug);
  cliRefreshes(turn, 1);
  turn.cleanup();
  assert.equal(stored(slug), 'rt-1');
  assert.equal(held(app), 'rt-1', 'the app container must not keep the refresh token the turn rotated out');
  app.cleanup();
  assert.equal(stored(slug), 'rt-1');
});

test('a turn started while the app container holds a rotated login gets the rotated one', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  cliRefreshes(app, 1);
  const turn = prepareClaudeCredentialsMount(slug);
  assert.equal(held(turn), 'rt-1', 'rt-0 was rotated out by the app container');
  turn.cleanup();
  app.cleanup();
});

test('a holder ending later never writes an older login over a newer rotation', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  const turn = prepareClaudeCredentialsMount(slug);
  // Two holders refresh from the same start: the turn later than the app.
  cliRefreshes(app, 1);
  cliRefreshes(turn, 2);
  turn.cleanup();
  assert.equal(stored(slug), 'rt-2');
  app.cleanup();
  assert.equal(stored(slug), 'rt-2', 'the app container ended last with the older rotation');
});

test('an unchanged copy never overwrites a login uploaded while it was held', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  setCredentials(slug, cred(5));
  app.cleanup();
  assert.equal(stored(slug), 'rt-5');
});

test('a turn boundary stores the app container rotation without waiting for its teardown', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  cliRefreshes(app, 1);
  syncClaudeCredentials(slug);
  assert.equal(stored(slug), 'rt-1');
  app.cleanup();
});

test('a login the operator cleared is not brought back by a copy still running', () => {
  const slug = freshApp(0);
  const app = prepareClaudeCredentialsMount(slug);
  cliRefreshes(app, 1);
  clearCredentials(slug);
  app.cleanup();
  assert.equal(db.prepare('SELECT claude_credentials_encrypted AS c FROM apps WHERE slug = ?').get(slug).c, null);
});
