import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Exactly ONE credential reaches an agent container, and which one is decided
// in exactly one place.
//
// The reason this file exists is a precedence rule that belongs to Claude Code,
// not to AppCrane. Anthropic documents it at
// https://code.claude.com/docs/en/authentication, highest first:
//
//   (2) ANTHROPIC_AUTH_TOKEN  (3) ANTHROPIC_API_KEY  (4) apiKeyHelper
//   (5) CLAUDE_CODE_OAUTH_TOKEN  (7) subscription OAuth from `claude /login`
//
// CLAUDE_CODE_OAUTH_TOKEN — the one-year token `claude setup-token` prints, and
// the only way to run an agent on a person's own subscription without a browser
// — ranks BELOW ANTHROPIC_API_KEY. A container handed both does not fail: it
// quietly bills the API key and the subscription is never touched. AppCrane has
// already been bitten by the same rule one rung up (see the "Credit balance is
// too low against the wrong account" comment on the credentials.json mount), so
// the assertions below are mostly ABSENCE assertions. "The OAuth token is set"
// proves nothing on its own; "and ANTHROPIC_API_KEY is not" is the whole test.
//
// Everything here inspects the argv that would be handed to docker, or drives a
// recording `docker` shim. Nothing needs a daemon.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-agentcred-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'debug';       // so the stderr log.debug line is emitted
delete process.env.ANTHROPIC_API_KEY;  // the platform key is opt-in per test

// A `docker` that leaks whatever credential it was given, on both streams.
const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/bin/sh\n' +
  'tok=""\n' +
  'for a in "$@"; do case "$a" in CLAUDE_CODE_OAUTH_TOKEN=*) tok="${a#CLAUDE_CODE_OAUTH_TOKEN=}";; esac; done\n' +
  // stderr, deliberately split mid-token across two writes with a real pause
  // between them, so Node sees TWO 'data' chunks and a scrubber that works on
  // raw chunks instead of whole lines lets the second half straight through.
  'printf "boom %s" "$(printf %s "$tok" | cut -c1-8)" >&2\n' +
  'sleep 0.3\n' +
  'printf "%s\\n" "$(printf %s "$tok" | cut -c9-)" >&2\n' +
  // stdout, as a well-formed stream-json assistant turn
  'printf \'{"type":"assistant","message":{"content":[{"type":"text","text":"i found %s"}]}}\\n\' "$tok"\n' +
  'exit 3\n',
  { mode: 0o755 },
);
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { setCredentials } = await import('../server/services/claudeCredentials.js');
const { setUserClaudeToken, clearUserClaudeToken } = await import('../server/services/userClaudeToken.js');
const {
  runAgentNew,
  runAgentExec,
  runAgentOneShot,
  agentCredentialKind,
  resolveAgentCredential,
  NO_CREDENTIAL_MESSAGE,
} = await import('../server/services/llm/runAgent.js');

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_TOKEN = 'sk-ant-oat01-PRETEND-USER-SUBSCRIPTION-TOKEN-0000';
const API_KEY    = 'sk-ant-api03-PRETEND-PLATFORM-KEY';

let slot = 0;
function mkApp(slug, { creds = false } = {}) {
  db.prepare('INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,?,?)')
    .run(slug, slug, ++slot, 'github', 'main');
  if (creds) {
    setCredentials(slug, { access_token: 'app-access-token', refresh_token: 'app-refresh-token' });
  }
  return slug;
}

let uid = 0;
function mkUser(role = 'admin') {
  const n = ++uid;
  return db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, `hash${n}`).lastInsertRowid;
}

// server/services/userClaudeToken.js is owned by another change and is a stub
// that throws today, so its two lookups are injected here. That is the same
// `deps` seam resolveAgentCredential exposes to callers.
const userTokenDeps = (userId, token = USER_TOKEN) => ({
  userClaudeTokenMeta: (id) => ({ present: id === userId, expiresAt: null }),
  getUserClaudeToken:  (id) => (id === userId ? token : null),
});
const noUserTokenDeps = {
  userClaudeTokenMeta: () => ({ present: false, expiresAt: null }),
  getUserClaudeToken:  () => null,
};

/** The -e VAR=value pairs in a docker argv, as an object. */
function envOf(args) {
  const out = {};
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] !== '-e') continue;
    const eq = args[i + 1].indexOf('=');
    out[args[i + 1].slice(0, eq)] = args[i + 1].slice(eq + 1);
  }
  return out;
}
/** The -v host:container pairs in a docker argv. */
const mountsOf = (args) => args.filter((a, i) => i > 0 && args[i - 1] === '-v');

const newAgent = (opts) => runAgentNew({
  image: 'appcrane/studio:test', workspaceDir: join(process.env.DATA_DIR, 'ws'), prompt: 'hi', ...opts,
});
const execAgent = (opts) => runAgentExec({ containerId: 'c123', prompt: 'hi', ...opts });

// ---------------------------------------------------------------------------
// 1. A user token wins, and nothing else comes with it
// ---------------------------------------------------------------------------

test('docker run: a user token sets CLAUDE_CODE_OAUTH_TOKEN and NO ANTHROPIC_API_KEY', () => {
  const user = mkUser();
  const slug = mkApp('run-usertoken', { creds: true });   // app creds present too
  const agent = newAgent({
    actingUserId: user, appSlug: slug, apiKey: API_KEY,   // ...and a platform key
    credentialDeps: userTokenDeps(user),
  });
  const env = envOf(agent.getDockerArgs());

  assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, USER_TOKEN);
  // The whole point. ANTHROPIC_API_KEY outranks the OAuth token, so its
  // presence here — even empty — is the silent-wrong-account bug.
  assert.ok(!('ANTHROPIC_API_KEY' in env), `ANTHROPIC_API_KEY leaked: ${JSON.stringify(env)}`);
  // And the app's credentials.json is not mounted either: that is a third
  // credential, and it outranks the OAuth token as well.
  assert.deepEqual(mountsOf(agent.getDockerArgs()).filter(m => m.includes('credentials.json')), []);
  agent.stop();
});

test('docker exec: a user token sets CLAUDE_CODE_OAUTH_TOKEN and NO ANTHROPIC_API_KEY', () => {
  const user = mkUser();
  const agent = execAgent({
    actingUserId: user, apiKey: API_KEY, hasAppCredentials: true,
    credentialDeps: userTokenDeps(user),
  });
  const env = envOf(agent.getDockerArgs());
  assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, USER_TOKEN);
  assert.ok(!('ANTHROPIC_API_KEY' in env), `ANTHROPIC_API_KEY leaked: ${JSON.stringify(env)}`);
  agent.stop();
});

test('an already-resolved oauthToken is accepted without a user lookup', () => {
  const agent = execAgent({ oauthToken: USER_TOKEN, apiKey: API_KEY });
  const env = envOf(agent.getDockerArgs());
  assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, USER_TOKEN);
  assert.ok(!('ANTHROPIC_API_KEY' in env));
  agent.stop();
});

test('end to end, no injection: a token in the real store reaches the container', () => {
  // The same path as the test above, but resolved through the real
  // server/services/userClaudeToken.js rather than the `deps` seam — the store,
  // the encryption round-trip and the argv in one measurement.
  const user = mkUser();
  const slug = mkApp('run-realstore', { creds: true });
  setUserClaudeToken(user, USER_TOKEN);
  try {
    const agent = newAgent({ actingUserId: user, appSlug: slug, apiKey: API_KEY });
    const env = envOf(agent.getDockerArgs());
    assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, USER_TOKEN);
    assert.ok(!('ANTHROPIC_API_KEY' in env), `ANTHROPIC_API_KEY leaked: ${JSON.stringify(env)}`);
    assert.deepEqual(mountsOf(agent.getDockerArgs()).filter(m => m.includes('credentials.json')), []);
    agent.stop();
  } finally {
    clearUserClaudeToken(user);
  }
});

// ---------------------------------------------------------------------------
// 2. Without a user token, the two older paths behave exactly as before
// ---------------------------------------------------------------------------

test('app credentials, no user token: the mount is unchanged and no key is set', () => {
  const user = mkUser();
  const slug = mkApp('run-appcreds', { creds: true });
  const agent = newAgent({
    actingUserId: user, appSlug: slug, apiKey: API_KEY, credentialDeps: noUserTokenDeps,
  });
  const args = agent.getDockerArgs();
  const env = envOf(args);

  assert.ok(!('ANTHROPIC_API_KEY' in env), 'API key would outrank the mounted credentials.json');
  assert.ok(!('CLAUDE_CODE_OAUTH_TOKEN' in env));
  // Both paths, legacy and dot-prefixed — unchanged from before this feature.
  const creds = mountsOf(args).filter(m => m.includes('credentials.json'));
  assert.equal(creds.length, 2);
  assert.ok(creds.some(m => m.endsWith(':/home/studio/.claude/credentials.json')), creds.join(' '));
  assert.ok(creds.some(m => m.endsWith(':/home/studio/.claude/.credentials.json')), creds.join(' '));
  agent.stop();
});

test('neither: the platform ANTHROPIC_API_KEY is set, as before', () => {
  const user = mkUser();
  const slug = mkApp('run-apikey');
  const agent = newAgent({
    actingUserId: user, appSlug: slug, apiKey: API_KEY, credentialDeps: noUserTokenDeps,
  });
  const env = envOf(agent.getDockerArgs());
  assert.equal(env.ANTHROPIC_API_KEY, API_KEY);
  assert.ok(!('CLAUDE_CODE_OAUTH_TOKEN' in env));
  assert.deepEqual(mountsOf(agent.getDockerArgs()).filter(m => m.includes('credentials.json')), []);
  agent.stop();
});

test('exec mode with nothing but a key behaves as before', () => {
  const agent = execAgent({ apiKey: API_KEY, credentialDeps: noUserTokenDeps });
  assert.equal(envOf(agent.getDockerArgs()).ANTHROPIC_API_KEY, API_KEY);
  agent.stop();
});

// ---------------------------------------------------------------------------
// 3. The precedence itself
// ---------------------------------------------------------------------------

test('precedence is user token > app credentials > platform key > none', () => {
  const user = mkUser();
  const slug = mkApp('kind-all', { creds: true });
  const withUser = userTokenDeps(user);

  assert.equal(agentCredentialKind({ actingUserId: user, appSlug: slug, apiKey: API_KEY }, withUser), 'user_oauth');
  assert.equal(agentCredentialKind({ actingUserId: user, appSlug: slug, apiKey: API_KEY }, noUserTokenDeps), 'app_credentials');

  const bare = mkApp('kind-bare');
  assert.equal(agentCredentialKind({ actingUserId: user, appSlug: bare, apiKey: API_KEY }, noUserTokenDeps), 'api_key');
  assert.equal(agentCredentialKind({ actingUserId: user, appSlug: bare, apiKey: '' }, noUserTokenDeps), 'none');
});

test('resolveAgentCredential hands back one secret and only one', () => {
  const user = mkUser();
  const slug = mkApp('resolve-all', { creds: true });
  const c = resolveAgentCredential({ actingUserId: user, appSlug: slug, apiKey: API_KEY }, userTokenDeps(user));
  assert.deepEqual(c, { kind: 'user_oauth', oauthToken: USER_TOKEN });
  assert.ok(!('apiKey' in c));
});

test('a token that vanishes between the presence check and the read falls through', () => {
  // present:true but the read returns nothing — a rotation mid-flight, or
  // ciphertext that no longer decrypts. Dispatching with NO credential would
  // be worse than dispatching with the platform key.
  const user = mkUser();
  const half = { userClaudeTokenMeta: () => ({ present: true }), getUserClaudeToken: () => null };
  assert.deepEqual(
    resolveAgentCredential({ actingUserId: user, apiKey: API_KEY }, half),
    { kind: 'api_key', apiKey: API_KEY },
  );
});

test('a token store that throws degrades to the next credential, it does not 500', () => {
  // This is the live state of server/services/userClaudeToken.js while it is a
  // stub: every lookup throws 'not implemented'. No gate may break on that.
  const boom = {
    userClaudeTokenMeta: () => { throw new Error('not implemented'); },
    getUserClaudeToken:  () => { throw new Error('not implemented'); },
  };
  assert.equal(agentCredentialKind({ actingUserId: 1, apiKey: API_KEY }, boom), 'api_key');
  assert.equal(agentCredentialKind({ actingUserId: 1, apiKey: '' }, boom), 'none');
});

// ---------------------------------------------------------------------------
// 4. The token never escapes
// ---------------------------------------------------------------------------

test('a user token never reaches a log line, a stream event, the stderr tail or an Error', async () => {
  const logged = [];
  mock.method(console, 'log', (...a) => { logged.push(a.join(' ')); });

  const seen = [];
  let failure = null;
  try {
    await runAgentOneShot({
      image: 'appcrane/studio:test',
      workspaceDir: join(process.env.DATA_DIR, 'ws'),
      prompt: 'hi',
      oauthToken: USER_TOKEN,
      timeoutMs: 30000,
      onChunk: (t) => seen.push(t),
    });
  } catch (err) {
    failure = err;
  }
  mock.restoreAll();

  // The shim exits 3, so the rejection carries the stderr tail — which is
  // exactly the path a leak would take to the operator's screen.
  // The shim splits the token across two writes, so "the whole token is absent"
  // is too weak on its own — half a credential in a log line is still a leak.
  // TAIL is the part after the split point: it must not appear either.
  const TAIL = USER_TOKEN.slice(8);
  const clean = (where, text) => {
    assert.ok(!text.includes(USER_TOKEN), `token in ${where}: ${text}`);
    assert.ok(!text.includes(TAIL), `token fragment in ${where}: ${text}`);
  };

  assert.ok(failure, 'the shim exits 3; runAgentOneShot must reject');
  clean('the rejection Error', failure.message);
  assert.ok(failure.message.includes('[redacted]'), `tail never carried the token at all: ${failure.message}`);

  const allLogs = logged.join('\n');
  assert.ok(allLogs.includes('[agent] stderr:'), 'the stderr debug line did not run; this test proved nothing');
  clean('a log line', allLogs);

  assert.ok(seen.length, 'no assistant text arrived; this test proved nothing');
  clean('a stream event', seen.join(''));
});

// ---------------------------------------------------------------------------
// 5. The route gates
// ---------------------------------------------------------------------------

function handlerFor(router, method, path) {
  for (const layer of router.stack) {
    const r = layer.route;
    if (r && r.path === path && r.methods[method]) return r.stack[r.stack.length - 1].handle;
  }
  throw new Error(`no ${method} ${path} on this router`);
}

/** Run a route handler and report the AppError code it produced, or 'passed'. */
async function outcome(handler, req) {
  try {
    await handler(req, { json: () => {}, status: () => ({ json: () => {} }) });
    return 'passed';
  } catch (err) {
    return err.code || err.message;
  }
}

test('the Builder gate refuses only when there is NO credential at all', async () => {
  const coder = (await import('../server/routes/coder.js')).default;
  const handler = handlerFor(coder, 'post', '/:slug/session');
  const user = mkUser('admin');

  // Nothing configured: a real refusal, with a message that names all three
  // ways out rather than only ANTHROPIC_API_KEY.
  const bare = mkApp('gate-none');
  const req = { params: { slug: bare }, user: { id: user, role: 'admin' }, body: {} };
  assert.equal(await outcome(handler, req), 'NOT_CONFIGURED');
  await handler(req, {}).catch((e) => {
    assert.equal(e.message, NO_CREDENTIAL_MESSAGE);
    assert.match(e.message, /subscription/i);
  });

  // The app has its own credentials.json and the platform has no key. Before
  // this change that was a 503 even though the dispatch would have worked.
  // NO_REPO is the NEXT check in the handler — reaching it is the pass.
  const withCreds = mkApp('gate-appcreds', { creds: true });
  assert.equal(
    await outcome(handler, { params: { slug: withCreds }, user: { id: user, role: 'admin' }, body: {} }),
    'NO_REPO',
  );

  // A caller with their own Claude subscription and NOTHING else on the
  // platform: no API key, and an app with no credentials.json of its own.
  // This is the case the old gate refused outright.
  setUserClaudeToken(user, USER_TOKEN);
  try {
    assert.equal(
      await outcome(handler, { params: { slug: bare }, user: { id: user, role: 'admin' }, body: {} }),
      'NO_REPO',
    );
  } finally {
    clearUserClaudeToken(user);
  }
  // ...and the refusal comes back the moment that token is gone again.
  assert.equal(await outcome(handler, req), 'NOT_CONFIGURED');

  // And the platform key still works on its own.
  process.env.ANTHROPIC_API_KEY = API_KEY;
  try {
    assert.equal(
      await outcome(handler, { params: { slug: bare }, user: { id: user, role: 'admin' }, body: {} }),
      'NO_REPO',
    );
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
  }
});

test('every AI entry point gates on agentCredentialKind, not on the platform key', async () => {
  // A source check because three of the four handlers reach a container or a
  // queue immediately after the gate. What matters is that no gate is left
  // reading process.env.ANTHROPIC_API_KEY directly — that is the exact line
  // that refused a caller holding their own subscription.
  const { readFileSync } = await import('fs');
  for (const f of ['coder.js', 'ask.js', 'appstudio.js', 'agents.js']) {
    const src = readFileSync(new URL(`../server/routes/${f}`, import.meta.url), 'utf8');
    assert.ok(src.includes('agentCredentialKind('), `${f} does not consult agentCredentialKind`);
    assert.ok(
      !/if \(!process\.env\.ANTHROPIC_API_KEY\)/.test(src),
      `${f} still refuses on the platform key alone`,
    );
  }
});
