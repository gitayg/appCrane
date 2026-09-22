import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// An expired session must not go unnoticed.
//
// Three surfaces, and all three were wrong in different ways.
//
// 1. THE POLARITY. adminApi.ts matched the 401 body against five known-bad
//    messages and redirected only on a match. The server returns TWELVE
//    distinct 401 messages — `Token expired`, `Invalid or expired token`,
//    `Authentication required`, `Authorization required` and three more were
//    not on the list. So an expired identity token answered `Token expired`,
//    matched nothing, and NOTHING HAPPENED: no redirect, no cleared
//    credential, a dead session behind a screen that still looked live.
//
//    An allowlist that must enumerate every message the server might invent,
//    and that does nothing when it misses one, fails OPEN. Inverted: a 401 from
//    a session-gated route means the session is gone, and the routes that
//    answer 401 for other reasons are named. A wrong password is the sign-in
//    screen's own answer, not a lapsed session, so the login routes are
//    excluded — redirecting there is a loop nobody can type a password through.
//
// 2. api.ts HAD NO 401 HANDLING AT ALL. Its two callers were AppStudio's agent
//    chat, the only files not going through adminApi, so an expired session
//    threw a raw `401 Unauthorized: ...` string and left the dead credential in
//    place. That file was the client for /api/agents and went with it in
//    v2.83.0, so adminApi is now the only fetch helper in the SPA and (1) is
//    the whole of the fetch story. The assertions that read api.ts are gone
//    with it; nothing else covered it.
//
// 3. THE SSE LOOP, which is the one that truly went unnoticed. EventSource
//    reports errors with NO status code, and ChatPanel wired `onerror` straight
//    to a reconnect — unbounded, with no delay, and never closing the
//    replacement. An expired session became a tight loop spawning EventSources
//    forever: no error, no redirect, nothing on screen to notice, and a leak.
//
// A LATCH, NOT AN EVENT: several pollers refuse in the same instant when a
// cookie lapses. Each would call replace(). One bounce, not four.

const read = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');
const expiry = read('sessionExpiry.ts');
const adminApi = read('adminApi.ts');
// The salvaged ChatPanel was the /api/agents chat UI, kept outside src/ after
// that router was retired so the SSE hygiene below would survive the port. The
// port happened in v2.84.0 (components/coder/useCoderSession.ts) and the
// salvage was deleted, so (3) now guards the live file. That is the point of
// these three: the hygiene has to be in whatever code actually opens an
// EventSource, not in a museum piece nobody runs.
const chat = read('components/coder/useCoderSession.ts');

// ---------------------------------------------------------------------------
// Polarity
// ---------------------------------------------------------------------------

test('no surface gates the redirect on an allowlist of server messages', () => {
  // The regression that matters. Any reappearance of a message set that the
  // redirect depends on re-opens the exact hole: a message nobody listed means
  // an expired session goes silent.
  for (const [name, src] of [['sessionExpiry', expiry], ['adminApi', adminApi]]) {
    assert.doesNotMatch(src, /PROVEN_BAD_CREDENTIAL_MESSAGES/,
      `${name} still gates on a known-bad message list; the server has twelve 401 messages and ` +
      'anything missing from the list fails open — which is how `Token expired` went unnoticed');
  }
});

test('the login routes are excluded, so a wrong password cannot loop', () => {
  assert.match(expiry, /NON_SESSION_401_PATHS/);
  assert.match(expiry, /identity\/login/,
    'the login route must be excluded: its 401 is a wrong password, not a lapsed session, and ' +
    'redirecting there is a loop that never lets anyone sign in');
  assert.match(expiry, /isNonSessionRoute/);
  assert.match(expiry, /if \(!isNonSessionRoute\(url\)\) clearCredentialsAndRedirect\(\)/,
    'the exclusion has to gate the redirect, not merely exist');
});

test('the fetch helper passes the request path so the exclusion can apply', () => {
  // handleUnauthorized cannot exclude the login route unless it is told which
  // route answered. A call that drops the url silently loses the exclusion.
  assert.match(adminApi, /handleUnauthorized\(r, path\)/,
    'adminApi must pass the path, or the login-route exclusion cannot fire');
});

// ---------------------------------------------------------------------------
// The silent loop (guarding the live coder stream, see the note above)
// ---------------------------------------------------------------------------

test('an SSE error probes the session before reconnecting', () => {
  assert.match(chat, /sessionStillValid\(\)/,
    'EventSource exposes no status code, so a lapsed session and a dropped connection are ' +
    'indistinguishable here; the only way to tell them apart is to ask over a channel that can answer');
});

test('the reconnect stops when the session is gone', () => {
  assert.match(chat, /if \(!ok \|\| stopped/,
    'a false answer means a bounce is under way — reconnecting then races the redirect');
});

test('the reconnect backs off and cannot be a tight loop', () => {
  assert.match(chat, /Math\.min\(1000 \* 2 \*\* attempt/,
    'the old version retried as fast as the browser allowed, turning any outage into a hot loop');
});

test('the replacement EventSource is closed, not leaked', () => {
  // The original created `es2` inside onerror, assigned onerror to it, and
  // returned a cleanup that closed only the ORIGINAL `es`. Every reconnect
  // leaked one EventSource, forever, for as long as the session stayed dead.
  assert.doesNotMatch(chat, /const es2 = api\.events/,
    'the leaking second EventSource is back');
  assert.match(chat, /return \(\) => \{[\s\S]{0,200}?current\?\.close\(\)/,
    'cleanup must close whichever EventSource is current, not the first one created');
});

// ---------------------------------------------------------------------------
// The latch
// ---------------------------------------------------------------------------

test('concurrent refusals produce ONE bounce', () => {
  assert.match(expiry, /if \(bounced\) return\s*\n\s*bounced = true/,
    'several pollers refuse in the same instant when a cookie lapses; without a latch each one ' +
    'calls replace() and the user is bounced once per poller');
});

test('pollers can ask whether the session has already lapsed', () => {
  assert.match(expiry, /export function sessionHasLapsed/,
    'a poller needs a way to stop rather than keep retrying into a session already known dead');
});

// ---------------------------------------------------------------------------
// The ambiguous case must not log anyone out
// ---------------------------------------------------------------------------

test('a network failure during the probe reconnects rather than signing the user out', () => {
  const fn = /export async function sessionStillValid[\s\S]*?\n\}/.exec(expiry);
  assert.ok(fn, 'sessionStillValid was renamed — update this test deliberately');
  assert.match(fn[0], /catch \(_\) \{\s*\n\s*return true/,
    'an unreachable server is not proof the session died; treating it as proof would sign a user ' +
    'out of a working session because their wifi dropped');
});

test('the redirect preserves where the user was', () => {
  assert.match(expiry, /\?redirect=' \+ encodeURIComponent\(here\)/);
  assert.match(expiry, /here !== '\/applications' && here !== '\/login'/,
    'bouncing a user back to the page they are being sent to is a loop');
});
