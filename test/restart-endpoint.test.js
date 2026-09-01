import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// A restart button that is a restart button (v2.56.0).
//
// A host whose update landed the files but could not finish — new code on disk,
// old code in memory — needs exactly one thing: a restart, so safe-boot.sh
// (v2.55.1) can reconcile the runtime on the way up. Until now the only ways to
// get one were ssh, or POSTing a config import, which restarts as a side effect
// of REPLACING THE DATABASE. Reaching for that as a restart button would be a
// catastrophe with a plausible motive, which is reason enough for this to exist.
//
// Asserted against the source: the handler's whole behaviour is process.exit,
// and a test that actually invoked it would kill the test runner.

const SRC = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
const H = SRC.slice(
  SRC.indexOf("app.post('/api/self-update/restart'"),
  SRC.indexOf("app.get('/api/self-update/status'"),
);

test('the handler exists and is platform-admin only', () => {
  assert.ok(H.length > 300, 'could not find the restart handler');
  assert.match(H, /requireAuth,\s*requirePlatformAdmin/,
    'a process kill switch must not be reachable below platform admin');
});

test('it refuses without an explicit confirm', () => {
  assert.match(H, /confirm !== '1'/,
    'if AppCrane is not supervised, exiting stops the server — that must be a deliberate act, '
    + 'not something a stray POST does');
  assert.match(H, /CONFIRM_REQUIRED/);
});

test('it refuses while a build is in flight, with the same escape hatch as self-update', () => {
  assert.match(H, /status IN \('pending','building','deploying'\)/,
    'killing the process mid-build orphans the container and leaves dangling layers');
  assert.match(H, /BUILDS_IN_FLIGHT/);
  assert.match(H, /req\.query\.force/, 'a genuinely stuck build has to be overridable');
});

test('it responds BEFORE exiting', () => {
  const respond = H.indexOf('res.json(');
  const exit = H.indexOf('process.exit(0)');
  assert.ok(respond > -1 && exit > -1);
  assert.ok(respond < exit,
    'exiting before the response flushes gives the caller a dropped connection instead of a '
    + 'confirmation, which reads as a crash');
  assert.match(H, /setTimeout\(/, 'the exit must be deferred so the response actually leaves');
});

test('it writes nothing and fetches nothing', () => {
  // The value of this endpoint is that it is boring. If it grew a git fetch or
  // a migration it would become another thing that can fail halfway.
  assert.doesNotMatch(H, /execFileSync|git |npm install|reset --hard/,
    'a restart endpoint that touches the tree is a second updater, with the same failure modes');
});

test('the audit write cannot block the restart', () => {
  assert.match(H, /catch \(_\) \{ \/\* an audit write is never a reason to refuse the restart/,
    'a host reaching for this is already in a bad state; a failing audit insert must not be what '
    + 'stops it recovering');
});
