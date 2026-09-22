import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

/**
 * A user with their own Claude subscription token and NO platform
 * ANTHROPIC_API_KEY must be able to start a coder session.
 *
 * v2.81.0 shipped per-user tokens and relaxed the ROUTE gates to "any
 * credential resolves". builderSession.createSession kept its own
 * unconditional `if (!process.env.ANTHROPIC_API_KEY) throw`, so the route let
 * the caller through and the service refused. Measured on a real host, with a
 * real token stored and the env var unset:
 *
 *   POST /api/coder/streamprobe/session
 *   {"error":{"code":"INTERNAL_ERROR","message":"ANTHROPIC_API_KEY not configured"}}
 *
 * Nothing caught it: every existing test either sets ANTHROPIC_API_KEY or
 * stubs at the runAgent layer, which is BELOW this check. So this is a
 * source-level guard on the shape of the gate — the layer that failed is the
 * one no functional test reaches.
 */
const FILES = {
  builderSession: 'server/services/builder/builderSession.js',
  coderRoute:     'server/routes/coder.js',
};
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('createSession asks whether ANY credential resolves, not whether the platform key is set', () => {
  const src = read(FILES.builderSession);
  const fn = src.slice(src.indexOf('export async function createSession'));
  const body = fn.slice(0, fn.indexOf('\n}\n'));

  assert.doesNotMatch(
    body, /!process\.env\.ANTHROPIC_API_KEY/,
    'createSession gates on the platform key again — a user with only their own subscription token cannot start a session',
  );
  assert.match(
    body, /agentCredentialKind\(/,
    'createSession does not resolve the credential at all',
  );
  assert.match(
    body, /actingUserId: userId/,
    "createSession resolves without the acting user, so the caller's own token is invisible to it",
  );
});

test('no other unconditional platform-key gate stands between a session and a dispatch', () => {
  // The route and the service must ask the same question. If either one goes
  // back to reading the env var directly, a stored token stops working and the
  // symptom appears one layer away from the cause.
  for (const [name, path] of Object.entries(FILES)) {
    const src = read(path);
    const offenders = src.split('\n')
      .map((line, i) => [i + 1, line])
      .filter(([, line]) => /if \(!process\.env\.ANTHROPIC_API_KEY\)/.test(line));
    assert.deepEqual(
      offenders, [],
      `${name} refuses on the platform key alone: ${offenders.map(([n, l]) => `${n}: ${l.trim()}`).join(' | ')}`,
    );
  }
});
