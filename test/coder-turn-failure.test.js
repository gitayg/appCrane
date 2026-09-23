import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { explainTurnFailure, isAuthFailure } from '../server/services/builder/turnFailure.js';
import { parseLine } from '../server/services/builder/streamJsonParser.js';

// Found by testing the paused-session fix for real: a rejected API key came
// back as a grey assistant bubble reading "Failed to authenticate. API Error:
// 401 API key is invalid." -- styled exactly like the coder's answer, and
// saying nothing about which credential to replace or where.
const CLI_401 = 'Failed to authenticate. API Error: 401 API key is invalid.';

test('a rejected credential names the credential and where to replace it', () => {
  const byKind = {
    user_oauth:      /claude setup-token[\s\S]*profile/,
    app_credentials: /credentials\.json/,
    api_key:         /ANTHROPIC_API_KEY/,
  };
  for (const [kind, fix] of Object.entries(byKind)) {
    const msg = explainTurnFailure({ text: CLI_401, isError: true, code: 1, kind });
    assert.ok(msg, `${kind}: an auth failure was treated as success`);
    assert.match(msg, fix, `${kind}: ${msg}`);
    assert.match(msg, /Claude said: Failed to authenticate/, `${kind}: the original error was dropped`);
  }
});

test('a successful reply that mentions 401 is an answer, not a failure', () => {
  assert.equal(explainTurnFailure({ text: 'I fixed the 401 handler in auth.js.', isError: false, code: 0, kind: 'api_key' }), null);
});

test('any other failed turn still says it failed, with what it printed', () => {
  const msg = explainTurnFailure({ text: '', isError: false, code: 137, kind: 'api_key', stderrTail: ['Killed'] });
  assert.match(msg, /turn failed \(exit 137\)[\s\S]*Killed/);
});

test('the parser keeps the CLI result is_error flag', () => {
  const ev = parseLine(JSON.stringify({ type: 'result', is_error: true, usage: {} }));
  assert.equal(ev.isError, true, 'is_error is dropped, so a failed turn exits looking like a success');
  assert.equal(parseLine(JSON.stringify({ type: 'result', usage: {} })).isError, false);
  assert.ok(isAuthFailure(CLI_401));
});

const session = readFileSync(new URL('../server/services/builder/builderSession.js', import.meta.url), 'utf8');
const hook    = readFileSync(new URL('../studio-web/src/components/coder/useCoderSession.ts', import.meta.url), 'utf8');

test('the turn records and shows the explanation instead of the raw failure text', () => {
  assert.match(session, /if \(failure\) \{\s*appendMessage\(sessionId, 'assistant', failure/);
  assert.match(session, /publish\(sessionId, \{ type: 'error', message: failure, turnFailed: true \}\)/);
  assert.match(hook, /ev\.turnFailed && last\?\.kind === 'assistant' \? p\.slice\(0, -1\)/,
    'the failure is still left on screen as a reply bubble');
});

test('the codebase summary is not rebuilt for a resumed thread, and its build is announced', () => {
  assert.match(session, /loadDispatchContext\(state\.appSlug, c\.workspaceDir, \{ withCodebase: !isResume, sessionId \}\)/,
    'every turn rebuilds a summary only the first turn sends');
  assert.match(session, /Reading the codebase before your first message/, 'the build runs with nothing on screen');
  assert.match(session, /Could not prepare the codebase summary \(\$\{err\.message\}\)/, 'a failed build is silent');
});

