import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// A coder session that belongs to someone else — pinned or simply the app's
// latest — is read-only for the viewer: every action on it is the owner's
// (routes/coder.js assertSessionOwner). Before v2.111.0 the panel only knew
// that for a PINNED session, so the app's latest showed a Resume button and a
// composer that both answered 403 NOT_SESSION_OWNER, and no way to start your
// own. tsc cannot check any of this.

const web = (p) => readFileSync(fileURLToPath(new URL(`../studio-web/src/${p}`, import.meta.url)), 'utf8');
const panel = web('components/coder/CoderPanel.tsx');
const hook = web('components/coder/useCoderSession.ts');
const api = web('components/coder/api.ts');
const refusal = web('components/coder/CoderRefusal.tsx');

test('"another user\'s session" is decided from the session owner, not from whether it was pinned', () => {
  assert.match(panel, /const otherUser = !!s\.session && props\.viewerId != null && s\.session\.user_id !== props\.viewerId/);
  assert.match(panel, /const readOnly = [^\n]*\|\| otherUser/, 'readOnly does not include otherUser');
});

test('on another user\'s session there is no Resume and no composer', () => {
  assert.match(panel, /\{s\.status === 'paused' && !readOnly && \(/, 'the Resume block is not gated on readOnly');
  assert.match(panel, /\{s\.sessionId && !otherUser && \(\s*<div\s+className="coder-composer"/, 'the composer is not hidden for another user\'s session');
});

test('it says whose session it is and offers "Start my own session", which asks to take over', () => {
  const block = panel.slice(panel.indexOf('{otherUser && isLiveStatus(s.status) && ('), panel.indexOf('Start my own session') + 40);
  assert.ok(block.length > 40, 'no other-user block');
  assert.match(block, /s\.session\?\.user_name/, 'the block does not name the session\'s owner');
  assert.match(block, /onClick=\{\(\) => void s\.start\(true\)\}/, '"Start my own session" does not request a take-over');
  assert.match(block, /disabled=\{s\.starting \|\| othersTurnRunning\}/, 'the button is offered while their turn is running');
  assert.match(hook, /const start = useCallback\(async \(takeOver = false\) =>[\s\S]*coderApi\.startSession\(slug, takeOver\)/);
  assert.match(api, /takeOver \? \{ take_over: true \} : undefined/);
});

test('a BUILDER_OCCUPIED refusal offers Take over; BUILDER_BUSY does not', () => {
  assert.match(refusal, /onTakeOver && code === 'BUILDER_OCCUPIED'/);
  assert.match(panel, /onTakeOver=\{otherUser \? \(\) => void s\.start\(true\) : \(\) => void s\.resume\(true\)\}/);
});
