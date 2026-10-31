import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The coder panel's Requests drawer. The server behaviour is pinned in
// coder-panel-requests.test.js; these pin how the panel reaches it: the
// picked ids go through the fenced dispatch (never into the message box),
// into the session on screen, never while a turn runs, at most the batch cap,
// and a "#123" in the user's message goes along as request_ids.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const panel = read('studio-web/src/components/coder/CoderPanel.tsx');
const drawer = read('studio-web/src/components/coder/CoderRequests.tsx');
const hook = read('studio-web/src/components/coder/useCoderSession.ts');
const reqHook = read('studio-web/src/components/coder/useCoderRequests.ts');
const api = read('studio-web/src/components/coder/api.ts');

test('the panel renders the drawer behind a Requests toggle', () => {
  assert.match(panel, /import \{ CoderRequests \} from '\.\/CoderRequests'/);
  assert.match(panel, /\{showRequests && \(\s*<CoderRequests/);
  assert.match(panel, /onClick=\{\(\) => \{ setShowRequests\(v => !v\); setTab\('chat'\) \}\}/);
});

test('the list comes from the per-app coder route', () => {
  assert.match(api, /adminApi\.get<\{ requests: CoderRequest\[\] \}>\(`\$\{base\(slug\)\}\/requests\$\{includeClosed \? '\?include_closed=1' : ''\}`\)/);
  assert.match(reqHook, /coderApi\.requests\(slug, showClosed\)/);
});

test('sending goes through the fenced dispatch into the session on screen, not the message box', () => {
  assert.match(panel, /onSend=\{s\.sendRequests\}/);
  assert.match(hook, /const r = await coderApi\.dispatchRequests\(slug, ids, sessionId \|\| undefined\)/);
  assert.match(api, /\{ request_ids: requestIds, \.\.\.\(sessionId \? \{ session_id: sessionId \} : \{\}\) \}/);
  assert.doesNotMatch(drawer, /setDraft|excerpt\)\s*=>\s*onMention/, 'the drawer writes request text into the message box');
  assert.match(drawer, /onClick=\{\(\) => props\.onMention\(r\.id\)\}/);
});

test('sending is off while the coder is mid-turn, with the reason shown', () => {
  assert.match(panel, /: s\.streaming \? 'The coder is in the middle of a turn\. Send these once it finishes, or stop it\.'/);
  assert.match(panel, /blockedReason=\{requestsBlocked\}/);
  assert.match(drawer, /disabled=\{n === 0 \|\| sending \|\| !!blockedReason\}/);
  assert.match(drawer, /\{n > 0 && blockedReason && <div className="coder-note" role="status">\{blockedReason\}<\/div>\}/);
  assert.match(hook, /if \(sessionId && status !== 'idle'\) throw new Error/);
});

test('picking stops at the batch cap and keeps the order picked', () => {
  assert.match(drawer, /import \{ MAX_CODER_BATCH \} from '\.\/SendToCoderBar'/);
  assert.match(drawer, /p\.includes\(id\) \? p\.filter\(x => x !== id\) : p\.length >= MAX_CODER_BATCH \? p : \[\.\.\.p, id\]/);
  assert.match(reqHook, /return out\.slice\(0, MAX_CODER_BATCH\)/);
});

test('a #id in the message goes along as request_ids, only for this app\'s open requests', () => {
  assert.match(reqHook, /if \(openIds\.has\(id\) && !out\.includes\(id\)\) out\.push\(id\)/);
  assert.match(panel, /const refs = referencedRequestIds\(text, reqs\.openIds\)\n\s*void s\.send\(text, undefined, files, refs\)/);
  assert.match(hook, /coderApi\.dispatch\(slug, sessionId, text, chosen \|\| model \|\| undefined, mode \|\| undefined, attachmentIds, requestIds\)/);
  assert.match(api, /\.\.\.\(requestIds\?\.length \? \{ request_ids: requestIds \} : \{\}\)/);
});

test('each request links to its full page', () => {
  assert.match(drawer, /<Link to=\{`\/requests\/\$\{r\.id\}`\} target="_blank" rel="noopener"/);
});
