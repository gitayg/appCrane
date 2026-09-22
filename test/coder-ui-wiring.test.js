import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

// The coder chat UI talks to /api/coder across a process boundary with no
// shared types and no integration test — studio-web is built separately and
// the browser is the only place the two ever meet. Every assertion below is a
// place where the client and server AGREE TODAY and where a change on either
// side would produce a UI that compiles, builds, renders, and silently does
// nothing useful. tsc cannot see any of them.

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');
const srv = (p) => readFileSync(new URL(`../server/${p}`, import.meta.url), 'utf8');

const coderRoute   = srv('routes/coder.js');
const api          = web('components/coder/api.ts');
const useSession   = web('components/coder/useCoderSession.ts');
const panel        = web('components/coder/CoderPanel.tsx');
const changes      = web('components/coder/CoderChanges.tsx');
const appFrame     = web('pages/AppFrame.tsx');
const adminApi     = web('adminApi.ts');
const css          = web('admin.css');

// ---------------------------------------------------------------------------
// The request bodies
// ---------------------------------------------------------------------------

test('dispatch sends `prompt`, which is the only field the route reads', () => {
  assert.match(coderRoute, /const \{ prompt \} = req\.body/,
    'the route changed its field name — the client below has to follow');
  assert.match(api, /dispatch:[\s\S]{0,300}?\{ prompt \}/,
    'a dispatch body keyed anything but `prompt` is answered 400 VALIDATION, and the ' +
    'chat just looks broken: the message leaves the composer and no turn ever starts');
});

test('release posts `paths` (and an optional `message`)', () => {
  assert.match(coderRoute, /const paths = req\.body\?\.paths/);
  assert.match(api, /release:[\s\S]{0,300}?\{ paths, message \}[\s\S]{0,60}\{ paths \}/,
    'release takes a paths array; sending files, or the whole change set, is a 400');
});

// ---------------------------------------------------------------------------
// The two encodings on one SSE channel
// ---------------------------------------------------------------------------

test('the route really does emit replayed events unwrapped and live ones wrapped', () => {
  // Replay: the stored row IS the event, sent verbatim.
  assert.match(coderRoute, /for \(const row of recent\) \{[\s\S]{0,120}?send\(JSON\.parse\(row\.content\)\)/,
    'replay stopped sending the raw stored event — re-check the client parser');
  // Live: builderSession wraps the same object.
  assert.match(srv('services/builder/builderSession.js'), /publish\(sessionId, \{ type: 'stream', event: ev \}\)/,
    'live events stopped being wrapped — re-check the client parser');
});

test('the stream reader accepts BOTH encodings', () => {
  // A reader that only unwraps `{type:'stream'}` renders live turns fine and
  // drops the entire replayed transcript — which looks like "the session lost
  // my history", not like a bug, so it can sit there indefinitely.
  assert.match(useSession, /ev\.type === 'stream'/,
    'the live (wrapped) form must be unwrapped');
  assert.match(useSession, /ev\.type === 'text'[\s\S]{0,160}?return ev as StreamEvent/,
    'the replayed (bare) form must be accepted too, or reopening the panel shows an empty chat');
});

test('a reconnect re-reads history instead of appending a second copy', () => {
  // The route replays on EVERY connect. Appending replay onto what is already
  // rendered duplicates the whole transcript once per blip.
  assert.match(useSession, /setLive\(\[\]\)/,
    'the live half must be cleared on each connect, or a reconnect doubles the transcript');
  assert.match(useSession, /watermark = d\.messages\.reduce/,
    'the ?after= watermark comes from the persisted message ids; without it the replay ' +
    'repeats the turns already shown as history');
  assert.match(coderRoute, /req\.query\.after/,
    'the route stopped honouring ?after= — the client watermark is now a no-op');
});

// ---------------------------------------------------------------------------
// SSE authentication
// ---------------------------------------------------------------------------

test('the SSE credential is sent under the name /api/coder resolves it by', () => {
  // coder.js promotes ?token= to Bearer and ?api_key= to X-API-Key, and those
  // are two DIFFERENT lookups (identity_sessions vs users.api_key_hash). An
  // admin-SPA browser holds only cc_api_key, so sending it as ?token= is a
  // 401 on the stream while every other call on the page succeeds.
  assert.match(coderRoute, /req\.query\.api_key && !req\.headers\['x-api-key'\]/);
  assert.match(coderRoute, /req\.query\.token && !req\.headers\.authorization/);
  assert.match(adminApi, /export function authParamsForSSE[\s\S]{0,400}?\{ api_key: key \}/,
    'the helper must be able to name the credential api_key, not only token');
  assert.match(api, /authParamsForSSE\(\)/,
    'the events URL must use the name-aware helper, not a bare ?token=');
});

// ---------------------------------------------------------------------------
// Who gets the button, and who gets the release control
// ---------------------------------------------------------------------------

test('the coder button appears only for Crane-hosted apps', () => {
  // /api/coder refuses everything else (NOT_CRANE_HOSTED / NO_REPO), so a
  // button on a GitHub-backed app can only ever produce a refusal.
  assert.match(appFrame, /craneHosted: app\.source_type === 'managed' && app\.repo_backend === 'local'/,
    'the gate must be the same predicate as managedRepo.usesLocalRepo()');
  assert.match(appFrame, /\{stage\.craneHosted && \([\s\S]{0,400}?Coder<\/button>/,
    'the topbar button must be gated on craneHosted');
  // And the server-side predicate it mirrors has not moved.
  assert.match(srv('services/managedRepo.js'),
    /usesLocalRepo\(app\) \{\s*\n\s*return app\?\.source_type === 'managed' && repoBackendOf\(app\) === REPO_BACKEND_LOCAL/,
    'usesLocalRepo changed shape — the client mirror in AppFrame must follow');
});

test('release is offered only to an app admin, because the route requires one', () => {
  assert.match(coderRoute, /requireAppAdmin\(app, req\.user, 'releasing changes'\)/);
  assert.match(coderRoute, /row\?\.app_role === 'admin' \|\| row\?\.app_role === 'owner'/);
  assert.match(appFrame, /canRelease: app\.app_role === 'admin' \|\| app\.app_role === 'owner'/,
    'the client gate must mirror requireAppAdmin, or non-admins are shown a button that 403s');
  assert.match(changes, /canRelease \?/,
    'CoderChanges must branch on canRelease rather than always rendering the control');
});

// ---------------------------------------------------------------------------
// Docked, not overlaid
// ---------------------------------------------------------------------------

test('the panel shrinks the iframe rather than covering it', () => {
  // The whole point of the surface is talking about the app while looking at
  // it. An overlay at this width hides most of the app it is about.
  assert.match(appFrame, /\['--frame-dock-width' as string\]: `\$\{dockWidth\}px`/,
    'AppFrame must publish the dock width the iframe shrinks by');
  assert.match(css, /\.lstage-iframe \{[\s\S]{0,200}?width: calc\(100% - var\(--frame-dock-width, 0px\)\)/,
    'the iframe must consume --frame-dock-width, or the panel lands on top of the app');
  assert.match(css, /\.lstage-frame \{[^}]*position: relative/,
    'the absolutely-positioned panel needs .lstage-frame as its containing block');
});

// ---------------------------------------------------------------------------
// Refusals rendered as themselves
// ---------------------------------------------------------------------------

test('the fetch helper keeps the error code, so refusals can be told apart', () => {
  assert.match(adminApi, /export class ApiError extends Error/);
  assert.match(adminApi, /throw new ApiError\(err\?\.message[\s\S]{0,80}?err\?\.code/,
    'flattening every failure to new Error(message) leaves no way to branch on a refusal');
});

test('every refusal code the coder routes emit has UI copy', () => {
  const refusal = web('components/coder/CoderRefusal.tsx');
  for (const code of ['NOT_CRANE_HOSTED', 'NO_REPO', 'NOT_CONFIGURED', 'BUILDER_OCCUPIED', 'ENV_FILE_IN_PUSH']) {
    assert.match(refusal, new RegExp(code),
      `${code} is a distinct thing for the user to do about it; rendering it as a generic ` +
      'error tells them nothing');
    // ...and the code is still one the platform actually produces.
    // ENV_FILE_IN_PUSH is thrown by the push guard (status 422, code preserved
    // by coder.js's `if (err.status) throw err`), not by the route itself.
    const source = code === 'ENV_FILE_IN_PUSH' ? srv('services/envFilePushGuard.js') : coderRoute;
    assert.match(source, new RegExp(code), `${code} is no longer emitted — drop the UI copy`);
  }
});

// ---------------------------------------------------------------------------
// The picker is not reimplemented
// ---------------------------------------------------------------------------

test('the coder prompt reuses the one usePeek picker', () => {
  assert.match(panel, /peekToPromptPrefix/,
    'the picked element must be turned into a prompt prefix by the shared helper');
  assert.doesNotMatch(panel, /usePeek\(/,
    'a second usePeek instance would install a second overlay on the same iframe');
  assert.match(appFrame, /peekFor === 'coder'/,
    'one picker, two consumers: the pick has to be routed to whoever started it');
});

// ---------------------------------------------------------------------------
// Sandbox only
// ---------------------------------------------------------------------------

test('the panel offers no promote-to-production control', () => {
  // The salvaged UI had one. This tool releases to sandbox; production stays a
  // separate, deliberate human action in the normal deploy flow.
  for (const [name, src] of [['CoderPanel', panel], ['CoderChanges', changes]]) {
    assert.doesNotMatch(src, /promote/i, `${name} must not offer promotion to production`);
  }
});
