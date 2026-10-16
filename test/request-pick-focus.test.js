import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

// The Request picker runs inside the app's own document, and the modal it opens
// lives in the dashboard. Neither failure below throws or shows in the console:
// the app's menu opens from the pick and keeps keyboard focus, so the modal's
// textarea just never receives what the user types. A headless-Chrome check
// reproduced both; these assertions pin the source shape that fixed them.

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');

const peek  = web('hooks/usePeek.tsx');
const modal = web('components/runtime-topbar/RequestModal.tsx');
const panel = web('components/runtime-topbar/RequestPanel.tsx');
const coder = web('components/coder/CoderPanel.tsx');
const keep  = web('hooks/useKeepFocusFromIframe.ts');

test('the pick swallows press/release events on the app window, in capture', () => {
  for (const t of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'touchstart', 'touchend']) {
    assert.match(peek, new RegExp(`'${t}'`), `${t} reaches the app — a menu that opens on it opens under the modal`);
  }
  assert.match(peek, /PRESS\.forEach\(t => win\?\.addEventListener\(t, onPress, true\)\)/,
    'press events must be stopped at the window in capture, before the app\'s document listeners');
  assert.match(peek, /stopImmediatePropagation\(\)/);
  assert.match(peek, /win\?\.addEventListener\('click',\s+onClick, true\)/,
    'the picking click must be taken at the window too');
});

test('the shared focus guard takes focus back from the app unless the user pressed in the app', () => {
  assert.match(keep, /queueMicrotask\(/, 'a timer lets keystrokes land in the app before focus returns');
  assert.doesNotMatch(keep, /setTimeout\(/, 'a timer lets keystrokes land in the app before focus returns');
  assert.match(keep, /document\.activeElement === iframe && !userInAppRef\.current\) targetRef\.current\?\.focus\(\)/);
  assert.match(keep, /addEventListener\('focusout', onAppFocusLoss, true\)/,
    'without hiding the focus loss, a trap that refocuses on focusout ping-pongs with the box');
  assert.match(keep, /const claim = useCallback\(\(\) => \{\s*userInAppRef\.current = false/,
    'the picking press lands in the app; claim() must not count it as the user choosing the app');
});

test('the Request modal, the Request drawer and the coder composer all use the shared guard', () => {
  assert.match(modal, /iframeRef\?: React\.RefObject<HTMLIFrameElement \| null>/);
  assert.match(modal, /useKeepFocusFromIframe\(iframeRef, taRef\)/);
  assert.match(modal, /onBlur=\{onTextareaBlur\}/);
  assert.match(panel, /useKeepFocusFromIframe\(iframeRef, taRef, \{ enabled: open \}\)/);
  assert.match(panel, /ref=\{taRef\}[\s\S]{0,200}?onBlur=\{keep\.onBlur\}/);
  assert.match(panel, /if \(open && peek\.ctx\) keep\.claim\(\)/);
  assert.match(coder, /useKeepFocusFromIframe\(props\.iframeRef, taRef, \{ enabled: open, frameKey: props\.frameKey \}\)/);
  assert.match(coder, /onBlur=\{keep\.onBlur\}/);
  assert.match(coder, /props\.onPeekConsumed\(\)\s*keep\.claim\(\)/);
  for (const [name, src] of [['RequestModal', modal], ['RequestPanel', panel], ['CoderPanel', coder]]) {
    assert.doesNotMatch(src, /userInAppRef/, `${name} carries its own copy of the guard instead of the shared hook`);
  }
});

test('both places that mount the Request modal hand it the app iframe', () => {
  assert.match(web('pages/AppFrame.tsx'), /<RequestModal[\s\S]{0,300}?iframeRef=\{iframeRef\}/);
  assert.match(web('pages/Applications.tsx'), /<RequestModal[\s\S]{0,300}?iframeRef=\{iframeRef\}/);
});

test('AppFrame hands the coder panel the app iframe, keyed on its URL', () => {
  assert.match(web('pages/AppFrame.tsx'), /<CoderPanel[\s\S]{0,900}?iframeRef=\{iframeRef\}\s*frameKey=\{stage\.url\}/);
});
