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

test('the Request modal takes focus back from the app unless the user pressed in the app', () => {
  assert.match(modal, /iframeRef\?: React\.RefObject<HTMLIFrameElement \| null>/);
  assert.match(modal, /onBlur=\{onTextareaBlur\}/);
  assert.match(modal, /queueMicrotask\(/, 'a timer lets keystrokes land in the app before focus returns');
  assert.match(modal, /document\.activeElement === iframe && !userInAppRef\.current\) taRef\.current\?\.focus\(\)/);
  assert.match(modal, /addEventListener\('focusout', onAppFocusLoss, true\)/,
    'without hiding the focus loss, a trap that refocuses on focusout ping-pongs with the modal');
});

test('both places that mount the Request modal hand it the app iframe', () => {
  assert.match(web('pages/AppFrame.tsx'), /<RequestModal[\s\S]{0,300}?iframeRef=\{iframeRef\}/);
  assert.match(web('pages/Applications.tsx'), /<RequestModal[\s\S]{0,300}?iframeRef=\{iframeRef\}/);
});
