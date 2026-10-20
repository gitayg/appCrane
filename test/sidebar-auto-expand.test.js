import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The admin sidebar rests as an icon rail and opens over the page on hover,
// focus or a tap; a pin keeps the old always-open layout. Behaviour is
// verified in a real browser separately; these pin the wiring that makes it.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const layout = read('studio-web/src/components/Layout.tsx');
const css = read('studio-web/src/admin.css');

test('hover-intent: open after a short delay, close after a longer one', () => {
  assert.match(layout, /const HOVER_OPEN_MS = 150\b/);
  assert.match(layout, /const HOVER_CLOSE_MS = 300\b/);
  assert.match(layout, /openTimer\.current = setTimeout\(\(\) => setPeek\(true\), HOVER_OPEN_MS\)/);
  assert.match(layout, /closeTimer\.current = setTimeout\(\(\) => setPeek\(false\), HOVER_CLOSE_MS\)/);
  assert.match(layout, /onPointerEnter=\{onSidebarPointerEnter\}/);
  assert.match(layout, /onPointerLeave=\{onSidebarPointerLeave\}/);
});

test('the rail opens over the page: content offset follows the pin, not the hover', () => {
  assert.match(layout, /const collapsed = !pinned && !peek && !mobileOpen/);
  assert.match(layout, /<main className=\{`admin-content\$\{pinned \? '' : ' collapsed'\}`\}>/);
  assert.match(layout, /'--content-left', \(pinned \? sidebarWidth : 56\) \+ 'px'/);
  assert.match(css, /\.admin-sidebar\.peek \{[^}]*width: var\(--sidebar-w, 220px\);[^}]*z-index: 20;/);
});

test('keyboard: focus inside expands it, Escape collapses it', () => {
  assert.match(layout, /onFocus=\{onSidebarFocus\}/);
  assert.match(layout, /onBlur=\{onSidebarBlur\}/);
  assert.match(layout, /const onSidebarFocus = \(\) => \{[\s\S]*?setPeek\(true\)/);
  assert.match(layout, /onKeyDown=\{onSidebarKeyDown\}/);
  assert.match(layout, /if \(e\.key !== 'Escape' \|\| pinned \|\| !peek\) return[\s\S]*?setPeek\(false\)/);
});

test('touch never hovers: the first tap on the resting rail opens it', () => {
  assert.match(layout, /if \(e\.pointerType === 'touch'\) return/);
  assert.match(layout, /onClickCapture=\{onSidebarClickCapture\}/);
  assert.match(layout, /lastPointer\.current !== 'touch' \|\| pinned \|\| peek \|\| isNarrow\(\)\) return\s*e\.preventDefault\(\)/);
});

test('the pin ("Keep expanded") is persisted in localStorage and replaces the manual collapse', () => {
  assert.match(layout, /localStorage\.getItem\('cc_sb_pin'\) === '1'/);
  assert.match(layout, /localStorage\.setItem\('cc_sb_pin', next \? '1' : ''\)/);
  assert.match(layout, /onClick=\{togglePin\}/);
  assert.match(layout, /aria-pressed=\{pinned\}/);
  assert.doesNotMatch(layout, /cc_sb_col/);
});

test('reduced motion: no width animation', () => {
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{\s*\.admin-sidebar, \.admin-sidebar\.peek \{ transition: none; \}/);
});

test('collapsed icons keep an accessible name', () => {
  assert.match(layout, /aria-label=\{collapsed \? p\.label : undefined\}/);
  assert.match(layout, /title=\{a\.name\}\s*aria-label=\{a\.name\}/);
  assert.match(layout, /title="Sign out" aria-label="Sign out"/);
});
