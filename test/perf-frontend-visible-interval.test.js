import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Admin UI polling stops while the tab is hidden and, when it is shown again,
// refreshes at once and resumes.

const listeners = new Map();
globalThis.document = {
  hidden: false,
  addEventListener: (t, fn) => listeners.set(t, fn),
  removeEventListener: (t) => listeners.delete(t),
};
globalThis.window = { setInterval: (fn, ms) => { const t = setInterval(fn, ms); t.unref(); return t }, clearInterval };
const { setVisibleInterval } = await import('../studio-web/src/utils/visibleInterval.ts');

const flip = (hidden) => { document.hidden = hidden; listeners.get('visibilitychange')?.(); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

test('no ticks while hidden; an immediate refresh on return, then ticking again', async () => {
  let n = 0;
  const stop = setVisibleInterval(() => { n++ }, 20);
  await sleep(70);
  assert.ok(n >= 2, `ticked ${n} times while visible`);
  flip(true);
  const atHide = n;
  await sleep(80);
  assert.equal(n, atHide, 'ticked while hidden');
  flip(false);
  assert.equal(n, atHide + 1, 'no immediate refresh on return');
  await sleep(70);
  assert.ok(n >= atHide + 3, 'did not resume');
  stop();
  const atStop = n;
  await sleep(50);
  assert.equal(n, atStop, 'ticked after cleanup');
  assert.equal(listeners.has('visibilitychange'), false);
});

test('started while hidden: nothing until shown', async () => {
  document.hidden = true;
  let n = 0;
  const stop = setVisibleInterval(() => { n++ }, 10);
  await sleep(40);
  assert.equal(n, 0);
  flip(false);
  assert.equal(n, 1);
  stop();
});

test('the dashboard no longer re-fetches live versions it never shows', () => {
  const dash = readFileSync(new URL('../studio-web/src/pages/Dashboard.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(dash, /live-version/);
});

test('the Requests badge reads a count, not the full list', () => {
  const layout = readFileSync(new URL('../studio-web/src/components/Layout.tsx', import.meta.url), 'utf8');
  const effect = layout.slice(layout.indexOf('Open-requests counter'), layout.indexOf('const fetchWaiting'));
  assert.match(effect, /'\/api\/enhancements\/count'/);
  assert.match(effect, /'\/api\/enhancements\/owned\/count'/);
  assert.match(effect, /'\/api\/enhancements\/my\/count'/);
  assert.doesNotMatch(effect, /requests: \{ status/);
});

test('background polls in the admin UI go through setVisibleInterval', () => {
  // Left on a bare timer on purpose: local clocks, a popup watcher (the popup
  // hides this tab), short action-progress polls, the bounded catalogue
  // refresh, and the self-update wait the admin started.
  const ALLOWED = new Set([
    'components/mfa/IdleSessionGuard.tsx', 'components/coder/CoderPanel.tsx', 'utils/popupSignIn.ts',
    'hooks/useAskSession.ts', 'components/BackupsCard.tsx', 'pages/Catalog.tsx', 'utils/visibleInterval.ts',
  ]);
  const root = fileURLToPath(new URL('../studio-web/src/', import.meta.url));
  const offenders = [];
  const walk = (dir) => {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) { walk(p); continue; }
      if (!/\.tsx?$/.test(f)) continue;
      const rel = p.slice(root.length);
      if (ALLOWED.has(rel)) continue;
      const src = readFileSync(p, 'utf8').replace(/setVisibleInterval/g, '');
      if (/\bsetInterval\(/.test(src)) offenders.push(rel);
    }
  };
  walk(root);
  assert.deepEqual(offenders.sort(), ['components/Layout.tsx', 'pages/AppManager.tsx']);
});
