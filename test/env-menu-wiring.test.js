import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Right-click on a topbar environment pill offers Promote to Production
// (sandbox only) and Redeploy (either). The rules that matter are not visual:
//
//  1. The server's promote gate is `isAdmin(user) || roleForUserOnApp(app) ===
//     'owner'` (routes/deploy.js). The menu must mirror BOTH halves, or it
//     either hides an action a platform admin is allowed to take, or offers an
//     app admin one that will 403.
//  2. The custom element must not decide who sees a menu — it cannot know — so
//     it reports the gesture and suppresses the browser's own context menu only
//     when the host says it rendered something.
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('the topbar reports a right-click on an env pill and cancels nothing on its own', () => {
  const src = read('studio-web/src/topbar-element/CraneAppTopbar.ts');
  assert.match(src, /addEventListener\('contextmenu'/, 'no contextmenu listener on the topbar');
  assert.match(src, /crane-env-menu/, "the contextmenu gesture is not emitted as 'crane-env-menu'");
  assert.match(
    src, /if \(handled\) e\.preventDefault\(\)/,
    'the element cancels the browser menu unconditionally — a viewer with no menu would get neither',
  );
  assert.match(
    src, /cancelable: true/,
    'emit() dispatches a non-cancelable event, so the host cannot signal that it handled it',
  );
});

test('both halves of the server promote rule gate the menu', () => {
  const src = read('studio-web/src/pages/AppFrame.tsx');
  assert.match(src, /isOwner: app\.app_role === 'owner'/, 'the owner half of the gate is gone');
  assert.match(src, /role === 'platform_admin'/, 'the platform-admin half of the gate is gone');
  assert.match(
    src, /stage\.isOwner \|\| platformAdmin/,
    'the menu renders without checking both halves of the rule deploy.js enforces',
  );
});

test('promote is offered on sandbox only, and both actions confirm first', () => {
  const src = read('studio-web/src/components/EnvActionMenu.tsx');
  assert.match(
    src, /state\.env === 'sandbox' &&/,
    'Promote to Production is not restricted to the sandbox pill — promoting production to itself is meaningless',
  );
  assert.match(src, /apps\/\$\{slug\}\/promote/, 'the promote endpoint is not called');
  assert.match(src, /apps\/\$\{slug\}\/deploy\/\$\{state\.env\}/, 'the redeploy endpoint is not called');
  for (const what of ['promote', 'redeploy']) {
    assert.ok(
      new RegExp(`confirming === '${what}'`).test(src),
      `${what} fires without a confirmation step, and it cannot be undone`,
    );
  }
});
