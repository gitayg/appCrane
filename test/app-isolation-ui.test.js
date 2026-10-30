import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// App isolation, dashboard side. With isolation on, each app answers on its own
// host and the platform host only redirects /<slug>; every place the dashboard
// hands a browser an app address must take it from the API's url / sandbox_url
// (falling back to the path for an older server), and the point-and-click
// picker, which cannot see into an app on another host, must still open the
// Request / coder flow instead of dead-ending.

const { appOpenUrl } = await import('../studio-web/src/lib/appLinks.ts');

const read = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');

test('appOpenUrl prefers the server-sent address and falls back to the path', () => {
  const iso = { slug: 'hub', url: 'https://hub.apps.example.com/', sandbox_url: 'https://hub-sandbox.apps.example.com/' };
  assert.equal(appOpenUrl(iso, 'production'), 'https://hub.apps.example.com/');
  assert.equal(appOpenUrl(iso, 'sandbox'), 'https://hub-sandbox.apps.example.com/');
  assert.equal(appOpenUrl({ slug: 'hub' }, 'production'), '/hub');
  assert.equal(appOpenUrl({ slug: 'hub' }, 'sandbox'), '/hub-sandbox');
  assert.equal(appOpenUrl({ slug: 'hub', url: '/hub', sandbox_url: '/hub-sandbox' }, 'sandbox'), '/hub-sandbox');
});

test('no app-opening site builds /<slug> or /<slug>-sandbox itself', () => {
  for (const f of ['pages/AppFrame.tsx', 'pages/Applications.tsx', 'components/AppPicker.tsx']) {
    const src = read(f);
    assert.ok(src.includes('appOpenUrl('), `${f} must open apps through appOpenUrl`);
    assert.doesNotMatch(src, /`\/\$\{(app|a)\.slug\}(-sandbox)?`/, `${f} still builds an app path by hand`);
  }
});

test('the picker tries the app host first, and hands back the whole page when that fails', () => {
  const src = read('hooks/usePeek.tsx');
  const start = src.indexOf('const start = useCallback');
  const body = src.slice(start, src.indexOf('const STYLE_ID', start));
  assert.match(body, /if \(!startOnAppHost\(iframe\)\) setCtx\(wholePage\(iframe\)\)/);
  assert.match(src, /function wholePage\(iframe: HTMLIFrameElement\): PeekCtx \{\s*return \{ selector: '', tag: '', id: '', text: '', path: iframe\.src \}/);
  assert.doesNotMatch(body, /alert\(/, 'a cross-address app must not dead-end in an alert');
  assert.match(src, /if \(!ctx\.selector\) return `--- Page ---/);
});

test('settings has an App isolation card that reads and saves through /api/settings/isolation', () => {
  // The generic PUT /api/settings/:key refuses these keys: they are validated
  // as a set (domain, certificate pair) by the dedicated endpoint.
  const card = read('components/AppIsolationCard.tsx');
  assert.match(card, /adminApi\.get<Isolation>\('\/api\/settings\/isolation'\)/);
  assert.match(card, /adminApi\.put<Isolation>\('\/api\/settings\/isolation', \{\s*domain: domain\.trim\(\), tls_cert_file: certFile\.trim\(\), tls_key_file: keyFile\.trim\(\)/);
  assert.doesNotMatch(card, /\/api\/settings\/\$\{/, 'per-key saves are refused by the server');
  assert.match(card, /r\?\.warning/, 'a save warning must be shown');
  assert.match(card, /sign in again once/);
  assert.match(card, /wildcard DNS record/);
  assert.ok(read('pages/Settings.tsx').includes('<AppIsolationCard />'));
});

test('UI copy stays in plain language', () => {
  const card = read('components/AppIsolationCard.tsx');
  const text = card.slice(card.indexOf('return ('));
  assert.doesNotMatch(text, /\borigin\b|CSRF|cookie/i);
  assert.doesNotMatch(read('hooks/usePeek.tsx').match(/WHOLE_PAGE_LABEL = '([^\n]*)'/)[1], /origin/i);
});

test('custom domain row carries the sign-in toggle bound to custom_domain_auth', () => {
  const src = read('pages/Applications.tsx');
  assert.match(src, /custom_domain_auth: on \? 1 : 0/);
  assert.match(src, /checked=\{!!app\.custom_domain_auth\}/);
  assert.ok(src.includes('Require AppCrane sign-in on the custom domain'));
});
