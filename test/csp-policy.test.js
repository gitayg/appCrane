import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// CSP hardening (v2.36.0). A WAS scan flagged "Permissive Content Security
// Policy": script-src carried 'unsafe-inline', which leaves a CSP with almost
// no XSS value — injected markup executes as readily as first-party code.
//
// Removing it is only safe while nothing the policy covers uses inline script.
// These tests enforce BOTH halves: the policy stays hardened, and the pages it
// covers stay free of inline script. Adding an inline <script> to the SPA
// should fail here loudly, not silently blank the app in production.

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const SRC = readFileSync(join(ROOT, 'server/index.js'), 'utf8');

const HTML_CSP = SRC.match(/^const HTML_CSP = "(.+)";$/m)?.[1];

test('script-src does not allow unsafe-inline', () => {
  assert.ok(HTML_CSP, 'could not locate HTML_CSP');
  const scriptSrc = HTML_CSP.split(';').find(d => d.trim().startsWith('script-src'));
  assert.ok(scriptSrc, 'no script-src directive');
  assert.ok(!scriptSrc.includes('unsafe-inline'),
    `script-src must not allow unsafe-inline — got: ${scriptSrc.trim()}`);
  assert.ok(!scriptSrc.includes('unsafe-eval'), 'script-src must not allow unsafe-eval');
});

test('the directives that actually contain damage are still present', () => {
  for (const d of ["default-src 'self'", "object-src 'none'", "base-uri 'self'"]) {
    assert.ok(HTML_CSP.includes(d), `CSP lost ${d}`);
  }
});

test('style-src keeps unsafe-inline on purpose', () => {
  // React `style={{…}}` is used throughout; dropping this breaks the UI, and
  // inline styles carry a fraction of the risk of inline scripts. Documenting
  // the choice so it reads as deliberate rather than overlooked.
  const styleSrc = HTML_CSP.split(';').find(d => d.trim().startsWith('style-src'));
  assert.ok(styleSrc.includes('unsafe-inline'));
});

test('no page served under the hardened policy contains inline script', () => {
  // The admin SPA shell plus any other HTML the static /docs route serves.
  const pages = [join(ROOT, 'docs/admin-app/index.html'), join(ROOT, 'public/raiseme.html')]
    .filter(existsSync);
  assert.ok(pages.length > 0, 'expected at least the SPA shell');

  for (const page of pages) {
    const html = readFileSync(page, 'utf8');
    // <script> with no src= is an inline block.
    for (const tag of html.match(/<script\b[^>]*>/gi) || []) {
      assert.match(tag, /\ssrc=/i,
        `${page} has an inline <script> — it will be blocked by the hardened CSP: ${tag}`);
    }
    // Inline event handlers need 'unsafe-inline' too.
    assert.ok(!/\son(click|load|error|submit|change)\s*=/i.test(html),
      `${page} has an inline event handler, which the hardened CSP blocks`);
  }
});

test('login.html — the one page with inline script — gets the legacy policy', () => {
  const login = join(ROOT, 'docs/login.html');
  if (!existsSync(login)) return;                     // deleted? then nothing to carve out
  const html = readFileSync(login, 'utf8');
  const hasInline = (html.match(/<script\b[^>]*>/gi) || []).some(t => !/\ssrc=/i.test(t));
  if (!hasInline) return;                             // cleaned up — carve-out no longer needed

  assert.match(SRC, /const LEGACY_LOGIN_CSP =/, 'login.html has inline script but no legacy policy');
  assert.match(SRC, /applyEmbedHeaders\(req, res, LEGACY_LOGIN_CSP\)/,
    'the embed path must serve login.html with the legacy policy');
  assert.match(SRC, /filePath\.endsWith\('login\.html'\) \? LEGACY_LOGIN_CSP/,
    'the static /docs route must serve login.html with the legacy policy');
});
