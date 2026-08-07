import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'fs';
// (readdirSync is used by servedHtml below to enumerate the static trees.)
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

// Walk every HTML file the static routes can serve. Enumerating rather than
// listing: `app.use('/docs', express.static(...))` and `/public` serve whatever
// is in those trees, so a hardcoded pair of paths silently misses the rest —
// which it did on the first pass (2 files checked, 15 actually served).
function servedHtml(dir, acc = []) {
  const full = join(ROOT, dir);
  if (!existsSync(full)) return acc;
  for (const entry of readdirSync(full, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const rel = join(dir, entry.name);
    if (entry.isDirectory()) servedHtml(rel, acc);
    else if (entry.name.endsWith('.html')) acc.push(rel);
  }
  return acc;
}

const ALL_HTML = [...servedHtml('docs'), ...servedHtml('public')];

// Everything under docs/ EXCEPT the built SPA shell is a pre-SPA page served
// with LEGACY_HTML_CSP, so inline script there is expected and allowed. The
// hardened policy governs the SPA shell and anything under public/.
const isLegacy = (p) => p.startsWith('docs') && !p.includes('admin-app');
const HARDENED_HTML = ALL_HTML.filter(p => !isLegacy(p));

test('every served HTML file is discovered, not assumed', () => {
  assert.ok(ALL_HTML.length >= 3, `expected the static trees to hold HTML, found ${ALL_HTML.length}`);
  assert.ok(ALL_HTML.some(p => p.endsWith('admin-app/index.html')), 'SPA shell not found');
});

test('no page under the hardened policy contains inline script', () => {
  const offenders = [];
  for (const rel of HARDENED_HTML) {
    const html = readFileSync(join(ROOT, rel), 'utf8');
    for (const tag of html.match(/<script\b[^>]*>/gi) || []) {
      if (!/\ssrc=/i.test(tag)) offenders.push(`${rel}: ${tag.slice(0, 80)}`);
    }
  }
  assert.deepEqual(offenders, [],
    `inline <script> will be blocked by script-src 'self' and blank these pages:\n${offenders.join('\n')}`);
});

test('no page under the hardened policy uses inline event handlers or javascript: URLs', () => {
  // on*= attributes and javascript: URLs both require 'unsafe-inline'.
  const offenders = [];
  for (const rel of HARDENED_HTML) {
    const html = readFileSync(join(ROOT, rel), 'utf8');
    const handlers = html.match(/\son(?:click|load|error|submit|change|input|keyup|keydown|mouseover|focus|blur)\s*=/gi) || [];
    if (handlers.length) offenders.push(`${rel}: ${handlers.length} inline handler(s) e.g. ${handlers[0].trim()}`);
    if (/(?:href|src)\s*=\s*["']javascript:/i.test(html)) offenders.push(`${rel}: javascript: URL`);
  }
  assert.deepEqual(offenders, [],
    `these require 'unsafe-inline' and will silently stop working:\n${offenders.join('\n')}`);
});

test('legacy pages with inline script are carved out, not left to break', () => {
  // v2.36.0 shipped a carve-out covering only login.html, which would have
  // blanked the other nine pre-SPA pages. If any legacy page still carries
  // inline script, the carve-out must exist and both serving paths must use it.
  const stillInline = ALL_HTML.filter(isLegacy).some(rel => {
    const html = readFileSync(join(ROOT, rel), 'utf8');
    return (html.match(/<script\b[^>]*>/gi) || []).some(t => !/\ssrc=/i.test(t));
  });
  if (!stillInline) return;   // legacy pages cleaned up or deleted — carve-out unneeded

  assert.match(SRC, /const LEGACY_HTML_CSP =/, 'legacy pages have inline script but no legacy policy');
  // The static route must allowlist the SPA shell rather than denylist filenames,
  // so a legacy page added later fails safe instead of blanking in production.
  assert.match(SRC, /isSpaShell \? HTML_CSP : LEGACY_HTML_CSP/,
    'static /docs route must serve non-SPA HTML with the legacy policy');
  assert.match(SRC, /applyEmbedHeaders\(req, res, LEGACY_HTML_CSP\)/,
    'the embed path must serve login.html with the legacy policy');
});
