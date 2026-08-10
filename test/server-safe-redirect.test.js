import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { isSafeRedirect, safeRedirectTarget } from '../server/utils/safeRedirect.js';

// Server half of the CWE-601 open redirect proven by a credentialed WAS scan.
// The scanner's payloads arrive percent-encoded on the wire, but Express decodes
// `req.query` before the route ever sees it — so every case below is asserted
// against the DECODED value, which is what `safeRedirectTarget` actually gets.
//
// Each payload is also resolved with the WHATWG URL parser against a same-origin
// base, so the test proves the value really is cross-origin rather than merely
// asserting a boolean. That is the whole point of the finding: these all *look*
// like local paths.

const __dirname = dirname(fileURLToPath(import.meta.url));
const BASE = 'https://app.example.com';
const EVIL_ORIGIN = 'https://evil.example';

const ROOT = join(__dirname, '..');
const CLIENT_SRC = readFileSync(join(ROOT, 'studio-web/src/utils/safeRedirect.ts'), 'utf8');

// Drop whole-line comments before asserting about route source. Both callbacks
// carry a comment that quotes the old `startsWith('http')` gate verbatim, so a
// guard run against the raw text would either trip on the prose or be satisfied
// by a call that is commented out. Only full-line comments are removed —
// stripping trailing `//` would truncate any line holding an 'http://' literal.
function stripFullLineComments(text) {
  return text
    .split('\n')
    .filter(line => !/^\s*(\/\/|\/\*|\*)/.test(line))
    .join('\n');
}

function codeOf(path) {
  return stripFullLineComments(readFileSync(join(ROOT, path), 'utf8'));
}

const OIDC_SRC = codeOf('server/routes/oidc.js');
const SAML_SRC = codeOf('server/routes/saml.js');

test('codeOf strips prose but keeps code', () => {
  // Proves codeOf() is doing real work, so the source guards below are not
  // vacuously passing. Asserted against a fixture rather than against the route
  // files: pinning this to a real comment would make CI fail on a reworded
  // comment — a guard that trips on a legitimate edit is as bad as one that
  // never trips at all.
  const fixture = [
    "// if (x.startsWith('http')) forward(x);",
    ' * startsWith(\'http\')',
    "  if (target.startsWith('http')) drop();",
    "  fetch('http://example.test');",
  ].join('\n');
  const stripped = stripFullLineComments(fixture);
  assert.doesNotMatch(stripped, /forward\(x\)/, 'a commented-out call survived the strip');
  assert.match(stripped, /if \(target\.startsWith\('http'\)\) drop\(\);/, 'real code was stripped');
  assert.match(stripped, /http:\/\/example\.test/, 'an http:// literal was truncated');
});

// ---------------------------------------------------------------------------
// The client validator, compiled from its real source.
//
// `studio-web/src/utils/safeRedirect.ts` is TypeScript, so `node --test` cannot
// import it. Rather than hand-copy the rule (a stale copy that silently passes
// is exactly how the original finding survived three call sites), lift the
// function body straight out of the .ts and compile it. If the client rule
// changes and the server's does not, the parity test below fails CI.
//
// The `new Function` input is a checked-in file in this repo, not request data;
// nothing is interpolated into it.
// ---------------------------------------------------------------------------
const CLIENT_BODY = CLIENT_SRC.match(
  /export function isSafeRedirect\([^)]*\)\s*:\s*boolean\s*\{([\s\S]*?)\n\}/,
);

test('the client validator can still be extracted from its source', () => {
  assert.ok(
    CLIENT_BODY,
    'could not find isSafeRedirect in studio-web/src/utils/safeRedirect.ts — ' +
      'the parity test below would silently test nothing',
  );
});

const clientIsSafeRedirect = new Function('value', CLIENT_BODY[1]);

// ---------------------------------------------------------------------------
// One shared table drives both validators. Every case lists the value as the
// route receives it (post-decode) and whether it must be accepted.
// ---------------------------------------------------------------------------
const CASES = [
  // Legitimate same-origin deep links.
  { value: '/launch', safe: true },
  { value: '/apps/foo?x=1#hash', safe: true },
  { value: '/dashboard', safe: true },
  { value: '/', safe: true },
  { value: '/launch/my-app', safe: true },

  // Protocol-relative and backslash variants — absolute addresses that begin
  // with a slash, which is why `startsWith('/')` was never a same-origin test.
  { value: '//evil.example', safe: false },
  { value: '///evil.example', safe: false },
  { value: '/\\evil.example', safe: false },
  { value: '//', safe: false },
  { value: '/\\', safe: false },

  // Control characters: browsers strip TAB/CR/LF before parsing a URL, so these
  // resolve cross-origin, and they can also split a Location header.
  { value: '/\t/evil.example', safe: false },
  { value: '/\r\n/evil.example', safe: false },
  { value: '/ok\x00', safe: false },
  { value: '/ok\x7f', safe: false },

  // Absolute URLs and schemes.
  { value: 'https://evil.example', safe: false },
  { value: 'http://evil.example', safe: false },
  { value: 'javascript:alert(1)', safe: false },
  { value: 'data:text/html,<script>alert(1)</script>', safe: false },
  { value: 'evil.example', safe: false },

  // Absent / empty means "no deep link", not "safe".
  { value: '', safe: false },
  { value: null, safe: false },
  { value: undefined, safe: false },
];

// ---------------------------------------------------------------------------
// The scanner's payloads, as they appear on the wire.
// ---------------------------------------------------------------------------
const SCANNER_PAYLOADS = [
  '//evil.example',
  '/%5cevil.example',
  '/%09/evil.example',
  '/%2f%2fevil.example',
  '/%0d%0a/evil.example',
  '/\\evil.example', // literal backslash, no encoding
  '/\t/evil.example', // literal TAB, no encoding
];

// Mirrors Express's decoding of req.query.
function fromQuery(raw) {
  return new URLSearchParams('redirect=' + raw).get('redirect');
}

test('scanner payloads are cross-origin once resolved, and are rejected', () => {
  for (const raw of SCANNER_PAYLOADS) {
    const decoded = fromQuery(raw);

    // Prove the payload is dangerous before asserting it is refused: resolved
    // against our own origin it still lands on the attacker's host.
    assert.equal(
      new URL(decoded, BASE).origin,
      EVIL_ORIGIN,
      `${JSON.stringify(raw)} was expected to resolve cross-origin`,
    );

    assert.equal(
      isSafeRedirect(decoded),
      false,
      `server accepted ${JSON.stringify(raw)} (decoded ${JSON.stringify(decoded)})`,
    );
    assert.equal(
      safeRedirectTarget(decoded, ''),
      '',
      `server forwarded ${JSON.stringify(raw)} instead of falling back`,
    );
  }
});

test('legitimate relative targets are accepted and stay same-origin', () => {
  for (const good of ['/launch', '/apps/foo?x=1#hash', '/dashboard']) {
    assert.equal(new URL(good, BASE).origin, BASE, `${good} should be same-origin`);
    assert.equal(isSafeRedirect(good), true, `server rejected ${good}`);
    assert.equal(safeRedirectTarget(good, ''), good, `server dropped ${good}`);
  }
});

test('absolute URLs and scheme-bearing targets are rejected', () => {
  for (const bad of [
    'https://evil.example',
    'http://evil.example',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '//evil',
  ]) {
    // Not same-origin: either the attacker's host, or an opaque origin ("null")
    // for the scheme payloads. Both are a redirect off our site.
    assert.notEqual(
      new URL(bad, BASE).origin,
      BASE,
      `${JSON.stringify(bad)} was expected to leave our origin`,
    );
    assert.equal(isSafeRedirect(bad), false, `server accepted ${JSON.stringify(bad)}`);
  }
});

test('server and client validators agree on every case', () => {
  // The scanner payloads are folded in as decoded rather than re-listed, so the
  // parity table cannot drift away from the payloads that proved the finding.
  const all = [...CASES, ...SCANNER_PAYLOADS.map(raw => ({ value: fromQuery(raw), safe: false }))];
  for (const { value, safe } of all) {
    assert.equal(
      isSafeRedirect(value),
      safe,
      `server disagreed on ${JSON.stringify(value)}`,
    );
    assert.equal(
      clientIsSafeRedirect(value),
      safe,
      `studio-web/src/utils/safeRedirect.ts disagreed on ${JSON.stringify(value)} — ` +
        'the two copies of this rule have drifted',
    );
  }
});

test('non-string request shapes are rejected (server-only concern)', () => {
  // `?redirect=a&redirect=b` gives Express an array and bracket notation gives
  // it an object. The client is typed; the server is not.
  for (const bad of [['/a', '/b'], { '0': '/a' }, 0, 1, true, {}]) {
    assert.equal(isSafeRedirect(bad), false, `server accepted ${JSON.stringify(bad)}`);
    assert.equal(safeRedirectTarget(bad, ''), '', `server forwarded ${JSON.stringify(bad)}`);
  }
});

test('safeRedirectTarget falls back rather than throwing', () => {
  assert.equal(safeRedirectTarget('//evil.example', ''), '');
  assert.equal(safeRedirectTarget(undefined, '/launch'), '/launch');
  assert.equal(safeRedirectTarget('//evil.example'), '/launch', 'default fallback is /launch');
  assert.equal(safeRedirectTarget('/apps/foo'), '/apps/foo');
});

// ---------------------------------------------------------------------------
// Regression guard for the functional half of the bug.
//
// Both callbacks used to gate the forward on `startsWith('http')` — an inverted
// filter that asked for an absolute URL where a same-origin path belongs. On the
// OIDC side /start could not produce such a value, so the deep link was always
// dropped and every SSO login landed on the default page. On the SAML side
// RelayState is browser-POSTed, so the gate did the opposite: it forwarded the
// cross-origin values and dropped the safe ones. Either way it masked the
// missing validation. Restoring the forward is only safe with the validator
// above, so these two must move together.
// ---------------------------------------------------------------------------
for (const [name, src] of [['oidc', OIDC_SRC], ['saml', SAML_SRC]]) {
  test(`${name} callback no longer gates the forward on startsWith('http')`, () => {
    assert.doesNotMatch(
      src,
      /\.startsWith\(\s*['"]http['"]\s*\)/,
      `server/routes/${name}.js still gates the redirect on startsWith('http') — ` +
        'SSO deep links are silently dropped',
    );
    assert.match(
      src,
      /safeRedirectTarget/,
      `server/routes/${name}.js does not use the shared validator`,
    );
    assert.match(
      src,
      /p\.set\(\s*['"]redirect['"]/,
      `server/routes/${name}.js never forwards a validated redirect target`,
    );
  });
}

test('oidc callback re-validates the redirect carried in state', () => {
  // `state` is HMAC-signed, but its payload round-trips through the IdP, so the
  // callback validates rather than trusting what /start stored.
  assert.match(OIDC_SRC, /safeRedirectTarget\(\s*stateData\.r\s*,\s*''\s*\)/);
  assert.match(OIDC_SRC, /const state = makeState\(safeRedirect\)/);
  assert.match(OIDC_SRC, /safeRedirectTarget\(\s*req\.query\.redirect\s*,\s*''\s*\)/);
});

test('saml callback validates RelayState independently of start', () => {
  // RelayState is browser-POSTed, sits outside the SAMLResponse signature, and
  // may never have passed through /start at all — so validating it at /start is
  // not sufficient. Both ends must validate.
  assert.match(
    SAML_SRC,
    /safeRedirectTarget\(\s*req\.body\.RelayState\s*,\s*''\s*\)/,
    'SAML callback does not validate the attacker-supplied RelayState',
  );
  assert.match(
    SAML_SRC,
    /safeRedirectTarget\(\s*req\.query\.redirect\s*,\s*''\s*\)/,
    'SAML start does not validate the redirect before it enters RelayState',
  );
});

// The callbacks cannot be invoked directly — OIDC needs a live IdP and SAML a
// signed assertion — so the forward is reproduced here from the same module the
// routes use. The source assertions above pin the routes to this exact shape;
// this test covers what that shape actually emits.
function forwardLocation(rawRedirect, base = BASE) {
  const target = safeRedirectTarget(rawRedirect, '');
  const p = new URLSearchParams({ oidc_token: 'tok' });
  if (target && !target.includes('/login')) {
    p.set('redirect', target);
  }
  return `${base}/login?${p.toString()}`;
}

test('an attacker-supplied RelayState never reaches the Location header', () => {
  for (const raw of SCANNER_PAYLOADS) {
    const location = forwardLocation(fromQuery(raw));
    const forwarded = new URL(location).searchParams.get('redirect');
    assert.equal(forwarded, null, `RelayState ${JSON.stringify(raw)} was forwarded`);
    // The victim ends up back on our own login page, not the attacker's host.
    assert.equal(new URL(location).origin, BASE);
  }
});

test('a validated deep link survives the callback forward', () => {
  // The functional half of the bug: this used to come back null for every
  // input, because the gate asked for a value /start could not produce.
  const location = forwardLocation('/apps/foo?x=1');
  assert.equal(new URL(location).searchParams.get('redirect'), '/apps/foo?x=1');
});

test('the forward refuses to loop back into the login page', () => {
  assert.equal(new URL(forwardLocation('/login')).searchParams.get('redirect'), null);
});

test('both callbacks refuse to bounce back into /login', () => {
  for (const [name, src] of [['oidc', OIDC_SRC], ['saml', SAML_SRC]]) {
    assert.match(
      src,
      /!\w+\.includes\(\s*['"]\/login['"]\s*\)/,
      `server/routes/${name}.js lost the /login loop guard`,
    );
  }
});
