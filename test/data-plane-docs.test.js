import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Documentation tests for the v2.45.0 data plane — `ingress_type: 'dual'`, the
// per-app `data_plane_port`, and the split between the AUTO allocation band and
// the wider range an operator may explicitly name.
//
// onboarding.md is served to agents by `appcrane_get_guide`, so for this feature
// the doc is part of the control surface, not a description of it. Three things
// in particular cannot be re-imposed by the runtime once the guide is wrong:
//
//   - The two port ranges. An operator opens ONE firewall block from the auto
//     band and a separate rule for anything named outside it. A guide that
//     conflates the bands either leaves a live app unreachable or has the
//     operator opening ports nothing uses.
//   - The 3000 refusal AND its reason. Without the reason a reader treats it as
//     an arbitrary bookkeeping rule and works around it — and the workaround is
//     publishing the HTTP control plane raw, which is the one outcome this
//     feature exists to prevent.
//   - What the data plane gives up. Nothing on that path runs forward_auth,
//     injects identity headers, terminates TLS or writes an audit entry, and the
//     only thing that tells an agent so is this section.
//
// Two rules this file holds itself to, same as test/tcp-ingress-docs.test.js:
//
//   1. Match on SUBSTANCE. Each detector pairs a subject regex with a polarity
//      regex that must hit the SAME statement, so a reworded claim still passes
//      and a reversed claim still fails.
//   2. Every detector is proven able to fail — against a near-miss that
//      describes the same feature with the claim wrong or missing, AND against
//      an empty document (the last test in this file). A doc test that passes on
//      an empty file is worthless.
//
// Both port ranges and the control-plane port are read from tcpIngress.js and
// exercised against the real allocator/validator, never typed here. Move a bound
// in code without moving it in the guide (or the reverse) and this goes red.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GUIDE_PATH = 'server/services/guides/onboarding.md';
const guide = readFileSync(join(ROOT, GUIDE_PATH), 'utf8');

const {
  AUTO_PORT_MIN,
  AUTO_PORT_MAX,
  PUBLIC_PORT_MIN,
  PUBLIC_PORT_MAX,
  CONTROL_PLANE_PORT,
  allocatePublicPort,
  assertPublicPortAssignable,
  validateDataPlanePort,
} = await import('../server/services/tcpIngress.js');

// ---------------------------------------------------------------------------
// Text helpers.
//
// Blockquote markers are stripped BEFORE anything else: the 3000 rationale is a
// `>` quote hard-wrapped over six lines, and treating each `>` line as its own
// block would sever the claim into halves that individually say nothing.
// Markdown emphasis and backticks are noise. Line structure still carries
// meaning in the opposite direction for tables — one claim per ROW — so rows,
// headings and list items each start a new block and are never joined.
// ---------------------------------------------------------------------------
const unquote = t => t.replace(/^[ \t]*>[ \t]?/gm, '');
const flat = t => unquote(t).replace(/[`*]/g, '').replace(/\s+/g, ' ');

// Fenced blocks are dropped before prose extraction. The dual-plane ASCII
// diagram is a fence containing both plane labels and the words "no Caddy", so
// left in it satisfies almost every loss detector below on its own — and a
// picture is not the statement those detectors are meant to require.
const deFence = t => t.replace(/^```[\s\S]*?^```/gm, '');

function unwrap(text) {
  const out = [];
  for (const raw of deFence(unquote(text)).split('\n')) {
    const line = raw.replace(/[`*]/g, '').replace(/\s+/g, ' ').trim();
    const prev = out[out.length - 1];
    const startsBlock = /^([-*+]\s|\d+\.\s|#|\|)/.test(line);
    if (line && prev && !startsBlock && !/^(#|\|)/.test(prev)) {
      out[out.length - 1] = `${prev} ${line}`;
    } else {
      out.push(line);
    }
  }
  return out.filter(Boolean);
}

function statements(text) {
  const out = [];
  for (const block of unwrap(text)) {
    for (const s of block.split(/(?<=[.;])\s+/)) {
      const t = s.trim();
      if (t) out.push(t);
    }
  }
  return out;
}

/** True when ONE statement satisfies every regex — subject and polarity together. */
function claims(text, ...res) {
  return statements(text).some(s => res.every(re => re.test(s)));
}

// Windows are cut from PROSE only — fenced blocks and table rows removed.
// Proximity is a weak signal and those two are dense: the dual-plane diagram
// sits three lines above the per-plane table, so any window spanning the pair
// contains "control plane", "Caddy", "no", TLS, forward_auth, identity headers,
// audit and rate limiting without a single sentence having claimed anything.
// That coincidence alone satisfied the 3000-rationale detector even after the
// rationale had been deleted from the guide.
const prose = t => unwrap(t).filter(b => !b.startsWith('|')).join(' ');

/** Every window of `radius` characters either side of a term occurrence. */
function windows(text, term, radius = 260) {
  const f = prose(text);
  const all = new RegExp(term.source, term.flags.includes('g') ? term.flags : `${term.flags}g`);
  const out = [];
  for (const m of f.matchAll(all)) {
    out.push(f.slice(Math.max(0, m.index - radius), m.index + radius));
  }
  return out;
}

/** True when some window around a term also carries every other regex. */
function nearby(text, term, ...res) {
  return windows(text, term).some(w => res.every(re => re.test(w)));
}

function section(text, headingRe) {
  const m = text.match(headingRe);
  return m ? m[0] : '';
}

// ---------------------------------------------------------------------------
// The per-plane comparison table, read as a table.
//
// Its rows are the authoritative statement of what each plane gets, and they
// carry that meaning positionally: the row "| ... | yes, all of it | none of it
// |" says nothing at all unless the third cell is known to be the data-plane
// column. Matching the row as one flat string let a `yes` from the control-plane
// column satisfy a check about the data plane — and worse, let a positive claim
// about the CONTROL plane elsewhere in the section ("SSO and identity headers
// work exactly as they do for an http app — dual does not weaken the existing
// door") satisfy a check that the DATA plane has none of them. Both were real:
// flipping every data-plane cell to "yes" left six of these tests green.
//
// So the column is located from the header row, and the polarity regex is
// tested against that cell alone.
// ---------------------------------------------------------------------------
function tableCells(line) {
  return line.replace(/^\||\|$/g, '').split('|').map(c => c.replace(/[`*]/g, '').trim());
}

function dataPlaneRows(text) {
  const out = [];
  let column = -1;
  let width = 0;
  for (const raw of deFence(unquote(text)).split('\n')) {
    const line = raw.trim();
    if (!line.startsWith('|')) continue;
    const cells = tableCells(line);
    if (cells.every(c => /^[:-]*$/.test(c))) continue;
    const header = cells.findIndex(c => /^data[- ]plane$/i.test(c));
    if (header > 0) {
      column = header;
      width = cells.length;
      continue;
    }
    if (column >= 0 && cells.length === width) out.push({ label: cells[0], cell: cells[column] });
  }
  return out;
}

/** True when a data-plane column cell answers `polarity` for a row `subject` names. */
function tableSays(text, subject, polarity) {
  return dataPlaneRows(text).some(({ label, cell }) => subject.test(`${label} ${cell}`) && polarity.test(cell));
}

const TCP_SECTION = section(guide, /^## [^\n]*tcp[^\n]*ingress[^\n]*$[\s\S]*?(?=^## )/im);
const DUAL_SECTION = section(TCP_SECTION, /^###\s+Dual-plane apps[\s\S]*?(?=^### )/im);

// The absence vocabulary. Deliberately wide — a table cell says "none of it", a
// sentence says "nothing injects them", a heading says "does not". All are the
// same claim; a doc that says "yes" matches none of them.
const ABSENT = /(\bno\b|\bnot\b|\bnone\b|\bnever\b|\bwithout\b|\bnothing\b|\bbypass|n\/a|does ?n[o']t|is ?n[o']t|are ?n[o']t)/i;

const REFUSED = /(may not|must not|cannot|can ?not|is refused|refused|rejected|reject|\b400\b|not allowed|never)/i;

/** `31000 through 31999`, `1024-65535`, `1024 to 65535` — same range, any prose. */
function rangeRe(lo, hi) {
  return new RegExp(String.raw`\b${lo}\b\s*(?:up to|through|to|\.\.|-|–|—)\s*\b${hi}\b`, 'i');
}
const AUTO_BAND_RE = rangeRe(AUTO_PORT_MIN, AUTO_PORT_MAX);
const WIDE_RANGE_RE = rangeRe(PUBLIC_PORT_MIN, PUBLIC_PORT_MAX);
const CONTROL_PORT_RE = new RegExp(String.raw`\b${CONTROL_PLANE_PORT}\b`);

// ---------------------------------------------------------------------------
// Detector registry. Every detector defined here is (a) run against the real
// guide, (b) run against a near-miss that must NOT satisfy it, and (c) run
// against an empty document by the final test in this file.
// ---------------------------------------------------------------------------
const DETECTORS = [];
function detector(name, fn) {
  DETECTORS.push({ name, fn });
  return fn;
}

const documentsAutoBand = detector('auto band', t =>
  claims(t, AUTO_BAND_RE, /allocat|auto|band|dedicated|lowest free|did ?n[o']t name/i));

const documentsWideRange = detector('explicit range', t =>
  claims(t, WIDE_RANGE_RE, /explicit|\bname\b|\bnames?\b|\bnamed\b|choose|\bpin\b|any port|anything/i));

const distinguishesRanges = detector('two ranges distinguished', t =>
  AUTO_BAND_RE.test(flat(t))
  && WIDE_RANGE_RE.test(flat(t))
  && claims(t, /(two different|not the same|never meant to be|conflat|distinct|two separate)/i,
    /(range|band|number|port)/i));

// Proximity is not enough here either: "container" and "publish" appear within a
// couple of sentences of nearly every data_plane_port mention in the section
// ("the publish has to target some container port", "the container is told
// PORT=3000 and the whole of it is published"), neither of which says which end
// of the publish data_plane_port is. The claim has to be in one statement, or in
// the comparison table's own "container port" row.
const DATA_PLANE_PORT_RE = /data[_ -]?plane[_ -]?port/i;
const documentsDataPlanePort = detector('data_plane_port is the container side', t =>
  tableSays(t, /container port/i, DATA_PLANE_PORT_RE)
  || claims(t, DATA_PLANE_PORT_RE, /container/i, /\bside\b|inside|targets?\b|maps? to/i));

const refuses3000 = detector('3000 is refused', t =>
  claims(t, /data[_ -]?plane[_ -]?port/i, CONTROL_PORT_RE, REFUSED)
  || nearby(t, /data[_ -]?plane[_ -]?port/gi, CONTROL_PORT_RE, REFUSED));

const CONTROL_LOSSES = [/\btls\b/i, /forward[_ -]?auth/i, /identity header/i, /\baudit\b/i, /rate[- ]limit/i];
const explains3000 = detector('3000 refusal has its security reason', t =>
  windows(t, CONTROL_PORT_RE, 320).some(w =>
    /control plane|caddy/i.test(w)
    && ABSENT.test(w)
    && CONTROL_LOSSES.filter(re => re.test(w)).length >= 3));

const DATA_PLANE_GIVES_UP = [
  ['the forward_auth SSO gate', /forward[_ -]?auth|sso|single sign[- ]on/i],
  ['X-AppCrane identity headers', /x-appcrane|identity header/i],
  ['per-request audit / access logging', /\baudit\b|access log|request log|logging/i],
  ['rate limiting', /rate[- ]limit/i],
  ['security headers', /security header|csp|x-frame-options|hsts/i],
  ['TLS terminated by AppCrane', /\btls\b|https|let'?s encrypt/i],
  ['being health-probed at all', /health/i],
];
// A prose claim only counts when the statement itself is about the data plane.
// "dual adds the raw door, it does not weaken the existing one" is a claim about
// the CONTROL plane and must not be mistaken for one.
const DATA_PLANE_SUBJECT = /data[- ]plane|published port|public_port|0\.0\.0\.0/i;

const givesUp = subject => t =>
  tableSays(t, subject, ABSENT) || claims(t, subject, ABSENT, DATA_PLANE_SUBJECT);

for (const [label, subject] of DATA_PLANE_GIVES_UP) {
  detector(`data plane gives up: ${label}`, givesUp(subject));
}

// In the table the answer to "who authenticates" is a cell, so naming the app is
// the whole claim. In prose it is not: "a flaw reachable through the
// unauthenticated data plane ... a handler that can read the app's database"
// names the app beside the word authenticate and says nothing about who does it.
// Prose therefore needs an ownership verb as well.
const APP_OWNS_CELL = /\bthe app\b|app owns|owned by the app/i;
const APP_OWNS_PROSE = /\b(the app|the application)\b[^.]{0,90}\b(owns?|is responsible for|must (handle|implement|do|provide)|has to (handle|implement|do)|entirely|alone)\b/i;
const appOwnsDataPlaneAuth = detector('the app owns data-plane authentication', t =>
  tableSays(t, /authenticat/i, APP_OWNS_CELL)
  || claims(t, /authenticat/i, APP_OWNS_PROSE, DATA_PLANE_SUBJECT));

// ---------------------------------------------------------------------------
// Near-miss documents. Each describes the same feature with one claim wrong or
// missing. These are what make the detectors above evidence rather than
// decoration.
// ---------------------------------------------------------------------------

// One number where there are two — the pre-v2.45.0 guide, still accurate about
// nothing except that ports exist.
const ONE_RANGE = `
- **Ports come from a dedicated range.** An allocated host port comes from
  **1024-65535**, lowest free first, so the operator's firewall rule is one
  predictable block instead of a per-app list.
`;

// The old, narrow band presented as the range an operator may name.
const STALE_BAND = `
- An *allocated* host port comes from a dedicated band, **30000 through 30999**,
  lowest free first. A host port you name **explicitly** may be anything in
  **31000-31999**.
`;

// Both numbers present, but nothing tells the reader they are different things —
// so a reader opens one firewall block and assumes it covers every case.
const BOTH_RANGES_NO_CONTRAST = `
- An *allocated* host port comes from a dedicated band, **${AUTO_PORT_MIN} through
  ${AUTO_PORT_MAX}**, lowest free first. A host port you name **explicitly** may be
  anything in **${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}**.
`;

// A dual section that keeps every Caddy control on the published port. This is
// the claim the whole loss list exists to contradict.
const CONTROLS_STILL_APPLY = `
### Dual-plane apps — one container, two doors

\`ingress_type: 'dual'\` publishes a second listener beside the control plane.

| | control plane | data plane |
|---|---|---|
| container port | \`3000\` | \`data_plane_port\`, chosen per app |
| host binding | \`127.0.0.1:<slot port>\` | \`0.0.0.0:<public_port>\` |
| Caddy in the path | yes | yes |
| forward_auth / SSO, identity headers, audit, rate limiting, security headers, TLS | yes, all of it | yes, all of it |
| who authenticates | AppCrane | AppCrane |
| what health checks probe | this one | this one too |

Caddy fronts both planes, so a dual app keeps every control on both doors.
`;

// True statements about the CONTROL plane, plus the diagram — all lifted from
// the real section. None of them says what the DATA plane gives up, and an
// earlier version of the loss detectors was satisfied by every one of them.
const CONTROL_PLANE_KEPT = `
\`\`\`
                  Caddy (TLS, forward_auth, identity headers, audit)
                    │
  {{HOST}}/<slug> ──┘──▶ 127.0.0.1:<slot port> ──▶ container:3000   ← CONTROL plane
  <host>:<public_port> ─────── raw, no Caddy ────▶ container:<data_plane_port>
                                                                    ← DATA plane
\`\`\`

The control plane is unchanged in every respect. A dual app's normal URL, SSO,
identity headers, audit, rate limiting, security headers and TLS work exactly as
they do for an \`http\` app — \`dual\` **adds** the raw door, it does not weaken the
one you already have, and it does not change what health checks probe.

It separates the *doors*, not the trust domains — a flaw reachable through the
unauthenticated data plane is reachable in the code that serves the control plane
too, and a data-plane handler that can read the app's database can read
everything the control plane could.
`;

// The refusal without its reason: reads as arbitrary bookkeeping, which is
// exactly the framing that gets it worked around.
const BOOKKEEPING_REASON = `
#### \`data_plane_port\` may not be 3000

Port 3000 is already used by the container's loopback publish, so the number is
taken. Pick a different one and the deploy will go through.
`;

// The refusal inverted: 3000 offered as a debugging convenience.
const GUARD_INVERTED = `
#### Publishing the control plane

Set \`data_plane_port\` to 3000 and the container's HTTP control plane is
published raw on the host as well — handy when you want to reach it directly.
`;

// data_plane_port named, but as a host-side number. A reader configures the
// wrong end of the publish.
const HOST_SIDE_CONFUSION = `
#### \`data_plane_port\`

Set \`data_plane_port\` to the port your clients are already configured for and
AppCrane will use it.
`;

// ---------------------------------------------------------------------------
// Guards. Every check below is meaningless if the sections did not load.
// ---------------------------------------------------------------------------
test('the ingress section and its dual-plane subsection both loaded', () => {
  assert.ok(TCP_SECTION.length > 1500, `no substantial ingress section in ${GUIDE_PATH}`);
  assert.ok(
    DUAL_SECTION.length > 800,
    `${GUIDE_PATH} has no substantial dual-plane subsection — every data-plane check below ` +
    'would pass vacuously against an empty string',
  );
  assert.match(DUAL_SECTION, /data_plane_port/);
});

// ---------------------------------------------------------------------------
// (1) The two ranges, both extracted from code and both exercised.
//
// AUTO_* and PUBLIC_PORT_* answer different questions and v2.45.0 pulled them
// apart. Importing the constants is not enough on its own — a constant nothing
// reads would agree with any doc — so each is exercised against the function
// that is supposed to enforce it before the doc is compared to it.
// ---------------------------------------------------------------------------
function stubDb(taken = new Set()) {
  return {
    prepare(sql) {
      return {
        all: () => [],
        get: (...args) => {
          if (/MAX\(slot\)/.test(sql)) return { max_slot: 0 };
          if (/public_port = \?/.test(sql)) return taken.has(args[0]) ? { slug: 'other-app' } : undefined;
          return undefined;
        },
      };
    },
  };
}

test('the auto band is strictly narrower than the assignable range', () => {
  // If these ever coincide there is only one range, and the guide would be right
  // to present one number — so the doc checks below would be wrong, not the doc.
  assert.ok(
    AUTO_PORT_MIN > PUBLIC_PORT_MIN || AUTO_PORT_MAX < PUBLIC_PORT_MAX,
    `AUTO ${AUTO_PORT_MIN}-${AUTO_PORT_MAX} is not narrower than PUBLIC ` +
    `${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}; the two-range documentation has nothing to describe`,
  );
});

test('allocatePublicPort really allocates from the AUTO band it exports', () => {
  assert.equal(
    allocatePublicPort(stubDb(), null), AUTO_PORT_MIN,
    'the first allocation did not land at AUTO_PORT_MIN — the exported band is not the allocated one',
  );

  const wholeBand = new Set();
  for (let p = AUTO_PORT_MIN; p <= AUTO_PORT_MAX; p++) wholeBand.add(p);
  assert.throws(
    () => allocatePublicPort(stubDb(wholeBand), null),
    e => e.code === 'NO_PUBLIC_PORT',
    'with the whole AUTO band taken the allocator still produced a port — it is not bounded by ' +
    'the band the guide tells operators to open in their firewall',
  );
});

test('assertPublicPortAssignable really enforces the wide range, not the band', () => {
  const db = stubDb();
  assert.equal(assertPublicPortAssignable(db, PUBLIC_PORT_MIN, null), PUBLIC_PORT_MIN);
  assert.equal(
    assertPublicPortAssignable(db, AUTO_PORT_MAX + 1, null), AUTO_PORT_MAX + 1,
    'a port just outside the auto band was refused — then the guide is wrong to tell an operator ' +
    'they may name one',
  );
  assert.throws(() => assertPublicPortAssignable(db, PUBLIC_PORT_MIN - 1, null), /between/i);
  assert.throws(() => assertPublicPortAssignable(db, PUBLIC_PORT_MAX + 1, null), /between/i);
});

test('onboarding.md documents the AUTO band the allocator hands out', () => {
  assert.ok(
    documentsAutoBand(TCP_SECTION),
    `${GUIDE_PATH} does not identify ${AUTO_PORT_MIN}-${AUTO_PORT_MAX} as the band an ALLOCATED ` +
    'port comes from. That band is the one predictable block an operator opens in the firewall; ' +
    'if it drifts from the allocator, allocated apps land outside the rule and are unreachable.',
  );
  assert.ok(!documentsAutoBand(STALE_BAND), 'the auto-band detector accepts a band the allocator does not use');
  assert.ok(!documentsAutoBand(ONE_RANGE), 'the auto-band detector passes on a doc with no auto band at all');
});

test('onboarding.md documents the range an operator may explicitly name', () => {
  assert.ok(
    documentsWideRange(TCP_SECTION),
    `${GUIDE_PATH} does not say an explicitly named port may be anything in ` +
    `${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}. Clients are configured with a port by hand or by MDM; ` +
    'a guide that still shows only the auto band tells an agent to refuse a legal request.',
  );
  assert.ok(
    !documentsWideRange(STALE_BAND),
    'the explicit-range detector accepts a range the validator does not enforce',
  );
});

test('onboarding.md distinguishes the two ranges rather than presenting one number', () => {
  assert.ok(
    distinguishesRanges(TCP_SECTION),
    `${GUIDE_PATH} shows the ranges but never says they are different things. Conflating them is ` +
    'the specific mistake v2.45.0 split them to prevent.',
  );
  assert.ok(!distinguishesRanges(ONE_RANGE), 'the two-range detector passes on a doc with a single range');
  assert.ok(
    !distinguishesRanges(BOTH_RANGES_NO_CONTRAST),
    'the two-range detector accepts a doc that prints both numbers without ever saying they ' +
    'answer different questions — which is the whole content of the claim',
  );
});

// ---------------------------------------------------------------------------
// (2) The data-plane port, the 3000 guard, and the reason for it.
// ---------------------------------------------------------------------------
test('validateDataPlanePort enforces the bounds and refuses the control-plane port', () => {
  assert.equal(validateDataPlanePort(PUBLIC_PORT_MIN), PUBLIC_PORT_MIN);
  assert.equal(validateDataPlanePort(PUBLIC_PORT_MAX), PUBLIC_PORT_MAX);
  assert.throws(() => validateDataPlanePort(PUBLIC_PORT_MIN - 1), /between/i);
  assert.throws(() => validateDataPlanePort(PUBLIC_PORT_MAX + 1), /between/i);
  assert.throws(
    () => validateDataPlanePort(CONTROL_PLANE_PORT),
    e => e.status === 400 && /control plane/i.test(e.message),
    `port ${CONTROL_PLANE_PORT} was accepted as a data-plane port, or refused without saying why. ` +
    'Publishing it puts the HTTP origin Caddy fronts on a public port with no TLS, no forward_auth, ' +
    'no identity headers and no audit.',
  );
});

test('onboarding.md documents data_plane_port as the CONTAINER side of the publish', () => {
  assert.ok(
    documentsDataPlanePort(DUAL_SECTION) || documentsDataPlanePort(TCP_SECTION),
    `${GUIDE_PATH} never ties data_plane_port to the container side of the publish. A reader who ` +
    'takes it for the host port configures the wrong end and gets a 409 or the wrong listener.',
  );
  assert.ok(
    !documentsDataPlanePort(HOST_SIDE_CONFUSION),
    'the container-side detector accepts a doc that describes data_plane_port as a host port',
  );
});

test(`onboarding.md says data_plane_port may not be ${CONTROL_PLANE_PORT}`, () => {
  assert.ok(
    refuses3000(DUAL_SECTION),
    `${GUIDE_PATH} does not state that ${CONTROL_PLANE_PORT} is refused as a data-plane port`,
  );
  assert.ok(
    !refuses3000(GUARD_INVERTED),
    `the refusal detector accepts a doc that offers ${CONTROL_PLANE_PORT} as a valid data-plane port`,
  );
});

test(`onboarding.md gives the SECURITY reason ${CONTROL_PLANE_PORT} is refused`, () => {
  assert.ok(
    explains3000(DUAL_SECTION),
    `${GUIDE_PATH} refuses ${CONTROL_PLANE_PORT} without saying that it is the control plane Caddy ` +
    'fronts and what publishing it would strip. A rule with no reason reads as bookkeeping, and the ' +
    'obvious workaround for bookkeeping is exactly the exposure the rule prevents.',
  );
  assert.ok(
    !explains3000(BOOKKEEPING_REASON),
    'the reason detector accepts a doc that explains the refusal as a port-numbering clash',
  );
  assert.ok(
    !explains3000(GUARD_INVERTED),
    'the reason detector accepts a doc that presents publishing the control plane as a feature',
  );
});

// ---------------------------------------------------------------------------
// (3) What the data plane gives up.
//
// Every control shipped in v2.35-v2.41 assumes Caddy is the only door. The
// dual-plane subsection is where an agent learns that the second door has none
// of them, and nothing in the runtime can re-impose them afterwards.
// ---------------------------------------------------------------------------
for (const [label, subject] of DATA_PLANE_GIVES_UP) {
  test(`onboarding.md states the data plane gives up: ${label}`, () => {
    assert.ok(
      givesUp(subject)(DUAL_SECTION),
      `the dual-plane section of ${GUIDE_PATH} never says, in one statement, that a dual app's ` +
      `data plane does not get ${label}. An agent reading it will assume Caddy is still in front ` +
      'of the published port, because for every other kind of app it is.',
    );
    assert.ok(
      !givesUp(subject)(CONTROLS_STILL_APPLY),
      `the detector for "${label}" also matches a doc claiming the control STILL applies to the ` +
      'data plane — it is matching the topic, not the claim',
    );
    assert.ok(
      !givesUp(subject)(CONTROL_PLANE_KEPT),
      `the detector for "${label}" is satisfied by a positive claim about the CONTROL plane — ` +
      'it is matching the section, not the plane',
    );
  });
}

test('onboarding.md states the app itself authenticates the data plane', () => {
  assert.ok(
    appOwnsDataPlaneAuth(DUAL_SECTION),
    `the dual-plane section of ${GUIDE_PATH} never says the app owns authentication on the data ` +
    'plane. Nothing else does — if the app skips it, the door is open.',
  );
  assert.ok(
    !appOwnsDataPlaneAuth(CONTROLS_STILL_APPLY),
    'the ownership detector accepts a doc that says AppCrane keeps authenticating the data plane',
  );
  assert.ok(
    !appOwnsDataPlaneAuth(CONTROL_PLANE_KEPT),
    'the ownership detector is satisfied by the trust-domain paragraph, which mentions an ' +
    'unauthenticated data plane and "the app\'s database" without ever saying who authenticates',
  );
});

// ---------------------------------------------------------------------------
// (4) Vacuity guard for the whole file.
//
// A near-miss per detector proves polarity. This proves presence: a detector
// that matched an empty document would be asserting nothing at all, and the two
// failure modes are independent — a regex can be polarity-sensitive and still
// match a document that says nothing.
// ---------------------------------------------------------------------------
test('no detector in this file matches an empty document', () => {
  const vacuous = DETECTORS.filter(({ fn }) => fn('')).map(({ name }) => name);
  assert.deepEqual(
    vacuous, [],
    `these detectors are satisfied by an empty guide and therefore assert nothing: ${vacuous.join(', ')}`,
  );
});
