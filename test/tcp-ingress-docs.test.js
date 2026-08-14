import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Documentation tests for TCP (layer-4) ingress — v2.42.0.
//
// onboarding.md is not prose decoration: appcrane_get_guide serves it to the AI
// agents that write the apps, so a wrong sentence there becomes a wrong app.
// For this feature specifically, the doc IS part of the control. A published
// port has no forward_auth, no identity headers, no per-request audit, no rate
// limiting, no security headers and no TLS from AppCrane — every control shipped
// in v2.35-v2.41 assumes Caddy is the only door. Nothing in the runtime can
// re-impose them, so the only defence against an agent reaching for `tcp`
// because it "sounds like headless" is the guide saying, plainly, what it costs.
//
// Two rules this file holds itself to:
//
//   1. Match on SUBSTANCE, not phrasing. Each check is a subject regex AND a
//      polarity regex that must hit the SAME statement, so a reworded
//      restatement still passes and a reversed claim still fails.
//   2. Every detector is proven able to fail. Each one runs against a near-miss
//      text that describes the same feature with the claim wrong or missing, and
//      must NOT match it. A doc test that passes against an empty file is
//      worthless.
//
// The port range is checked against the ALLOCATOR, not against a number typed
// here: the range is read from tcpIngress.js, the enforcement is exercised, and
// the doc has to agree with both. Docs drifting from code is a recurring defect
// in this repo and nothing caught it before.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GUIDE_PATH = 'server/services/guides/onboarding.md';
const BACKLOG_PATH = 'BACKLOG.md';

const guide = readFileSync(join(ROOT, GUIDE_PATH), 'utf8');
const backlogPath = join(ROOT, BACKLOG_PATH);
const backlog = existsSync(backlogPath) ? readFileSync(backlogPath, 'utf8') : null;

const { PUBLIC_PORT_MIN, PUBLIC_PORT_MAX, assertPublicPortAssignable } =
  await import('../server/services/tcpIngress.js');

// ---------------------------------------------------------------------------
// Statement extraction. Markdown emphasis and backticks are noise for matching,
// but line structure carries meaning here in two opposite directions:
//
//   - The loss table is one claim per ROW ("| forward_auth SSO gate | yes | no |").
//     Joining rows would let a `yes` from the http column satisfy a check about
//     the tcp column, so rows, headings and list items each start a new block.
//   - Prose is hard-wrapped at ~80 columns, so a single claim is split across
//     lines mid-sentence ("so the app owns\nauthentication completely"). Matching
//     per raw line would silently miss it — the failure mode that produced this
//     comment. Continuation lines are rejoined first.
//
// Only then split on sentence ends — never on ':' or '|', which would sever a
// claim into two harmless halves.
// ---------------------------------------------------------------------------
function unwrap(text) {
  const out = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/[`*]/g, '').replace(/\s+/g, ' ').trim();
    const prev = out[out.length - 1];
    const startsBlock = /^([-*+]\s|\d+\.\s|#|\||>)/.test(line);
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

/** True when one statement satisfies every regex — subject and polarity together. */
function claims(text, ...res) {
  return statements(text).some(s => res.every(re => re.test(s)));
}

/** True when some window around a term also carries the other required regexes. */
function nearby(text, term, ...res) {
  const flat = text.replace(/[`*]/g, '').replace(/\s+/g, ' ');
  const all = new RegExp(term.source, term.flags.includes('g') ? term.flags : term.flags + 'g');
  for (const m of flat.matchAll(all)) {
    const w = flat.slice(Math.max(0, m.index - 220), m.index + 220);
    if (res.every(re => re.test(w))) return true;
  }
  return false;
}

function section(text, headingRe) {
  const m = text.match(headingRe);
  return m ? m[0] : '';
}

const TCP_SECTION = section(guide, /^## [^\n]*tcp[^\n]*ingress[^\n]*$[\s\S]*?(?=^## )/im);

// The absence vocabulary. Deliberately wide — a table cell says "no", a
// sentence says "nothing injects them", a heading says "does not". All three
// are the same claim, and a doc that says "yes" matches none of them.
const ABSENT = /(\bno\b|\bnot\b|\bnone\b|\bnever\b|\bwithout\b|\bnothing\b|\babsent\b|\bbypass|n\/a|does ?n[o']t|is ?n[o']t|are ?n[o']t)/i;

test('the TCP ingress section exists and loaded (guards every check below)', () => {
  assert.ok(TCP_SECTION.length > 1500, `no substantial TCP ingress section in ${GUIDE_PATH}`);
  assert.match(TCP_SECTION, /\btcp\b/i);
  assert.match(TCP_SECTION, /ingress_type/);
});

// ---------------------------------------------------------------------------
// (1) The controls a published port LOSES.
//
// Near-miss: a section that documents the same feature but claims the Caddy
// controls still apply to it. Every detector below must reject this text; if one
// accepts it, that detector is matching the topic instead of the claim.
// ---------------------------------------------------------------------------
const CONTROLS_STILL_APPLY = `
## TCP (layer-4) ingress — apps that aren't HTTP
Set \`ingress_type: 'tcp'\` and AppCrane publishes the production container's
port on the host at \`0.0.0.0:<public_port>\`.

| Control | \`http\` app | \`tcp\` app |
|---|---|---|
| \`forward_auth\` SSO gate | yes | yes |
| \`X-AppCrane-*\` identity headers | yes | yes |
| per-request audit / access log | yes | yes |
| rate limiting | yes | yes |
| security headers | yes | yes |
| TLS terminated by AppCrane | yes | yes |

AppCrane keeps handling authentication for the published port, so a tcp app
gets the same gate every other app gets.
`;

const LOSSES = [
  ['the SSO gate does not run', /forward[_ -]?auth|sso gate|single sign[- ]on/i],
  ['identity headers are not injected', /x-appcrane|identity header/i],
  ['requests are not audited or logged', /\baudit\b|access log|request log|logging/i],
  ['no rate limiting', /rate[- ]limit/i],
  ['no security headers', /security header|csp|x-frame-options|hsts/i],
  ['AppCrane does not terminate TLS', /\btls\b|https|let'?s encrypt/i],
];

for (const [label, SUBJECT] of LOSSES) {
  test(`onboarding.md states that a tcp app loses: ${label}`, () => {
    assert.ok(
      claims(TCP_SECTION, SUBJECT, ABSENT),
      `${GUIDE_PATH} never says, in one statement, that ${label} for a tcp app. ` +
      'A published port has none of these; if the doc has stopped saying so, an ' +
      'agent reading it will assume Caddy is still in front.',
    );
    assert.ok(
      !claims(CONTROLS_STILL_APPLY, SUBJECT, ABSENT),
      `the detector for "${label}" also matches a doc that claims the control STILL applies — ` +
      'it is matching the topic, not the claim',
    );
  });
}

test('onboarding.md states that the app owns authentication completely', () => {
  const OWNS = /\b(app|application|it)\b[^.]{0,90}\b(owns?|is responsible for|must (handle|implement|do|provide)|has to (handle|implement|do))\b[^.]{0,40}(auth|identity)/i;
  assert.ok(
    claims(TCP_SECTION, OWNS),
    `${GUIDE_PATH} never says the app itself owns authentication on a published port. ` +
    'Nothing else does — if the app skips it, the door is open.',
  );
  assert.ok(
    !claims(CONTROLS_STILL_APPLY, OWNS),
    'the ownership detector matches a doc that says AppCrane keeps handling auth',
  );
});

// ---------------------------------------------------------------------------
// (2) tcp is NOT auth_mode: 'headless'.
//
// This is the confusion the feature invites. Headless means AppCrane steps back
// from authentication but Caddy is still in the path (TLS, security headers, the
// auth-mode stamp, request logging). tcp means AppCrane steps out of the
// connection entirely. An agent that conflates them ships an app with no door.
// ---------------------------------------------------------------------------
const CONTRAST = /\b(not|isn'?t|is ?not|unlike|differs?|different|instead of|rather than|don'?t|do not|confuse|versus|vs\.?)\b/i;

test("onboarding.md distinguishes tcp ingress from auth_mode: 'headless'", () => {
  const distinguishes = t => nearby(t, /headless/gi, CONTRAST, /\btcp\b/i);
  assert.ok(
    distinguishes(TCP_SECTION),
    `${GUIDE_PATH} mentions headless near tcp but never contrasts them. ` +
    'They are not the same setting: headless still goes through Caddy.',
  );

  // Near-miss: the two are named together and equated rather than contrasted.
  const EQUATED = `
### Also see \`auth_mode: 'headless'\`
TCP ingress is like \`auth_mode: 'headless'\`: AppCrane steps back and the app
handles its own auth, so pick whichever reads better for your app.
`;
  assert.ok(
    !distinguishes(EQUATED),
    'the contrast detector accepts a doc that EQUATES tcp with headless',
  );
});

// ---------------------------------------------------------------------------
// (3) Opening the firewall is a separate operator step.
//
// The firewall is NOT an independent second key, and the guide must not sell it
// as one. Two separate reasons, both proven: a Docker publish is a DNAT rule
// evaluated in nat/FORWARD that never traverses INPUT, so a plain `ufw deny`
// does not block it; and this host sits behind SDP, so the boundary that exists
// is the perimeter, not the internet. An earlier draft of this section claimed
// "two keys on purpose, so a mis-click cannot put an app on the internet" — this
// test previously REQUIRED that claim, which is how the false version survived a
// review. It now requires the accurate one.
// ---------------------------------------------------------------------------
test('onboarding.md does not sell the firewall as an independent second key', () => {
  const SECOND_KEY = /two keys|cannot put an app on the internet|does ?n[o']t open the firewall/i;
  assert.doesNotMatch(TCP_SECTION, SECOND_KEY,
    `${GUIDE_PATH} still tells the reader the host firewall is a second key AppCrane leaves ` +
    'unturned. A ufw INPUT rule does not filter a Docker-published port, so that reassurance ' +
    'is false and an operator acts on it.');
});

test('onboarding.md explains why a plain firewall rule does not filter a published port', () => {
  for (const claim of [/DOCKER-USER/, /FORWARD/, /INPUT/, /DNAT/i]) {
    assert.match(TCP_SECTION, claim,
      `${GUIDE_PATH} no longer explains the DNAT/DOCKER-USER mechanism — without it a reader ` +
      'writes a ufw rule, sees it accepted, and believes the port is filtered.');
  }
  // Not vacuous: a section that only name-drops "firewall" must not satisfy this.
  assert.ok(!/DOCKER-USER/.test('Open the firewall for the 31000-31999 range.'),
    'the mechanism detector would pass on a doc that merely mentions a firewall');
});

test('onboarding.md states the real boundary on this deployment', () => {
  assert.match(TCP_SECTION, /SDP/,
    `${GUIDE_PATH} does not say the host sits behind SDP, so a reader cannot tell whether ` +
    'a published port is internet-facing or perimeter-facing — the two call for different responses.');
  assert.doesNotMatch(TCP_SECTION, /open relay on (this|the) (platform|host)'?s? public IP/i,
    'the retracted open-relay-on-a-public-IP claim is back in the guide');
});

// ---------------------------------------------------------------------------
// (4) The documented port range must be the range the allocator enforces.
//
// Both sides are extracted, never typed: the bounds come from tcpIngress.js and
// are exercised against the real assertion, and every numeric range and every
// example port in the doc is checked against them. Change the range in code
// without touching the doc (or the reverse) and this fails.
// ---------------------------------------------------------------------------
const RANGE_RE = /(\d{4,5})\s*(?:-|–|—|\.\.|to)\s*(\d{4,5})/g;
const PORT_LITERAL_RE = /public_port["`\s]*[:=]\s*["`]?(\d{4,5})/g;

function documentedRanges(text) {
  return [...text.matchAll(RANGE_RE)].map(m => [Number(m[1]), Number(m[2])]);
}

test('the allocator enforces the range it exports', () => {
  // A stub is enough: every bounds rejection happens before the first query.
  const noApps = { prepare: () => ({ get: () => undefined, all: () => [] }) };

  assert.equal(assertPublicPortAssignable(noApps, PUBLIC_PORT_MIN, null), PUBLIC_PORT_MIN);
  assert.throws(
    () => assertPublicPortAssignable(noApps, PUBLIC_PORT_MIN - 1, null),
    /between/i,
    'a port below PUBLIC_PORT_MIN was accepted — the exported bound is not the enforced one',
  );
  assert.throws(
    () => assertPublicPortAssignable(noApps, PUBLIC_PORT_MAX + 1, null),
    /between/i,
    'a port above PUBLIC_PORT_MAX was accepted — the exported bound is not the enforced one',
  );
});

test('onboarding.md documents the same port range the allocator enforces', () => {
  const agrees = t => {
    const ranges = documentedRanges(t);
    return ranges.length > 0
      && ranges.every(([lo, hi]) => lo === PUBLIC_PORT_MIN && hi === PUBLIC_PORT_MAX);
  };

  assert.ok(
    agrees(TCP_SECTION),
    `${GUIDE_PATH} documents ${JSON.stringify(documentedRanges(TCP_SECTION))} but the allocator ` +
    `enforces ${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX}. The operator opens a firewall block from ` +
    'this number; a stale one either leaves a live app unreachable or opens ports nothing uses.',
  );

  const STALE = "Ports come from a dedicated **30000–30999** range, lowest free first.";
  assert.ok(!agrees(STALE), 'the range detector accepts a range the allocator does not enforce');
  assert.ok(!agrees('Ports come from a dedicated range.'), 'the range detector passes with no range at all');
});

test('every example public_port in onboarding.md is inside the enforced range', () => {
  const examples = [...TCP_SECTION.matchAll(PORT_LITERAL_RE)].map(m => Number(m[1]));
  assert.ok(examples.length > 0, `${GUIDE_PATH} shows no concrete public_port example`);

  const inRange = ports => ports.every(p => p >= PUBLIC_PORT_MIN && p <= PUBLIC_PORT_MAX);
  assert.ok(
    inRange(examples),
    `example ports ${JSON.stringify(examples)} are not all within ` +
    `${PUBLIC_PORT_MIN}-${PUBLIC_PORT_MAX} — copying one out of the doc would 400`,
  );
  assert.ok(
    !inRange([...('public_port=30005'.matchAll(PORT_LITERAL_RE))].map(m => Number(m[1]))),
    'the example-port detector accepts a port outside the enforced range',
  );
});

// ---------------------------------------------------------------------------
// (5) Setting this is platform-admin only.
//
// The doc has to say who may do it, because the API gate is invisible to the
// agent reading the guide — and "an app owner can change their own auth_mode"
// makes the wrong generalisation easy.
// ---------------------------------------------------------------------------
test('onboarding.md states that only a platform admin may turn tcp ingress on', () => {
  const RESTRICTED = /(platform[- ]admin|platform_admin)[^.\n]{0,40}(only)|only[^.\n]{0,40}(platform[- ]admin|platform_admin)/i;
  const restricts = t => claims(t, RESTRICTED) || nearby(t, /platform[- ]?admin/gi, /\bonly\b/i);

  assert.ok(
    restricts(TCP_SECTION),
    `${GUIDE_PATH} does not say that opening a host port is platform-admin only`,
  );
  assert.ok(
    !restricts("Any app owner can set `ingress_type: 'tcp'` from the app's settings page."),
    'the authz detector accepts a doc that describes this as self-service',
  );
});

// ---------------------------------------------------------------------------
// (6) BACKLOG.md records the layer4 deferral WITH its reasoning.
//
// Option A (Caddy's layer4 plugin) was considered and rejected for this
// release. The value of the record is the reasoning, not the line item: without
// the cost — a custom xcaddy build replacing the binary that fronts every app —
// a future reader re-opens the question from zero, or worse, assumes nobody
// thought of it.
// ---------------------------------------------------------------------------
test('BACKLOG.md exists', () => {
  assert.ok(backlog !== null, `${BACKLOG_PATH} is missing — Option A has no written record`);
  assert.ok(backlog.length > 500, `${BACKLOG_PATH} is a stub`);
});

test('BACKLOG.md records the layer4 deferral with its reasoning', () => {
  const mentionsLayer4 = t => /layer[- ]?4|caddy-l4/i.test(t) && /caddy/i.test(t);
  const deferred = t => claims(t, /layer[- ]?4|caddy-l4|option a/i, /(defer|not doing|out of scope|postpon|rejected|backlog|instead)/i)
    || nearby(t, /layer[- ]?4|caddy-l4/gi, /(defer|not doing|out of scope|postpon|rejected|instead)/i);
  const cost = t => /xcaddy|custom (caddy )?build|build caddy|custom binary/i.test(t);
  const blastRadius = t => nearby(t, /every app|whole platform|all apps|blast radius/gi, /(caddy|binary|proxy|regress|down)/i);
  const records = t => mentionsLayer4(t) && deferred(t) && cost(t) && blastRadius(t);

  assert.ok(mentionsLayer4(backlog), `${BACKLOG_PATH} does not mention Caddy's layer4 option`);
  assert.ok(deferred(backlog), `${BACKLOG_PATH} does not record layer4 as deferred`);
  assert.ok(cost(backlog), `${BACKLOG_PATH} omits the cost that decided it: a custom xcaddy build`);
  assert.ok(
    blastRadius(backlog),
    `${BACKLOG_PATH} omits why that cost is disqualifying: the swapped binary fronts every app`,
  );

  // A bare line item — the exact thing this file exists to prevent.
  assert.ok(
    !records('## Backlog\n\n- Caddy layer4 plugin for raw TCP apps — maybe later.\n'),
    'the backlog detector accepts a one-line TODO with no reasoning',
  );
  // Reasoning present but the decision inverted: not a record of a deferral.
  assert.ok(
    !records('## Caddy layer4\n\nWe build Caddy with xcaddy so layer4 fronts every app.\n'),
    'the backlog detector accepts a doc that adopts layer4 rather than defers it',
  );
});
