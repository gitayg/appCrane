import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The confirmation dialog must list BOTH kinds of loss.
//
// redeployRisk reports two independent things:
//
//   at_risk_paths  — the image declares VOLUME here and nothing mounts it.
//   written_paths  — the app WROTE here, found with `docker diff`, and no mount
//                    covers it. The image declares nothing, so the first list
//                    is empty.
//
// The second is the whole reason the writable-layer detection exists: a Laravel
// app persisting to /var/www/html/storage declares no VOLUME at all, and there
// are roughly nine of those in the catalogue. For exactly those apps
// `at_risk_paths` is `[]`.
//
// The dialog originally rendered only `at_risk_paths`, and gated its remediation
// sentence on `at_risk_paths.length > 0`. So the app the feature was built for
// got a red data-loss warning with an EMPTY "Lost" list, no advice, and a
// sentence claiming the paths were "held in anonymous volumes" — which is not
// what happened to them. A warning that names nothing is worse than no warning:
// it reads as a false alarm and teaches the operator to click through.
//
// Asserted against the source. A DOM test would be better, and the component was
// checked in a browser when it was written — but nothing re-checks that on every
// run, and this catches the specific regression (rendering one list, not both).

const src = readFileSync(
  new URL('../studio-web/src/components/RedeployWarning.tsx', import.meta.url), 'utf8');

/** The "Lost" column's JSX. */
function lostColumn() {
  const start = src.indexOf('rw-col lost');
  assert.ok(start > 0, 'the Lost column was renamed — update this test deliberately');
  const end = src.indexOf('rw-col kept', start);
  assert.ok(end > start, 'could not delimit the Lost column');
  return src.slice(start, end);
}

test('the Lost column renders writable-layer paths, not only declared volumes', () => {
  const col = lostColumn();
  assert.match(col, /at_risk_paths\.map/,
    'declared-volume paths must still be listed');
  assert.match(col, /written\.map/,
    'writable-layer paths must be listed too, or a Laravel-shaped app gets a data-loss ' +
    'warning with an empty Lost list and no idea what it is about to lose');
});

test('the two kinds carry different explanations', () => {
  // "Held in anonymous volumes" is true of an undeclared VOLUME and false of a
  // writable-layer write. Saying it for both would be a confident wrong answer.
  const col = lostColumn();
  assert.match(col, /anonymous volumes/, 'the declared-volume explanation is gone');
  assert.match(col, /writable layer/i,
    'the writable-layer paths need their own explanation — they are not in a volume at all');
});

test('the remediation sentence fires for either kind of loss', () => {
  // The original gated this on at_risk_paths.length > 0, so the app that most
  // needed the advice was the one that never saw it.
  assert.match(src, /!risk\.unknown && lost\.length > 0/,
    'the remediation block must be gated on the COMBINED list; gating it on at_risk_paths ' +
    'hides the advice from exactly the apps the writable-layer detection was built for');
  assert.doesNotMatch(src, /risk\.at_risk_paths\.length > 0 && \(\s*\n\s*<p className="rw-why"/,
    'the remediation is still gated on at_risk_paths alone');
});

test('the combined list is what the operator is told they are accepting', () => {
  // The typed-slug gate says "the paths listed above". If `lost` and what is
  // rendered ever diverge, the operator confirms something other than what they
  // read.
  assert.match(src, /const lost = \[\.\.\.risk\.at_risk_paths, \.\.\.written\]/,
    'both kinds must feed the combined list');
});

test('an unreadable writable layer is surfaced rather than shown as nothing', () => {
  // writable_layer_unknown means docker diff failed or overflowed. Rendering
  // nothing would present "we could not look" as "there is nothing there" —
  // the same silent-reassurance failure the 4MB maxBuffer had.
  const col = lostColumn();
  assert.match(col, /writable_layer_unknown/,
    'an unknown writable layer must say so in the dialog, not render as an empty list');
});
