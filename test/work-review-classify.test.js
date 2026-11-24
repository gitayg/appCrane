import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join } from 'path';

// Scores work-review's prompt tests (plugins/work-review/skills/work-review/scripts/classify.mjs)
// against prompts a person labelled by meaning (test/fixtures/work-review-labelled-prompts.json).
// A label left out is false. The scores are printed on every run, so a change to a
// pattern shows what it won and lost; the test fails when a score drops below the
// floor recorded in the fixture. Raise a floor when a change earns it; lower one only
// with a reason, and say what was traded for it.

const C = await import(join(import.meta.dirname, '..', 'plugins', 'work-review', 'skills', 'work-review', 'scripts', 'classify.mjs'));
const F = JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', 'work-review-labelled-prompts.json'), 'utf8'));

const DETECTORS = { vague: C.isVague, criteria: C.hasCriteria, correction: C.isCorrection, nudge: C.isNudge };

function score(name, cases = F.cases) {
  const fn = DETECTORS[name];
  const r = { tp: 0, fp: 0, fn: 0, tn: 0, falsePos: [], falseNeg: [] };
  for (const c of cases) {
    const want = !!c[name], got = !!fn(c.text);
    if (want && got) r.tp++;
    else if (!want && got) { r.fp++; r.falsePos.push(c.text); }
    else if (want && !got) { r.fn++; r.falseNeg.push(c.text); }
    else r.tn++;
  }
  r.precision = r.tp + r.fp ? r.tp / (r.tp + r.fp) : 1;
  r.recall = r.tp + r.fn ? r.tp / (r.tp + r.fn) : 1;
  return r;
}

const pct = x => `${Math.round(x * 100)}%`;
const clip = s => (s.length > 70 ? s.slice(0, 70) + '…' : s);

test('the labelled set is well formed', () => {
  assert.ok(F.cases.length >= 50, 'keep at least 50 labelled prompts');
  const seen = new Set();
  for (const c of [...F.cases, ...F.heldOut]) {
    assert.equal(typeof c.text, 'string');
    assert.ok(!seen.has(c.text), `duplicate case: ${c.text}`);
    seen.add(c.text);
    for (const k of Object.keys(c)) assert.ok(k === 'text' || k in DETECTORS, `unknown label "${k}" on: ${c.text}`);
  }
  for (const name of Object.keys(DETECTORS)) {
    assert.ok(F.cases.some(c => c[name]), `no positive case for ${name}`);
    assert.ok(F.cases.some(c => !c[name]), `no negative case for ${name}`);
    assert.ok(F.floors[name], `no floor for ${name}`);
    assert.ok(F.heldOutFloors?.[name], `no held-out floor for ${name}`);
  }
});

for (const name of Object.keys(DETECTORS)) {
  test(`${name}: precision and recall against the labelled prompts stay at or above their floors`, t => {
    const r = score(name);
    t.diagnostic(`${name}: precision ${pct(r.precision)} (floor ${pct(F.floors[name].precision)}), recall ${pct(r.recall)} (floor ${pct(F.floors[name].recall)}); ${r.tp} right, ${r.fp} wrongly flagged, ${r.fn} missed`);
    for (const s of r.falsePos) t.diagnostic(`  flagged but not ${name}: ${clip(s)}`);
    for (const s of r.falseNeg) t.diagnostic(`  ${name} but missed: ${clip(s)}`);
    assert.ok(r.precision >= F.floors[name].precision, `${name} precision ${pct(r.precision)} fell below its floor ${pct(F.floors[name].precision)}`);
    assert.ok(r.recall >= F.floors[name].recall, `${name} recall ${pct(r.recall)} fell below its floor ${pct(F.floors[name].recall)}`);
  });
}

// The held-out prompts were labelled after the patterns were last tuned and are
// never tuned against, so these are the scores to quote. When a pattern changes,
// fold them into cases and write a fresh held-out set (see the fixture's "about").
for (const name of Object.keys(DETECTORS)) {
  test(`${name}: on held-out prompts it was not tuned on, scores stay at or above their floors`, t => {
    const r = score(name, F.heldOut);
    const fl = F.heldOutFloors[name];
    t.diagnostic(`${name} (held out, ${F.heldOut.length} prompts): precision ${pct(r.precision)} (floor ${pct(fl.precision)}), recall ${pct(r.recall)} (floor ${pct(fl.recall)}); ${r.tp} right, ${r.fp} wrongly flagged, ${r.fn} missed`);
    for (const s of r.falsePos) t.diagnostic(`  flagged but not ${name}: ${clip(s)}`);
    for (const s of r.falseNeg) t.diagnostic(`  ${name} but missed: ${clip(s)}`);
    assert.ok(r.precision >= fl.precision, `${name} held-out precision ${pct(r.precision)} fell below ${pct(fl.precision)}`);
    assert.ok(r.recall >= fl.recall, `${name} held-out recall ${pct(r.recall)} fell below ${pct(fl.recall)}`);
  });
}
