import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// v2.66.3. The release workflow resolves the tag it is acting on in three
// places — checkout, build, upload — and they must agree.
//
// They did not. Checkout and build both read `github.event.inputs.ref` first
// and fell back to the branch; the upload step read the branch only. On a
// `release: published` event those are the same string, because ref_name IS the
// tag, so every run this workflow had ever had was correct. Under
// workflow_dispatch they differ: the job would check out the requested tag,
// build correct artifacts for it, and then upload them to a release named
// "main" that does not exist.
//
// The dispatch path existed but had never been exercised, so nothing failed
// until it was needed — to regenerate provenance for 30 tags after a history
// rewrite, which is precisely when a silent mismatch is most expensive.

const WF = readFileSync(new URL('../.github/workflows/release-supply-chain.yml', import.meta.url), 'utf8');

// The expression, ignoring whitespace inside ${{ }}.
const RESOLVER = /\$\{\{\s*github\.event\.inputs\.ref\s*\|\|\s*github\.ref(_name)?\s*\}\}/;

test('every step that resolves the target ref honours the dispatch input', () => {
  const lines = WF.split('\n');
  const refLines = lines.filter(l => /^\s*(ref|REF|TAG):\s*\$\{\{/.test(l));

  assert.ok(refLines.length >= 3,
    `expected the checkout/build/upload ref assignments, found ${refLines.length}`);

  for (const line of refLines) {
    assert.match(line.trim(), RESOLVER,
      'a step resolves the tag without falling back through github.event.inputs.ref, '
      + 'so a workflow_dispatch run would act on the branch instead of the requested tag: '
      + line.trim());
  }
});

test('the workflow still accepts a dispatch with a ref input', () => {
  assert.match(WF, /workflow_dispatch:/, 'the dispatch trigger must exist to re-run a past tag');
  assert.match(WF, /inputs:[\s\S]{0,200}?ref:/, 'dispatch must take the tag as an input');
});

test('release assets are uploaded with --clobber', () => {
  // Re-running a tag must overwrite its existing four assets rather than fail
  // on a duplicate name — otherwise regenerating provenance for a published
  // release is impossible without deleting the assets first.
  assert.match(WF, /--clobber/, 'a re-run must be able to replace existing assets');
});
