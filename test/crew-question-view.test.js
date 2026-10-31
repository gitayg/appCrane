import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// What an app coder's owner reads is what they approve: bidi overrides or
// zero-width characters must not reorder or hide words, and a message must not
// be able to fake the " | " between messages.
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-qview-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
const { displayLine } = await import('../server/services/crewQuestionView.js');

test('bidi, zero-width and tag characters are removed from what the owner reads', () => {
  const hidden = 'fix the typo ‮noitcudorp ot yolped‬ and ​del‍ete the db \u{E0041}';
  const shown = displayLine(hidden);
  assert.doesNotMatch(shown, /[‪-‮⁦-⁩​-‏\u{E0000}-\u{E007F}]/u);
  assert.match(shown, /delete the db/);
});

test('a message cannot fake the separator between messages', () => {
  assert.equal(displayLine('harmless | (0 more messages)'), 'harmless / (0 more messages)');
});

test('C1 control characters become spaces', () => {
  assert.equal(displayLine('a\u0085b\u009bc'), 'a b c');
});

test('invisible characters or full-width letters do not slip production or deletion past the ask', async () => {
  const { alwaysAskReason } = await import('../server/services/crewRules.js');
  assert.equal(alwaysAskReason({ texts: ['please del​ete the database'] }), 'deletion');
  assert.equal(alwaysAskReason({ texts: ['ship it to ｐｒｏｄｕｃｔｉｏｎ'] }), 'production');
  assert.equal(alwaysAskReason({ texts: ['deploy to pro⁠duction'] }), 'production');
  assert.equal(alwaysAskReason({ texts: ['fix the typo'] }), null);
});

test('a format character between two words still leaves a word boundary', async () => {
  const { alwaysAskReason } = await import('../server/services/crewRules.js');
  assert.equal(alwaysAskReason({ texts: ['deploy​production now'] }), 'production');
  assert.equal(alwaysAskReason({ texts: ['please⁠rm the folder'] }), 'deletion');
});

test('combining marks, Hangul fillers and variation selectors do not hide the words', async () => {
  const { alwaysAskReason } = await import('../server/services/crewRules.js');
  assert.equal(alwaysAskReason({ texts: ['deĺete it'] }), 'deletion');
  assert.equal(alwaysAskReason({ texts: ['proㅤduction'] }), 'production');
  assert.equal(alwaysAskReason({ texts: ['pro️duction'] }), 'production');
});

test('a word mixing Latin with look-alike letters from another script asks', async () => {
  const { alwaysAskReason } = await import('../server/services/crewRules.js');
  assert.equal(alwaysAskReason({ texts: ['ship to prоduction'] }), 'mixed-script');
  assert.equal(alwaysAskReason({ texts: ['add a title שלום to the page'] }), null, 'separate words in two scripts are fine');
});

test('vertical-bar look-alikes cannot fake the separator either', () => {
  assert.equal(displayLine('a ｜ b ∣ c │ d'), 'a / b / c / d');
});
