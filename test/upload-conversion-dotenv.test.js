import { test } from 'node:test';
import assert from 'node:assert/strict';

// The strict dotenv parser used to import bundled .env values. Expected values
// follow what the `dotenv` package yields for the same text.

const { parseDotenv } = await import('../server/services/dotenvParse.js');
const obj = (text) => Object.fromEntries(parseDotenv(text).values);

test('plain, export prefix, comments, blank lines, spaces around =', () => {
  assert.deepEqual(obj('# top\n\nA=1\nexport B=two\n  C = three  \n#D=4\n'), { A: '1', B: 'two', C: 'three' });
});

test('= inside a value is kept', () => {
  assert.deepEqual(obj('URL=postgres://u:p@h/db?x=1&y=2\n'), { URL: 'postgres://u:p@h/db?x=1&y=2' });
});

test('unquoted value ends at #, quoted value keeps it', () => {
  assert.deepEqual(obj('A=abc # note\nB="abc # not a note"\nC=\'x#y\'\n'), { A: 'abc', B: 'abc # not a note', C: 'x#y' });
});

test('single, double and backtick quotes; \\n expands only inside double quotes', () => {
  assert.deepEqual(obj('A=\'a\\nb\'\nB="a\\nb"\nC=`a\\nb`\n'), { A: 'a\\nb', B: 'a\nb', C: 'a\\nb' });
});

test('multiline quoted value spans lines', () => {
  assert.deepEqual(obj('KEY="-----BEGIN-----\nline2\n-----END-----"\nNEXT=1\n'), { KEY: '-----BEGIN-----\nline2\n-----END-----', NEXT: '1' });
});

test('CRLF and a BOM are normalised', () => {
  assert.deepEqual(obj('﻿A=1\r\nB="x\r\ny"\r\n'), { A: '1', B: 'x\ny' });
});

test('empty values and a later duplicate replacing an earlier one', () => {
  assert.deepEqual(obj('A=\nB=""\nA=second\n'), { A: 'second', B: '' });
});

test('escaped quote does not close a double-quoted value', () => {
  assert.deepEqual(obj('A="say \\"hi\\""\n'), { A: 'say \\"hi\\"' });
});

test('errors: not KEY=VALUE, unterminated quote, text after quote — line and key only, never the value', () => {
  const r = parseDotenv('GOOD=1\njust-some-SECRETVALUE\nBAD="SECRETVALUE-open\nstill SECRETVALUE\n');
  assert.deepEqual(Object.fromEntries(r.values), { GOOD: '1' });
  assert.deepEqual(r.errors, [
    { line: 2, reason: 'not a KEY=VALUE line' },
    { line: 3, key: 'BAD', reason: 'unterminated quoted value' },
  ]);
  const t = parseDotenv('X="SECRETVALUE" trailing\n');
  assert.deepEqual(t.errors, [{ line: 1, key: 'X', reason: 'unexpected text after the closing quote' }]);
  assert.ok(!JSON.stringify([r.errors, t.errors]).includes('SECRETVALUE'));
});
