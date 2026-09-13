import { test } from 'node:test';
import assert from 'node:assert/strict';

// Env vars layered onto a stored .env: value quoting that dotenvParse.js reads
// back exactly, and edits that leave every other byte alone.

const { parseDotenv } = await import('../server/services/dotenvParse.js');
const { formatDotenvValue, mergeDotenvText, appendDotenvText, isLoadableEnvName } = await import('../server/services/dotenvMerge.js');
const read = (text, key) => parseDotenv(text).values.get(key);

const NASTY = [
  '', 'plain', ' leading', 'trailing ', '   ', 'a b', 'a#b', '#', '#start', 'x # y', "it's", 'say "hi"', 'back`tick',
  'multi\nline', 'multi\n\nblank', 'crlf\r\nx', 'lone\rcr', '$HOME and ${X} $(cmd)', 'tab\there', 'back\\slash', 'ends\\',
  '\\n literal', 'a=b=c', 'KEY=VAL', 'export X=1', 'ünï ✓ 日本', "'", '"', '`', "'\"", "'`", '\\', '\n', 'x\\\ny', 'a\\"b',
  "q'uote and \"double\"", 'postgres://u:p@db.example.com:5432/x?ssl=true#frag', '-----BEGIN KEY-----\nabc\n-----END KEY-----',
];
// No quoting in dotenvParse.js carries these exactly. Listed so the rules never widen silently.
const UNREPRESENTABLE = ["'\"` all three", 'cr\r"quote', 'ends with space \\', "\\n with ' and `", "'`\" "];

test('every representable nasty value round-trips through dotenvParse.js exactly, alone and inside a file', () => {
  for (const v of NASTY) {
    const f = formatDotenvValue(v);
    assert.notEqual(f, null, `expected a representation for ${JSON.stringify(v)}`);
    assert.equal(read(`K=${f}\n`, 'K'), v, `alone: ${JSON.stringify(v)} as ${JSON.stringify(f)}`);
    const merged = mergeDotenvText('# head\nK=old # note\nNEXT=1\n', new Map([['K', v]]));
    assert.equal(read(merged.text, 'K'), v, `merged: ${JSON.stringify(v)}`);
    assert.equal(read(merged.text, 'NEXT'), '1');
    const app = appendDotenvText('A=1', [['K', v], ['Z', 'z']]);
    assert.equal(read(app.text, 'K'), v, `appended: ${JSON.stringify(v)}`);
    assert.equal(read(app.text, 'Z'), 'z');
  }
  for (const v of UNREPRESENTABLE) assert.equal(formatDotenvValue(v), null, JSON.stringify(v));
});

test('fuzz: whatever formatDotenvValue writes, dotenvParse.js reads back', () => {
  let seed = 12345;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const alphabet = ['a', 'n', 'r', ' ', '\t', '#', "'", '"', '`', '\\', '\n', '\r', '$', '=', 'é'];
  let written = 0;
  for (let i = 0; i < 20000; i++) {
    let v = '';
    const len = Math.floor(rnd() * 9);
    for (let j = 0; j < len; j++) v += alphabet[Math.floor(rnd() * alphabet.length)];
    const f = formatDotenvValue(v);
    if (f === null) continue;
    written++;
    assert.equal(read(`K=${f}\nNEXT=ok\n`, 'K'), v, `fuzz ${JSON.stringify(v)} -> ${JSON.stringify(f)}`);
    assert.equal(read(`K=${f}\nNEXT=ok\n`, 'NEXT'), 'ok');
  }
  assert.ok(written > 15000, `only ${written} of 20000 were representable`);
});

test('override rewrites only the assignment: comments, order, blanks, export, CRLF, BOM and inline comments stay byte-identical', () => {
  const input = '﻿# top comment\r\n\r\nexport API_URL = "http://old.example.com" # keep me\r\nOTHER=1\r\n   # indented comment\r\nSECRET=old\r\nTAIL=z';
  const r = mergeDotenvText(input, new Map([['API_URL', 'https://new.example.com/a b'], ['SECRET', 'n#w']]));
  assert.deepEqual(r.overridden, ['API_URL', 'SECRET']);
  assert.equal(r.text, "﻿# top comment\r\n\r\nexport API_URL = 'https://new.example.com/a b' # keep me\r\nOTHER=1\r\n   # indented comment\r\nSECRET='n#w'\r\nTAIL=z");
  assert.equal(read(r.text, 'API_URL'), 'https://new.example.com/a b');
});

test('a multiline quoted value is replaced as a whole; every duplicate is overridden; an equal value is left untouched', () => {
  const input = 'A=1\nCERT="-----BEGIN-----\nline\n-----END-----" # c\nB=2\nDUP=x\nDUP="y"\nSAME="same"\n';
  const r = mergeDotenvText(input, new Map([['CERT', 'new'], ['DUP', 'z'], ['SAME', 'same']]));
  assert.equal(r.text, 'A=1\nCERT=new # c\nB=2\nDUP=z\nDUP=z\nSAME="same"\n');
  assert.deepEqual(r.overridden, ['CERT', 'DUP']);
});

test('a file with a parse error is not edited; an unrepresentable value is reported and left as is', () => {
  const broken = 'A=1\nB="unterminated\n';
  assert.equal(mergeDotenvText(broken, new Map([['A', '2']])).text, broken);
  assert.equal(mergeDotenvText(broken, new Map([['A', '2']])).parseError, true);
  const r = mergeDotenvText('A=1\n', new Map([['A', "'\"` all three"]]));
  assert.equal(r.text, 'A=1\n');
  assert.deepEqual(r.unrepresentable, ['A']);
});

test('append keeps existing bytes, adds a final newline when missing, follows CRLF', () => {
  assert.equal(appendDotenvText('A=1', [['B', 'two words']]).text, "A=1\n# Added by AppCrane from this app's environment variables\nB='two words'\n");
  assert.equal(appendDotenvText('A=1\r\n', [['B', 'b']]).text, "A=1\r\n# Added by AppCrane from this app's environment variables\r\nB=b\r\n");
  assert.equal(appendDotenvText('', [['B', 'b']]).text, "# Added by AppCrane from this app's environment variables\nB=b\n");
  assert.equal(appendDotenvText('A=1\n', []).text, 'A=1\n');
});

test('loadable names: the files a production-mode build reads; never example/sample/template/development', () => {
  for (const n of ['.env', '.env.local', '.env.production', '.env.production.local', '.env.sandbox', '.env.sandbox.local']) assert.ok(isLoadableEnvName(n), n);
  for (const n of ['.env.example', '.env.sample', '.env.template', '.env.development', '.env.test', '.envrc', '.env.production.example']) assert.ok(!isLoadableEnvName(n), n);
});
