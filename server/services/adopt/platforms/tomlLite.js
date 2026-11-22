// A TOML reader for railway.toml: tables, arrays of tables, dotted and quoted
// keys, basic / literal / multi-line strings, integers, floats, booleans,
// arrays and inline tables. Dates are kept as their text. A file outside that
// is refused with the line named; nothing is evaluated.

import { dict, isReservedKey } from './reservedKeys.js';

export class TomlLiteError extends Error {
  constructor(message, line) {
    super(line ? `line ${line}: ${message}` : message);
    this.line = line;
  }
}

const MAX_BYTES = 512 * 1024;
const MAX_DEPTH = 32;
const BARE_KEY = /[A-Za-z0-9_-]/;

export function parseTomlLite(text) {
  if (typeof text !== 'string') throw new TomlLiteError('not text');
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) throw new TomlLiteError(`file is over ${MAX_BYTES} bytes`);
  const s = text.replace(/^﻿/, '');
  let i = 0;
  const root = dict();
  let current = root;
  const defined = new Set();

  const line = () => s.slice(0, i).split('\n').length;
  const fail = (msg) => { throw new TomlLiteError(msg, line()); };
  const ws = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const comment = () => { if (s[i] === '#') while (i < s.length && s[i] !== '\n') i++; };
  const eol = () => {
    ws(); comment();
    if (s[i] === '\r') i++;
    if (i < s.length && s[i] !== '\n') fail(`unexpected "${s[i]}"`);
    i++;
  };
  const skipBlank = () => {
    for (;;) {
      const start = i;
      while (/[ \t\r\n]/.test(s[i] || '')) i++;
      comment();
      if (i === start) return;
    }
  };

  function basicString() {
    if (s.startsWith('"""', i)) {
      i += 3;
      if (s[i] === '\n') i++; else if (s.startsWith('\r\n', i)) i += 2;
      let out = '';
      for (;;) {
        if (i >= s.length) fail('unterminated multi-line string');
        if (s.startsWith('"""', i)) { i += 3; while (s[i] === '"') { out += '"'; i++; } return out; }
        if (s[i] === '\\') {
          if (/^\\[ \t]*\r?\n/.test(s.slice(i))) { i++; while (/[ \t\r\n]/.test(s[i] || '')) i++; continue; }
          out += escape();
          continue;
        }
        out += s[i++];
      }
    }
    i++;
    let out = '';
    for (;;) {
      const c = s[i];
      if (c === undefined || c === '\n') fail('unterminated string');
      if (c === '"') { i++; return out; }
      if (c === '\\') { out += escape(); continue; }
      out += c; i++;
    }
  }

  function escape() {
    const n = s[i + 1];
    const map = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\', e: '\x1b' };
    if (Object.hasOwn(map, n)) { i += 2; return map[n]; }
    if (n === 'u' || n === 'U') {
      const len = n === 'u' ? 4 : 8;
      const hex = s.slice(i + 2, i + 2 + len);
      if (hex.length !== len || !/^[0-9a-fA-F]+$/.test(hex)) fail('bad unicode escape');
      i += 2 + len;
      return String.fromCodePoint(parseInt(hex, 16));
    }
    fail(`unsupported escape \\${n}`);
  }

  function literalString() {
    if (s.startsWith("'''", i)) {
      i += 3;
      if (s[i] === '\n') i++; else if (s.startsWith('\r\n', i)) i += 2;
      const end = s.indexOf("'''", i);
      if (end < 0) fail('unterminated multi-line literal string');
      let out = s.slice(i, end);
      i = end + 3;
      while (s[i] === "'") { out += "'"; i++; }
      return out;
    }
    i++;
    const end = s.indexOf("'", i);
    const nl = s.indexOf('\n', i);
    if (end < 0 || (nl >= 0 && nl < end)) fail('unterminated literal string');
    const out = s.slice(i, end);
    i = end + 1;
    return out;
  }

  function key() {
    const parts = [];
    for (;;) {
      ws();
      if (s[i] === '"') parts.push(basicString());
      else if (s[i] === "'") parts.push(literalString());
      else {
        const start = i;
        while (BARE_KEY.test(s[i] || '')) i++;
        if (i === start) fail('expected a key');
        parts.push(s.slice(start, i));
      }
      if (isReservedKey(parts[parts.length - 1])) fail(`key "${parts[parts.length - 1]}" is not allowed`);
      ws();
      if (s[i] !== '.') return parts;
      i++;
    }
  }

  function value(depth) {
    if (depth > MAX_DEPTH) fail('nesting is too deep');
    const c = s[i];
    if (c === '"') return basicString();
    if (c === "'") return literalString();
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        skipBlank();
        if (s[i] === ']') { i++; return arr; }
        arr.push(value(depth + 1));
        skipBlank();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return arr; }
        fail('expected "," or "]" in an array');
      }
    }
    if (c === '{') {
      i++;
      const obj = dict();
      ws();
      if (s[i] === '}') { i++; return obj; }
      for (;;) {
        const k = key();
        if (s[i] !== '=') fail('expected "=" in an inline table');
        i++; ws();
        assign(obj, k, value(depth + 1), new Set());
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return obj; }
        fail('expected "," or "}" in an inline table');
      }
    }
    const m = s.slice(i).match(/^[^\s,\]}#]+/);
    if (!m) fail('expected a value');
    const tok = m[0];
    i += tok.length;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    const num = tok.replace(/_/g, '');
    if (/^[+-]?(?:0|[1-9]\d*)$/.test(num)) return Number(num);
    if (/^0x[0-9a-fA-F]+$/.test(num)) return parseInt(num.slice(2), 16);
    if (/^0o[0-7]+$/.test(num)) return parseInt(num.slice(2), 8);
    if (/^0b[01]+$/.test(num)) return parseInt(num.slice(2), 2);
    if (/^[+-]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(num)) return Number(num);
    if (/^[+-]?(?:inf|nan)$/.test(num)) return Number(num.replace('inf', 'Infinity').replace('nan', 'NaN'));
    if (/^\d{4}-\d{2}-\d{2}/.test(tok) || /^\d{2}:\d{2}/.test(tok)) {
      let t = tok;
      if (/^\d{4}-\d{2}-\d{2}$/.test(tok) && /^ \d{2}:\d{2}/.test(s.slice(i))) {
        const rest = s.slice(i).match(/^ [^\s,\]}#]+/)[0];
        t += rest; i += rest.length;
      }
      return t;
    }
    fail(`unsupported value "${tok.slice(0, 40)}"`);
  }

  function assign(table, parts, v, definedSet) {
    let t = table;
    for (const p of parts.slice(0, -1)) {
      if (!Object.hasOwn(t, p)) t[p] = dict();
      else if (typeof t[p] !== 'object' || Array.isArray(t[p])) fail(`key "${p}" is already a value`);
      t = t[p];
    }
    const last = parts[parts.length - 1];
    if (Object.hasOwn(t, last)) fail(`duplicate key "${parts.join('.')}"`);
    t[last] = v;
    definedSet.add(parts.join('\u0000'));
  }

  function tableAt(parts, isArray) {
    let t = root;
    parts.forEach((p, idx) => {
      const lastPart = idx === parts.length - 1;
      if (lastPart && isArray) {
        if (!Object.hasOwn(t, p)) t[p] = [];
        if (!Array.isArray(t[p])) fail(`"${parts.join('.')}" is not an array of tables`);
        const n = dict();
        t[p].push(n);
        t = n;
        return;
      }
      if (!Object.hasOwn(t, p)) t[p] = dict();
      let next = t[p];
      if (Array.isArray(next)) next = next[next.length - 1];
      if (!next || typeof next !== 'object') fail(`key "${p}" is already a value`);
      t = next;
    });
    return t;
  }

  for (;;) {
    skipBlank();
    if (i >= s.length) break;
    if (s[i] === '[') {
      const isArray = s[i + 1] === '[';
      i += isArray ? 2 : 1;
      const parts = key();
      if (s[i] !== ']' || (isArray && s[i + 1] !== ']')) fail('expected "]" to close the table header');
      i += isArray ? 2 : 1;
      const id = parts.join('\u0000');
      if (!isArray) {
        if (defined.has(id)) fail(`table [${parts.join('.')}] is defined twice`);
        defined.add(id);
      }
      current = tableAt(parts, isArray);
      eol();
      continue;
    }
    const parts = key();
    if (s[i] !== '=') fail('expected "=" after a key');
    i++; ws();
    assign(current, parts, value(0), new Set());
    eol();
  }
  return root;
}
