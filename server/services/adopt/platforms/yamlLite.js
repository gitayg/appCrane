// A YAML reader for the subset deploy manifests use (render.yaml, heroku.yml):
// block mappings and sequences, plain / quoted scalars, flow sequences and
// one-level flow mappings, block scalars (| and >) and comments. Anchors,
// aliases, tags, multi-line plain scalars and multiple documents are refused
// with the line named, so a file this cannot read is reported, never guessed.
// Nothing is evaluated: values come back as strings, numbers, booleans or null.

import { dict, isReservedKey } from './reservedKeys.js';

export class YamlLiteError extends Error {
  constructor(message, line) {
    super(line ? `line ${line}: ${message}` : message);
    this.line = line;
  }
}

const MAX_BYTES = 512 * 1024;
const MAX_DEPTH = 64;

function stripComment(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && quote === '"') { i++; continue; }
      if (c === quote) {
        if (quote === "'" && text[i + 1] === "'") { i++; continue; }
        quote = null;
      }
      continue;
    }
    if ((c === '"' || c === "'") && (i === 0 || /[\s:[{,-]/.test(text[i - 1]))) { quote = c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) return text.slice(0, i).trimEnd();
  }
  return text.trimEnd();
}

function unquoteDouble(s, line) {
  let out = '';
  for (let i = 1; i < s.length - 1; i++) {
    const c = s[i];
    if (c !== '\\') { out += c; continue; }
    const n = s[++i];
    const map = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', '0': '\0', ' ': ' ' };
    if (Object.hasOwn(map, n)) out += map[n];
    else if (n === 'u' || n === 'x') {
      const len = n === 'u' ? 4 : 2;
      const hex = s.slice(i + 1, i + 1 + len);
      if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) throw new YamlLiteError('bad escape in a double-quoted string', line);
      out += String.fromCharCode(parseInt(hex, 16));
      i += len;
    } else throw new YamlLiteError(`unsupported escape \\${n}`, line);
  }
  return out;
}

function scalar(raw, line) {
  const s = raw.trim();
  if (s === '') return null;
  if (/^[&*!]/.test(s)) throw new YamlLiteError('anchors, aliases and tags are not supported', line);
  if (s.startsWith('"')) {
    if (s.length < 2 || !s.endsWith('"')) throw new YamlLiteError('unterminated double-quoted string', line);
    return unquoteDouble(s, line);
  }
  if (s.startsWith("'")) {
    if (s.length < 2 || !s.endsWith("'")) throw new YamlLiteError('unterminated single-quoted string', line);
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.startsWith('[') || s.startsWith('{')) return flow(s, line);
  if (/^(?:null|Null|NULL|~)$/.test(s)) return null;
  if (/^(?:true|True|TRUE)$/.test(s)) return true;
  if (/^(?:false|False|FALSE)$/.test(s)) return false;
  if (/^[-+]?\d+$/.test(s) && Number.isSafeInteger(Number(s))) return Number(s);
  if (/^[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?$/.test(s)) return Number(s);
  return s;
}

function splitFlow(body, line) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      cur += c;
      if (c === '\\' && quote === '"') { cur += body[++i] ?? ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if (c === '[' || c === '{') depth++;
    if (c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (quote || depth !== 0) throw new YamlLiteError('unbalanced flow collection', line);
  if (cur.trim()) parts.push(cur);
  return parts;
}

function flow(s, line) {
  const open = s[0];
  const close = open === '[' ? ']' : '}';
  if (!s.endsWith(close)) throw new YamlLiteError('a flow collection must close on the same line', line);
  const parts = splitFlow(s.slice(1, -1), line);
  if (open === '[') return parts.map((p) => scalar(p, line));
  const out = dict();
  for (const p of parts) {
    const m = p.match(/^\s*("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:]+?)\s*:\s*(.*)$/s);
    if (!m) throw new YamlLiteError('flow mapping entries must be key: value', line);
    const key = String(scalar(m[1], line));
    if (isReservedKey(key)) throw new YamlLiteError(`key "${key}" is not allowed`, line);
    if (Object.hasOwn(out, key)) throw new YamlLiteError(`duplicate key "${key}"`, line);
    out[key] = scalar(m[2], line);
  }
  return out;
}

const KEY_RE = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#][^:#]*?)\s*:(?:\s+(.*)|\s*)$/;

function isSeqItem(text) {
  return text === '-' || text.startsWith('- ');
}

/** Parse the subset. Returns the document's value. Throws YamlLiteError. */
export function parseYamlLite(text) {
  if (typeof text !== 'string') throw new YamlLiteError('not text');
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) throw new YamlLiteError(`file is over ${MAX_BYTES} bytes`);
  const raw = text.replace(/^﻿/, '').split(/\r?\n/);
  const lines = [];
  let docs = 0;
  for (let i = 0; i < raw.length; i++) {
    const r = raw[i];
    if (/^\t/.test(r) || /^ *\t/.test(r)) throw new YamlLiteError('tabs are not allowed for indentation', i + 1);
    if (/^---(?:\s|$)/.test(r)) {
      if (++docs > 1 || lines.length) throw new YamlLiteError('only one YAML document is supported', i + 1);
      continue;
    }
    if (/^\.\.\.\s*$/.test(r)) break;
    if (/^%/.test(r)) throw new YamlLiteError('YAML directives are not supported', i + 1);
    lines.push({ indent: r.length - r.trimStart().length, raw: r, text: stripComment(r.trim()), no: i + 1 });
  }
  const content = lines.filter((l) => l.text !== '');
  const all = lines;
  let pos = 0;
  const peek = () => content[pos];

  function blockScalar(indicator, parentIndent, afterLine) {
    const m = indicator.match(/^([|>])([+-]?)(\d?)([+-]?)$/);
    if (!m) throw new YamlLiteError(`unsupported block scalar header "${indicator}"`, afterLine.no);
    const folded = m[1] === '>';
    const chomp = m[2] || m[4];
    const start = all.indexOf(afterLine) + 1;
    const body = [];
    let indent = m[3] ? parentIndent + Number(m[3]) : null;
    let j = start;
    for (; j < all.length; j++) {
      const l = all[j];
      if (l.raw.trim() === '') { body.push(''); continue; }
      if (indent === null) indent = l.indent;
      if (l.indent < indent || l.indent <= parentIndent) break;
      body.push(l.raw.slice(indent));
    }
    while (pos < content.length && content[pos].no <= (all[j - 1]?.no ?? 0) && content[pos].no > afterLine.no) pos++;
    let trailing = 0;
    while (body.length && body[body.length - 1] === '') { body.pop(); trailing++; }
    let value;
    if (folded) {
      value = '';
      for (let k = 0; k < body.length; k++) {
        const ln = body[k];
        if (k === 0) value = ln;
        else if (ln === '' || /^\s/.test(ln) || body[k - 1] === '' || /^\s/.test(body[k - 1])) value += `\n${ln}`;
        else value += ` ${ln}`;
      }
    } else value = body.join('\n');
    if (chomp === '-') return value;
    if (chomp === '+') return `${value}\n${'\n'.repeat(trailing)}`;
    return body.length ? `${value}\n` : '';
  }

  function inlineValue(rest, line, indent, depth) {
    if (/^[|>]/.test(rest)) return blockScalar(rest, indent, line);
    return scalar(rest, line.no);
  }

  function node(indent, depth) {
    if (depth > MAX_DEPTH) throw new YamlLiteError('nesting is too deep', peek()?.no);
    const l = peek();
    if (!l || l.indent < indent) return null;
    return isSeqItem(l.text) ? seq(l.indent, depth) : map(l.indent, depth);
  }

  function childAfterKey(line, indent, depth) {
    const n = peek();
    if (!n) return null;
    if (n.indent > indent) return node(n.indent, depth + 1);
    if (n.indent === indent && isSeqItem(n.text)) return seq(indent, depth + 1);
    return null;
  }

  function seq(indent, depth) {
    const out = [];
    while (peek() && peek().indent === indent && isSeqItem(peek().text)) {
      const l = content[pos];
      const rest = l.text === '-' ? '' : l.text.slice(2).trimStart();
      if (rest === '') {
        pos++;
        const n = peek();
        out.push(n && n.indent > indent ? node(n.indent, depth + 1) : null);
        continue;
      }
      const inner = indent + (l.text.length - rest.length);
      if (isSeqItem(rest) || (KEY_RE.test(rest) && !/^["'[{]/.test(rest.trim()) ) || /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')\s*:(\s|$)/.test(rest)) {
        content[pos] = { ...l, indent: inner, text: rest };
        out.push(node(inner, depth + 1));
        continue;
      }
      pos++;
      out.push(inlineValue(rest, l, indent, depth));
    }
    const n = peek();
    if (n && n.indent > indent) throw new YamlLiteError('unexpected indentation (multi-line plain scalars are not supported)', n.no);
    return out;
  }

  function map(indent, depth) {
    const out = dict();
    while (peek() && peek().indent === indent && !isSeqItem(peek().text)) {
      const l = content[pos];
      const m = l.text.match(KEY_RE);
      if (!m) throw new YamlLiteError(`expected "key: value", got "${l.text.slice(0, 60)}"`, l.no);
      const key = String(scalar(m[1], l.no));
      if (key === '<<') throw new YamlLiteError('merge keys are not supported', l.no);
      if (isReservedKey(key)) throw new YamlLiteError(`key "${key}" is not allowed`, l.no);
      if (Object.hasOwn(out, key)) throw new YamlLiteError(`duplicate key "${key}"`, l.no);
      pos++;
      const rest = (m[2] || '').trim();
      out[key] = rest === '' ? childAfterKey(l, indent, depth) : inlineValue(rest, l, indent, depth);
    }
    const n = peek();
    if (n && n.indent > indent) throw new YamlLiteError('unexpected indentation (multi-line plain scalars are not supported)', n.no);
    return out;
  }

  if (!content.length) return null;
  const first = content[0];
  const value = node(first.indent, 0);
  if (pos < content.length) throw new YamlLiteError('unexpected content after the document', content[pos].no);
  return value;
}
