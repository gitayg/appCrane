/**
 * Layer an app's AppCrane environment variables onto a stored .env file
 * (envFileStore.js restore). The file is the base; env vars override keys it
 * defines and are appended when no root-level loadable file defines them.
 *
 * Editing rules (mergeDotenvText):
 *   - only the assignment of an overridden key is rewritten; every other byte
 *     (comments, blank lines, order, `export ` prefixes, CRLF/LF, BOM, inline
 *     comments after the value) is kept
 *   - a multiline quoted value is replaced as a whole
 *   - every occurrence of a duplicate key is overridden
 *   - an assignment whose current value already equals the env var is left
 *     byte-identical
 *   - a file with any parse error is not edited at all (a guess at its structure
 *     could swallow following lines)
 *
 * Values are written so dotenvParse.js reads back exactly the env var value
 * (formatDotenvValue). A value no dotenv quoting can carry exactly under those
 * rules is reported as unrepresentable and not written; the container still
 * gets it through the runtime environment.
 */

import { parseDotenv } from './dotenvParse.js';

const KEY_RE = /^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=/;
const PLAIN_RE = /^[^\s#'"`]+$/;
export const APPEND_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * The .env names an app built with NODE_ENV=production loads (dotenv: .env;
 * Vite / Next.js / CRA: .env, .env.local, .env.<mode>, .env.<mode>.local), with
 * <mode> production, or sandbox for a bundler run with --mode sandbox. Never
 * example/sample/template, and not .env.development / .env.test, which a
 * production build does not read.
 */
export const LOADABLE_ENV_NAMES = new Set(['.env', '.env.local', '.env.production', '.env.production.local', '.env.sandbox', '.env.sandbox.local']);

export function isLoadableEnvName(name) {
  return LOADABLE_ENV_NAMES.has(name);
}

function findClosingQuote(body, quote) {
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\' && body[i + 1] === quote) { i++; continue; }
    if (body[i] === quote) return i;
  }
  return -1;
}

/** Text that dotenvParse.js reads back as exactly `value`, or null when there is none. */
export function formatDotenvValue(value) {
  const v = String(value);
  if (v === '') return '';
  if (PLAIN_RE.test(v)) return v;
  const endsWithBackslash = v.endsWith('\\');
  if (!v.includes('\r') && !endsWithBackslash) {
    if (!v.includes("'")) return `'${v}'`;
    if (!v.includes('`')) return `\`${v}\``;
  }
  if (!v.includes('"') && !/\\[nr]/.test(v) && !endsWithBackslash) {
    return `"${v.replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
  }
  return null;
}

function splitLines(text) {
  const parts = text.split(/(\r\n|\n|\r)/);
  const lines = [];
  for (let i = 0; i < parts.length; i += 2) lines.push({ content: parts[i], term: parts[i + 1] ?? '' });
  return lines;
}

/**
 * Returns { text, overridden: [keys], unrepresentable: [keys], defined: Set, parseError }.
 * `overrides` is a Map of key -> value.
 */
export function mergeDotenvText(input, overrides) {
  const text = String(input);
  const parsed = parseDotenv(text);
  const defined = new Set(parsed.values.keys());
  if (parsed.errors.length) return { text, overridden: [], unrepresentable: [], defined, parseError: true };

  const lines = splitLines(text);
  const out = [];
  const overridden = [];
  const unrepresentable = [];
  const keep = (from, to) => { for (let i = from; i <= to; i++) out.push(lines[i].content + lines[i].term); };

  for (let n = 0; n < lines.length; n++) {
    let s = lines[n].content;
    let lead = '';
    if (n === 0 && s.startsWith('﻿')) { lead = '﻿'; s = s.slice(1); }
    const ws = /^[ \t]*/.exec(s)[0];
    lead += ws;
    s = s.slice(ws.length);
    if (s === '' || s.startsWith('#')) { keep(n, n); continue; }
    const ex = /^export[ \t]+/.exec(s);
    if (ex) { lead += ex[0]; s = s.slice(ex[0].length); }
    const m = KEY_RE.exec(s);
    if (!m) { keep(n, n); continue; }
    const key = m[1];
    const afterEq = s.slice(m[0].length);
    const sp = /^[ \t]*/.exec(afterEq)[0];
    const prefix = lead + m[0] + sp;
    const rest = afterEq.slice(sp.length);
    const startN = n;
    const quote = rest[0];
    let value;
    let suffix;
    if (quote === '"' || quote === "'" || quote === '`') {
      let body = rest.slice(1);
      let end = findClosingQuote(body, quote);
      while (end === -1 && n + 1 < lines.length) {
        n++;
        body += `\n${lines[n].content}`;
        end = findClosingQuote(body, quote);
      }
      value = body.slice(0, end);
      if (quote === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
      suffix = body.slice(end + 1);
    } else {
      const hash = rest.indexOf('#');
      const region = hash === -1 ? rest : rest.slice(0, hash);
      value = region.trim();
      suffix = rest.slice(value.length);
    }

    if (!overrides.has(key) || overrides.get(key) === value) { keep(startN, n); continue; }
    const formatted = formatDotenvValue(overrides.get(key));
    if (formatted === null) {
      if (!unrepresentable.includes(key)) unrepresentable.push(key);
      keep(startN, n);
      continue;
    }
    out.push(prefix + formatted + suffix + lines[n].term);
    if (!overridden.includes(key)) overridden.push(key);
  }
  return { text: out.join(''), overridden, unrepresentable, defined, parseError: false };
}

/**
 * Append `entries` ([key, value] pairs) to `input`, after one comment line.
 * Returns { text, appended: [keys], unrepresentable: [keys] }. Keeps the file's
 * line ending style and never edits existing bytes (a missing final newline is
 * added first).
 */
export function appendDotenvText(input, entries) {
  let text = String(input);
  const term = text.includes('\r\n') ? '\r\n' : '\n';
  const appended = [];
  const unrepresentable = [];
  const lines = [];
  for (const [k, v] of entries) {
    const f = formatDotenvValue(v);
    if (f === null) { unrepresentable.push(k); continue; }
    lines.push(`${k}=${f}`);
    appended.push(k);
  }
  if (lines.length === 0) return { text, appended, unrepresentable };
  if (text.length && !/(\r\n|\n|\r)$/.test(text)) text += term;
  text += `# Added by AppCrane from this app's environment variables${term}${lines.join(term)}${term}`;
  return { text, appended, unrepresentable };
}
