/**
 * Strict dotenv parser for importing bundled .env files (uploadConversion.js).
 *
 * Follows what the `dotenv` package does to the same text, so a value lands in
 * AppCrane the way the running app read it:
 *   - CRLF / CR line endings are normalised to LF; a leading BOM is dropped
 *   - blank lines and lines starting with '#' are ignored
 *   - an optional `export ` prefix is accepted
 *   - KEY = VALUE, spaces around '=' allowed, '=' inside a value kept
 *   - '...', "..." and `...` quote a value, which may span lines; inside double
 *     quotes \n and \r become newline / carriage return
 *   - an unquoted value ends at '#' and is trimmed
 *   - a later duplicate key replaces an earlier one
 *
 * Strict where dotenv is lenient: a line that is not KEY=VALUE, an unterminated
 * quote, or text after a closing quote is reported as an error instead of being
 * skipped silently. Errors carry the line number, the key name when there is
 * one, and a reason — never any part of a value.
 */

const LINE_KEY_RE = /^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=/;

function findClosingQuote(body, quote) {
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\' && body[i + 1] === quote) { i++; continue; }
    if (body[i] === quote) return i;
  }
  return -1;
}

export function parseDotenv(input) {
  const text = (Buffer.isBuffer(input) ? input.toString('utf8') : String(input ?? ''))
    .replace(/^﻿/, '')
    .replace(/\r\n?/g, '\n');
  const lines = text.split('\n');
  const values = new Map();
  const errors = [];

  for (let n = 0; n < lines.length; n++) {
    const lineNo = n + 1;
    let s = lines[n].replace(/^[ \t]+/, '');
    if (s === '' || s.startsWith('#')) continue;
    s = s.replace(/^export[ \t]+/, '');
    const m = LINE_KEY_RE.exec(s);
    if (!m) { errors.push({ line: lineNo, reason: 'not a KEY=VALUE line' }); continue; }
    const key = m[1];
    const rest = s.slice(m[0].length).replace(/^[ \t]+/, '');
    const quote = rest[0];

    if (quote === '"' || quote === "'" || quote === '`') {
      let body = rest.slice(1);
      let end = findClosingQuote(body, quote);
      while (end === -1 && n + 1 < lines.length) {
        n++;
        body += `\n${lines[n]}`;
        end = findClosingQuote(body, quote);
      }
      if (end === -1) { errors.push({ line: lineNo, key, reason: 'unterminated quoted value' }); continue; }
      if (!/^[ \t]*(#.*)?$/.test(body.slice(end + 1))) {
        errors.push({ line: lineNo, key, reason: 'unexpected text after the closing quote' });
        continue;
      }
      let value = body.slice(0, end);
      if (quote === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
      values.set(key, value);
      continue;
    }

    const hash = rest.indexOf('#');
    values.set(key, (hash === -1 ? rest : rest.slice(0, hash)).trim());
  }

  return { values, errors };
}
