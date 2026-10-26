// Secrets-in-code scan of a release tree, for the release check.
//
// Reuses crewSecrets.js's token shapes (near-certain credentials) and adds one
// assignment rule: a key/secret/token/password name assigned a long quoted
// literal whose character entropy is high, so `password = "changeme"` and
// `token: "${process.env.X}"` do not match. Only file, line and rule id are
// reported; the value never leaves this function.

import { readdirSync, readFileSync, lstatSync } from 'fs';
import { join, relative } from 'path';
import { findSecret } from './crewSecrets.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'bower_components', '__pycache__', '.venv', 'venv', '.next', '.cache']);
const SKIP_EXT = /\.(png|jpe?g|gif|webp|ico|svg|woff2?|ttf|eot|otf|mp[34]|webm|mov|zip|gz|tgz|br|pdf|wasm|map|lock|sqlite|db)$/i;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 20000;
const MAX_FINDINGS = 25;

const ASSIGNMENT_RE = /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b["']?\s*[:=]\s*["']([A-Za-z0-9+/_\-.=]{24,})["']/i;

export function shannonEntropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/** The rule id a line matches, or null. */
export function lineSecretRule(line) {
  if (/EXAMPLE|PLACEHOLDER|your[_-]?(api[_-]?)?key|xxxxxxxx/i.test(line)) return null;
  const known = findSecret(line);
  if (known) return known;
  const m = ASSIGNMENT_RE.exec(line);
  if (m && shannonEntropy(m[1]) >= 3.5) return 'high-entropy-assignment';
  return null;
}

/**
 * @param {string} root release directory
 * @param {{ deadline?: number }} [opts] epoch ms after which the walk stops
 * @returns {{ findings: Array<{ file: string, line: number, rule: string }>, files: number, truncated: boolean }}
 */
export function scanTreeForSecrets(root, { deadline = Infinity } = {}) {
  const findings = [];
  let files = 0;
  let truncated = false;
  const walk = (dir) => {
    if (truncated) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of entries) {
      if (findings.length >= MAX_FINDINGS || files >= MAX_FILES || Date.now() > deadline) { truncated = true; return; }
      const p = join(dir, d.name);
      if (d.isSymbolicLink()) continue;
      if (d.isDirectory()) {
        if (!SKIP_DIRS.has(d.name)) walk(p);
        continue;
      }
      if (!d.isFile() || SKIP_EXT.test(d.name)) continue;
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.size > MAX_FILE_BYTES) continue;
      files++;
      let text;
      try { text = readFileSync(p, 'utf8'); } catch { continue; }
      if (text.includes('\u0000')) continue;
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const rule = lineSecretRule(lines[i]);
        if (rule) {
          findings.push({ file: relative(root, p), line: i + 1, rule });
          if (findings.length >= MAX_FINDINGS) break;
        }
      }
    }
  };
  walk(root);
  return { findings, files, truncated };
}
