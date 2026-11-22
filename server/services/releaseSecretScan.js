// Secrets-in-code scan of a release tree, for the release check.
//
// Reuses crewSecrets.js's token shapes (near-certain credentials) and adds one
// assignment rule: a key/secret/token/password name assigned a long quoted
// literal whose character entropy is high, so `password = "changeme"` and
// `token: "${process.env.X}"` do not match. Only file, line and rule id are
// reported; the value never leaves this function.

import { readdirSync, readFileSync, lstatSync } from 'fs';
import { join, relative } from 'path';
import { findSecret, RULES as CREW_RULES } from './crewSecrets.js';
import { jwtPayload } from './adopt/secrets.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'bower_components', '__pycache__', '.venv', 'venv', '.next', '.cache']);
const SKIP_EXT = /\.(png|jpe?g|gif|webp|ico|svg|woff2?|ttf|eot|otf|mp[34]|webm|mov|zip|gz|tgz|br|pdf|wasm|map|lock|sqlite|db)$/i;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 20000;
const MAX_FINDINGS = 25;

const ASSIGNMENT_RE = /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b["']?\s*[:=]\s*["']([A-Za-z0-9+/_\-.=]{24,})["']/i;

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const WEAK_SECRETS = 'supersecretkey|supersecret|super-secret-key|super_secret_key|secretkey|secret_key|secret-key|mysecret|mysecretkey|my-secret-key|my_secret_key|jwtsecret|jwt_secret|jwt-secret|jwtsecretkey|your_jwt_secret|your-jwt-secret|yoursecretkey|your-secret-key|your_secret_key|changeme|change_me|change-me|changethis|keyboard cat|topsecret|s3cr3t|shhhhh|secret|secret123|default_secret|dev-secret|dev_secret|devsecret';
const WEAK_JWT_SECRET_RES = [
  new RegExp(`\\b(?:jwt|session|token|cookie|auth|app|signing)?[_-]?secret(?:[_-]?key)?["']?\\s*[:=]\\s*["'](?:${WEAK_SECRETS})["']`, 'gi'),
  new RegExp(`\\.(?:sign|verify)\\(\\s*[^,()]{1,200},\\s*["'](?:${WEAK_SECRETS})["']`, 'gi'),
  new RegExp(`\\b[A-Za-z_.]*secret[A-Za-z_]*\\s*(?:\\|\\||\\?\\?)\\s*["'](?:${WEAK_SECRETS})["']`, 'gi'),
];
const EXTRA_RULES = [
  { id: 'supabase-secret-key', re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g },
  { id: 'stripe-live-secret', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g },
];
const PLACEHOLDER_RE = /EXAMPLE|PLACEHOLDER|xxxxxxxx/i;

/** A Supabase anon JWT or publishable key: shipped to browsers by design. */
export function isPublicByDesign(value) {
  const v = String(value || '');
  if (/^sb_publishable_/.test(v)) return true;
  for (const m of v.matchAll(JWT_RE)) if (jwtPayload(m[0])?.role === 'anon') return true;
  return false;
}

/**
 * Every credential-shaped match in a text, with its value, for callers that
 * redact before anything leaves them. Supabase anon keys are not matches.
 * @returns {Array<{ rule: string, value: string, index: number }>}
 */
export function secretMatches(text) {
  const out = [];
  if (typeof text !== 'string' || !text) return out;
  const add = (rule, value, index) => {
    if (PLACEHOLDER_RE.test(value) || isPublicByDesign(value)) return;
    out.push({ rule, value, index });
  };
  for (const m of text.matchAll(JWT_RE)) {
    if (jwtPayload(m[0])?.role === 'service_role') add('supabase-service-role-key', m[0], m.index);
  }
  for (const r of CREW_RULES) {
    for (const m of text.matchAll(new RegExp(r.re.source, 'g'))) add(r.id, m[0], m.index);
  }
  for (const r of EXTRA_RULES) for (const m of text.matchAll(new RegExp(r.re.source, r.re.flags))) add(r.id, m[0], m.index);
  for (const re of WEAK_JWT_SECRET_RES) for (const m of text.matchAll(new RegExp(re.source, re.flags))) add('weak-jwt-secret', m[0], m.index);
  for (const m of text.matchAll(new RegExp(ASSIGNMENT_RE.source, 'gi'))) {
    if (shannonEntropy(m[1]) >= 3.5 && !out.some((o) => o.index <= m.index + m[0].length && m.index <= o.index + o.value.length)) {
      add('high-entropy-assignment', m[1], m.index);
    }
  }
  return out;
}

function extraSecretRule(line) {
  for (const m of line.matchAll(JWT_RE)) if (jwtPayload(m[0])?.role === 'service_role') return 'supabase-service-role-key';
  for (const r of EXTRA_RULES) { r.re.lastIndex = 0; if (r.re.test(line)) return r.id; }
  for (const re of WEAK_JWT_SECRET_RES) { re.lastIndex = 0; if (re.test(line)) return 'weak-jwt-secret'; }
  return null;
}

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
  const extra = extraSecretRule(line);
  if (extra) return extra;
  const m = ASSIGNMENT_RE.exec(line);
  if (m && shannonEntropy(m[1]) >= 3.5 && !isPublicByDesign(m[1])) return 'high-entropy-assignment';
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
