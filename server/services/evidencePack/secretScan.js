import { SECRET_COLUMNS } from './secretColumns.js';
import { tableExists } from './util.js';

// Last line of defence before a pack is written: every file is searched for
// values that must never leave the database or the process environment. A
// hit fails the pack (it is not silently redacted): it means a collector
// exported something it should not, and that needs fixing, not hiding.

const PATTERNS = [
  ['AppCrane API key', /\bdhk_[a-z]+_[A-Za-z0-9_-]{16,}/],
  ['Anthropic key', /\bsk-ant-[A-Za-z0-9_-]{16,}/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/],
  ['private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['AES-GCM ciphertext', /\b[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]{2,}\b/],
];

const ENV_SECRET_RE = /KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE/i;

function secretColumnValues(db) {
  const out = [];
  const take = (table, cols) => {
    if (!tableExists(db, table)) return;
    const have = new Set(db.prepare(`PRAGMA table_info("${table}")`).all().map((c) => c.name));
    for (const c of cols) {
      if (!have.has(c)) continue;
      for (const r of db.prepare(`SELECT "${c}" AS v FROM "${table}" WHERE "${c}" IS NOT NULL AND length("${c}") >= 12`).all()) out.push(String(r.v));
    }
  };
  for (const [table, cols] of SECRET_COLUMNS) take(table, cols);
  if (tableExists(db, 'settings')) {
    for (const r of db.prepare('SELECT key, value FROM settings WHERE value IS NOT NULL AND length(value) >= 12').all()) {
      if (/secret|passw|token|private|_enc$|encrypted|hash|cert/i.test(r.key)) out.push(String(r.value));
    }
  }
  return out;
}

/** The literal values a pack must not contain. `extra` lets a caller (and tests) add more. */
export function forbiddenValues(db, extra = []) {
  const vals = new Set();
  for (const [k, v] of Object.entries(process.env)) {
    if (ENV_SECRET_RE.test(k) && typeof v === 'string' && v.length >= 8) vals.add(v);
  }
  if (process.env.ENCRYPTION_KEY) vals.add(process.env.ENCRYPTION_KEY.slice(0, 64));
  for (const v of secretColumnValues(db)) vals.add(v);
  for (const v of extra) if (v && String(v).length >= 8) vals.add(String(v));
  return [...vals];
}

/** [{ file, kind }] for every hit. The value itself is never returned. */
export function scanFiles(files, forbidden) {
  const hits = [];
  for (const [path, buf] of Object.entries(files)) {
    const text = buf.toString('utf8');
    for (const [kind, re] of PATTERNS) if (re.test(text)) hits.push({ file: path, kind });
    for (const v of forbidden) if (text.includes(v)) { hits.push({ file: path, kind: 'stored secret or environment secret' }); break; }
  }
  return hits;
}
