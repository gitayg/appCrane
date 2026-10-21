import { scrubText } from '../eventScrub.js';

export function tableExists(db, name) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
}

export function columns(db, table) {
  return tableExists(db, table) ? db.prepare(`PRAGMA table_info("${table}")`).all().map((c) => c.name) : [];
}

// Setting and column names whose VALUE is a credential or key material. Only
// "set / not set" is exported for these, never the value.
export const SECRET_NAME_RE = /secret|passw|token|private|_enc$|_enc_|encrypted|hash|cert|pem|credential|signing|api_key_value|_key$/i;

const FORMULA_RE = /^[=+\-@\t\r]/;

function cell(v) {
  if (v === null || v === undefined) return '';
  let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (FORMULA_RE.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** RFC 4180 CSV; a cell that a spreadsheet would read as a formula is prefixed with an apostrophe. */
export function toCsv(rows, cols) {
  const out = [cols.join(',')];
  for (const r of rows) out.push(cols.map((c) => cell(r[c])).join(','));
  return out.join('\r\n') + '\r\n';
}

export const json = (v) => JSON.stringify(v, null, 2) + '\n';

export const scrub = (v, max = 2000) => {
  if (v === null || v === undefined) return null;
  const s = scrubText(typeof v === 'string' ? v : JSON.stringify(v));
  return s.length > max ? s.slice(0, max - 3) + '...' : s;
};

/** [fromSql, toSqlExclusive] for SQLite datetime() comparison. */
export function periodBounds(period) {
  return [`${period.from} 00:00:00`, `${addDay(period.to)} 00:00:00`];
}

export function addDay(d) {
  const t = new Date(`${d}T00:00:00Z`);
  t.setUTCDate(t.getUTCDate() + 1);
  return t.toISOString().slice(0, 10);
}

export const daysBetween = (a, b) => {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  return Number.isFinite(ta) && Number.isFinite(tb) ? Math.floor((tb - ta) / 86_400_000) : null;
};

export function sqliteToIso(s) {
  if (!s) return null;
  const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${String(s).replace(' ', 'T')}Z`);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}
