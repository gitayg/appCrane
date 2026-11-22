import { getDb } from '../db.js';
import { _internals } from '../utils/auditRedact.js';
import log from '../utils/logger.js';

// audit_log rows written before v2.28.0 hold MCP tool arguments verbatim, so
// appcrane_set_secret({value}) left app secrets there in plaintext, and every
// backup since carries them. This masks secret-named fields in those rows the
// way redactAuditArgs masks new ones, and changes nothing else in the row.
// Runs once: the settings flag records that the table was scrubbed.

const FLAG = 'audit_legacy_secret_scrub_v1';

function mask(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 8) return { value, changed: false };
  let changed = false;
  const out = Array.isArray(value) ? [] : {};
  for (const [k, v] of Object.entries(value)) {
    if (!Array.isArray(value) && _internals.isSecretKey(k) && typeof v === 'string' && !v.startsWith('[redacted')) {
      out[k] = v.length === 0 ? '[redacted:empty]' : `[redacted:${v.length} chars]`;
      changed = true;
    } else {
      const r = mask(v, depth + 1);
      out[k] = r.value;
      changed ||= r.changed;
    }
  }
  return { value: out, changed };
}

export function scrubLegacyAuditSecrets(db = getDb()) {
  if (db.prepare('SELECT 1 FROM settings WHERE key = ?').get(FLAG)) return { skipped: true };
  const update = db.prepare('UPDATE audit_log SET detail = ? WHERE id = ?');
  let rows = 0;
  db.transaction(() => {
    for (const r of db.prepare('SELECT id, detail FROM audit_log WHERE detail IS NOT NULL').all()) {
      let parsed;
      try { parsed = JSON.parse(r.detail); } catch { continue; }
      const { value, changed } = mask(parsed);
      if (!changed) continue;
      update.run(JSON.stringify(value), r.id);
      rows++;
    }
    db.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))").run(FLAG, String(rows));
  })();
  if (rows) log.warn(`Masked secret values in ${rows} audit_log row(s) written before audit redaction; backups taken before this boot still hold them`);
  return { skipped: false, rows };
}
