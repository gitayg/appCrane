import { encrypt, decrypt, deriveSecret } from '../encryption.js';
import { KEY_LABEL as CHAIN_LABEL, checkpointValid, signCheckpoint } from '../auditChain.js';
import { RECOVERY_LABEL, LEGACY_RECOVERY_SETTING } from '../mfa.js';
import {
  COLUMNS, SETTINGS_JSON, SETTINGS_HANDLED, INERT_TABLES, ENCRYPTED_RE, EMBEDDED_RE, coveredColumn,
} from './registry.js';

const MAX_LEGACY_RECOVERY_SECRETS = 20;

export class RotationError extends Error {
  constructor(message, report) {
    super(message);
    this.report = report;
  }
}

function tryDecrypt(blob, keyHex) {
  try { return { ok: true, plain: decrypt(blob, keyHex) }; } catch { return { ok: false }; }
}

function tableExists(db, table) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
}

function columnsOf(db, table) {
  return db.prepare(`PRAGMA table_info("${table}")`).all().map((c) => c.name);
}

/**
 * Every value to re-encrypt, decrypted with the old key. Nothing is written.
 * items: { where, table, column, rowid, oldBlob, plain }. A value that does
 * not decrypt goes to failures (it would be lost, so the run must stop).
 */
function collect(db, oldKey) {
  const items = [];
  const failures = [];
  const counts = {};
  const add = (where, table, column, rowid, blob) => {
    const d = tryDecrypt(blob, oldKey);
    if (!d.ok) { failures.push(where); return; }
    items.push({ where, table, column, rowid, oldBlob: blob, plain: d.plain });
  };

  for (const [table, cols] of COLUMNS) {
    if (!tableExists(db, table)) continue;
    const present = columnsOf(db, table);
    for (const column of cols) {
      if (!present.includes(column)) continue;
      const label = `${table}.${column}`;
      counts[label] = 0;
      const rows = db.prepare(`SELECT rowid AS rid, "${column}" AS v FROM "${table}" WHERE "${column}" IS NOT NULL AND "${column}" != ''`).all();
      for (const r of rows) {
        counts[label]++;
        add(`${label} rowid ${r.rid}`, table, column, r.rid, String(r.v));
      }
    }
  }

  const settings = db.prepare('SELECT rowid AS rid, key, value FROM settings WHERE value IS NOT NULL').all();
  counts['settings (encrypted values)'] = 0;
  for (const s of settings) {
    if (SETTINGS_HANDLED.has(s.key)) continue;
    const json = SETTINGS_JSON.find((j) => j.key === s.key);
    if (json) {
      let parsed = null;
      try { parsed = JSON.parse(s.value); } catch (_) {}
      for (const path of json.paths) {
        const blob = path.reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), parsed);
        if (typeof blob !== 'string' || !blob) continue;
        const label = `settings.${s.key}:${path.join('.')}`;
        counts[label] = (counts[label] || 0) + 1;
        add(label, 'settings', 'value', s.rid, blob);
      }
      continue;
    }
    if (ENCRYPTED_RE.test(s.value)) {
      counts['settings (encrypted values)']++;
      add(`settings.${s.key}`, 'settings', 'value', s.rid, s.value);
    }
  }
  return { items, failures, counts };
}

/**
 * Blobs that decrypt under the old key in places the registry does not cover.
 * Outside INERT_TABLES they make the run refuse: after rotation nothing could
 * read them. Inside, they are reported and left as they are.
 */
function scanUncovered(db, oldKey, items) {
  const uncovered = [];
  const inert = [];
  const coveredBlobs = new Set(items.map((i) => i.oldBlob));
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map((t) => t.name);
  for (const table of tables) {
    for (const column of columnsOf(db, table)) {
      const rows = db.prepare(`SELECT rowid AS rid, "${column}" AS v FROM "${table}"
        WHERE typeof("${column}") = 'text' AND "${column}" GLOB '*[0-9a-f]:[0-9a-f]*'`).all();
      for (const r of rows) {
        for (const blob of String(r.v).match(EMBEDDED_RE) || []) {
          if (coveredBlobs.has(blob)) continue;
          if (coveredColumn(table, column) && table !== 'settings') continue;
          if (table === 'settings' && SETTINGS_HANDLED.has(db.prepare('SELECT key FROM settings WHERE rowid = ?').get(r.rid)?.key)) continue;
          if (!tryDecrypt(blob, oldKey).ok) continue;
          (INERT_TABLES.has(table) ? inert : uncovered).push(`${table}.${column} rowid ${r.rid}`);
        }
      }
    }
  }
  return { uncovered, inert };
}

/** Re-sign every checkpoint that verifies under the old key; forged ones stay as they are (and stay reported). */
function planCheckpoints(db, oldKey, newKey) {
  if (!tableExists(db, 'audit_chain_checkpoints')) return { rows: [], invalid: 0 };
  const oldK = deriveSecret(CHAIN_LABEL, oldKey);
  const newK = deriveSecret(CHAIN_LABEL, newKey);
  const renamed = new Map();
  const rows = [];
  let invalid = 0;
  for (const c of db.prepare('SELECT * FROM audit_chain_checkpoints ORDER BY id').all()) {
    if (!checkpointValid(c, oldK)) { invalid++; continue; }
    const prev = c.prev_signature == null ? null : (renamed.get(c.prev_signature) ?? c.prev_signature);
    const next = { ...c, prev_signature: prev };
    next.signature = signCheckpoint(next, newK);
    renamed.set(c.signature, next.signature);
    rows.push(next);
  }
  return { rows, invalid };
}

function planRecovery(db, oldKey) {
  const existing = db.prepare('SELECT value FROM settings WHERE key = ?').get(LEGACY_RECOVERY_SETTING)?.value;
  let list = [];
  if (existing) {
    const d = tryDecrypt(existing, oldKey);
    if (!d.ok) return { error: `settings.${LEGACY_RECOVERY_SETTING}` };
    try { list = JSON.parse(d.plain); } catch (_) { return { error: `settings.${LEGACY_RECOVERY_SETTING}` }; }
    if (!Array.isArray(list)) return { error: `settings.${LEGACY_RECOVERY_SETTING}` };
  }
  const unused = tableExists(db, 'user_mfa_recovery_codes')
    ? db.prepare('SELECT COUNT(*) AS n, COUNT(DISTINCT user_id) AS u FROM user_mfa_recovery_codes WHERE used_at IS NULL').get()
    : { n: 0, u: 0 };
  if (unused.n > 0) {
    const secret = deriveSecret(RECOVERY_LABEL, oldKey);
    list = [...list.filter((k) => k !== secret), secret].slice(-MAX_LEGACY_RECOVERY_SECRETS);
  }
  return { list, users_with_codes: unused.u, codes: unused.n };
}

function verifyAll(db, plan, newKey, oldKey) {
  const bad = [];
  for (const it of plan.items) {
    const raw = db.prepare(`SELECT "${it.column}" AS v FROM "${it.table}" WHERE rowid = ?`).get(it.rowid)?.v;
    const blob = it.table === 'settings' && !ENCRYPTED_RE.test(String(raw)) ? (String(raw).match(EMBEDDED_RE) || []).find((b) => b === it.newBlob) : raw;
    const d = blob ? tryDecrypt(blob, newKey) : { ok: false };
    if (!d.ok || d.plain !== it.plain || tryDecrypt(blob, oldKey).ok) bad.push(it.where);
  }
  return bad;
}

/**
 * Re-encrypt every covered value from oldKey to newKey, in one transaction.
 * Returns the report. Throws RotationError (nothing written) when a value does
 * not decrypt, a blob sits somewhere uncovered, or the self-check fails.
 * beforeCommit() runs inside the transaction after the self-check; if it
 * throws, everything rolls back.
 */
export function rotateDatabase(db, { oldKey, newKey, dryRun = false, beforeCommit = null, actor = 'crane rotate-key' } = {}) {
  const plan = collect(db, oldKey);
  const scan = scanUncovered(db, oldKey, plan.items);
  const chain = planCheckpoints(db, oldKey, newKey);
  const recovery = planRecovery(db, oldKey);
  const failures = [...plan.failures, ...(recovery.error ? [recovery.error] : [])];
  const report = {
    dry_run: dryRun,
    counts: plan.counts,
    values: plan.items.length,
    failures,
    uncovered: scan.uncovered,
    inert_left_as_is: scan.inert,
    audit_checkpoints_resigned: chain.rows.length,
    audit_checkpoints_invalid_left: chain.invalid,
    recovery_codes: { users: recovery.users_with_codes ?? 0, unused: recovery.codes ?? 0, previous_key_secrets_kept: recovery.list?.length ?? 0 },
  };
  if (failures.length) throw new RotationError(`${failures.length} value(s) do not decrypt with the current key`, report);
  if (scan.uncovered.length) throw new RotationError(`${scan.uncovered.length} encrypted value(s) are in places rotate-key does not cover`, report);
  if (dryRun) return report;

  db.transaction(() => {
    for (const it of plan.items) {
      it.newBlob = encrypt(it.plain, newKey);
      if (it.table === 'settings' && SETTINGS_JSON.some((j) => it.where.startsWith(`settings.${j.key}:`))) {
        const raw = db.prepare('SELECT value FROM settings WHERE rowid = ?').get(it.rowid).value;
        db.prepare('UPDATE settings SET value = ? WHERE rowid = ?').run(raw.split(it.oldBlob).join(it.newBlob), it.rowid);
      } else {
        db.prepare(`UPDATE "${it.table}" SET "${it.column}" = ? WHERE rowid = ?`).run(it.newBlob, it.rowid);
      }
    }
    // audit_chain_checkpoints is append-only for UPDATE; a re-signed row is
    // deleted and written back under the same id.
    const del = db.prepare('DELETE FROM audit_chain_checkpoints WHERE id = ?');
    const ins = db.prepare(`INSERT INTO audit_chain_checkpoints (id, kind, src, upto_row_id, chain_hash, data, created_at, prev_signature, signature)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const c of chain.rows) {
      del.run(c.id);
      ins.run(c.id, c.kind, c.src, c.upto_row_id, c.chain_hash, c.data, c.created_at, c.prev_signature, c.signature);
    }
    if (recovery.list?.length) {
      db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`)
        .run(LEGACY_RECOVERY_SETTING, encrypt(JSON.stringify(recovery.list), newKey));
    }

    const bad = verifyAll(db, plan, newKey, oldKey);
    const newK = deriveSecret(CHAIN_LABEL, newKey);
    const notResigned = chain.rows.filter((c) => !checkpointValid(db.prepare('SELECT * FROM audit_chain_checkpoints WHERE id = ?').get(c.id), newK));
    if (bad.length || notResigned.length) {
      report.failures = [...bad, ...notResigned.map((c) => `audit_chain_checkpoints id ${c.id}`)];
      throw new RotationError('self-check failed after re-encryption', report);
    }

    const detail = JSON.stringify({ values: report.values, audit_checkpoints_resigned: report.audit_checkpoints_resigned, by: actor });
    db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail, actor_kind) VALUES (NULL, NULL, 'security.key_rotated', ?, 'human')").run(detail);
    db.prepare(`INSERT INTO events (kind, severity, summary, data) VALUES ('security.key_rotated', 'warning', ?, ?)`)
      .run(`ENCRYPTION_KEY rotated: ${report.values} stored secret(s) re-encrypted`, detail);
    if (beforeCommit) beforeCommit();
  })();
  report.self_check = 'every re-encrypted value decrypts with the new key and not with the old one';
  return report;
}

/** After commit: every covered value decrypts with `keyHex`. Returns the places that do not. */
export function selfCheck(db, keyHex) {
  const { failures } = collect(db, keyHex);
  return failures;
}
