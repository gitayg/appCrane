// Platform-admin view of every personal MCP key (routes/adminMcpKeys.js).
//
// Revoking used to be owner-only, so a key a person forgot about stayed live
// until it expired. These read and revoke any user's key. Nothing here selects
// key_hash: the list is built from an explicit column list.

import { logAudit } from '../middleware/audit.js';

const LIVE = "k.revoked_at IS NULL AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))";

export function listMcpKeys(db, { status = 'live' } = {}) {
  const rows = db.prepare(`
    SELECT k.id, k.user_id, u.name AS owner_name, u.email AS owner_email,
           k.label, k.purpose, k.read_only, k.app_id, a.slug AS app_slug,
           u.mcp_app_scope AS owner_mcp_app_scope,
           k.created_at, k.issued_at, k.last_used_at, k.expires_at, k.revoked_at,
           (k.coder_session_id IS NOT NULL) AS coder_session
      FROM user_mcp_keys k
      LEFT JOIN users u ON u.id = k.user_id
      LEFT JOIN apps a ON a.id = k.app_id
     ${status === 'all' ? '' : `WHERE ${LIVE}`}
     ORDER BY k.id DESC
  `).all();
  return rows.map((r) => ({
    id: r.id,
    owner: { id: r.user_id, name: r.owner_name, email: r.owner_email },
    label: r.label,
    purpose: r.purpose,
    read_only: !!r.read_only,
    app_scope: r.app_slug ?? null,
    owner_mcp_app_scope: parseScope(r.owner_mcp_app_scope),
    created_at: r.created_at,
    issued_at: r.issued_at,
    last_used_at: r.last_used_at,
    expires_at: r.expires_at,
    revoked_at: r.revoked_at,
    coder_session: !!r.coder_session,
  }));
}

function parseScope(v) {
  if (v == null) return null;
  try { return JSON.parse(v); } catch { return null; }
}

/** Revoke one key of any user. Idempotent: an already revoked key reports so. */
export function adminRevokeMcpKey(db, keyId, adminId) {
  const key = db.prepare('SELECT id, user_id, revoked_at FROM user_mcp_keys WHERE id = ?').get(keyId);
  if (!key) return null;
  if (key.revoked_at) return { id: key.id, already: true };
  db.transaction(() => {
    db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL").run(key.id);
    logAudit(adminId, null, 'user-mcp-key-revoke-admin', { key_id: key.id, owner_user_id: key.user_id, target_user_id: key.user_id });
  })();
  return { id: key.id, already: false };
}

/**
 * Live non-coder keys not used for `days` days. A key never used counts from
 * its creation, so a key issued yesterday is not "unused for 30 days".
 */
function unusedKeys(db, days) {
  return db.prepare(`
    SELECT k.id, k.user_id FROM user_mcp_keys k
     WHERE k.revoked_at IS NULL AND k.coder_session_id IS NULL
       AND datetime(COALESCE(k.last_used_at, k.created_at)) < datetime('now', '-' || ? || ' days')
     ORDER BY k.id
  `).all(days);
}

export function revokeUnusedMcpKeys(db, { days, dryRun, adminId }) {
  if (dryRun) {
    const keys = unusedKeys(db, days);
    return { dry_run: true, days, count: keys.length, key_ids: keys.map((k) => k.id) };
  }
  const revoked = db.transaction(() => {
    const out = [];
    const revoke = db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL");
    for (const k of unusedKeys(db, days)) {
      if (!revoke.run(k.id).changes) continue;
      out.push(k.id);
      logAudit(adminId, null, 'user-mcp-key-revoke-admin', {
        key_id: k.id, owner_user_id: k.user_id, target_user_id: k.user_id, reason: `unused for ${days}+ days`,
      });
    }
    return out;
  })();
  return { dry_run: false, days, count: revoked.length, key_ids: revoked };
}
