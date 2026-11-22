// The personal MCP key the Applications page puts into an app-onboarding agent
// brief (POST /api/me/mcp-keys with purpose 'onboarding').
//
// Every click used to create another write-capable key that nobody revoked:
// one production instance held 83 onboarding keys, 77 of them never used. A
// new onboarding key now replaces the caller's earlier onboarding keys that
// were never used. A key that has been used belongs to an agent that may still
// be working and is left alone, as are coder session keys, other people's keys
// and keys made on the MCP page.

import { generateApiKey, hashApiKey } from './encryption.js';
import { logAudit } from '../middleware/audit.js';

export const ONBOARDING_PURPOSE = 'onboarding';
export const ONBOARDING_TTL_DAYS = 30;
// Labels written before user_mcp_keys.purpose existed (migration 168).
const LEGACY_LABEL = /^onboarding-\d+$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function onboardingLabel(now = new Date()) {
  return `App onboarding, ${now.getUTCDate()} ${MONTHS[now.getUTCMonth()]} ${now.getUTCFullYear()}`;
}

/** The caller's onboarding keys a new one replaces: live, never used, not a coder key. */
export function replaceableOnboardingKeys(db, userId) {
  return db.prepare(`
    SELECT id, label, purpose FROM user_mcp_keys
     WHERE user_id = ? AND revoked_at IS NULL AND last_used_at IS NULL AND coder_session_id IS NULL
  `).all(userId).filter((k) => k.purpose === ONBOARDING_PURPOSE || (k.purpose == null && LEGACY_LABEL.test(k.label || '')));
}

/**
 * Revoke the replaceable keys and create the new one, in one transaction.
 * The expiry asked for is 30 days; migration 136's insert trigger lowers it to
 * the platform's api_key_max_age_days when that is shorter.
 */
export function issueOnboardingKey(db, userId, { readOnly = 0, now = new Date() } = {}) {
  const apiKey = generateApiKey('dhk_mcp');
  const label = onboardingLabel(now);
  const run = db.transaction(() => {
    const revokedIds = [];
    const revoke = db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL");
    for (const k of replaceableOnboardingKeys(db, userId)) {
      if (!revoke.run(k.id).changes) continue;
      revokedIds.push(k.id);
      logAudit(userId, null, 'user-mcp-key-revoke', { key_id: k.id, reason: 'replaced by a new onboarding key' });
    }
    const id = db.prepare(`
      INSERT INTO user_mcp_keys (user_id, key_hash, label, expires_at, read_only, purpose)
      VALUES (?, ?, ?, datetime('now', '+' || ? || ' days'), ?, ?)
    `).run(userId, hashApiKey(apiKey), label, ONBOARDING_TTL_DAYS, readOnly, ONBOARDING_PURPOSE).lastInsertRowid;
    return { id, revokedIds };
  });
  const { id, revokedIds } = run();
  return { id, apiKey, label, revokedIds };
}
