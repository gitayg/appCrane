// API key expiry and the "MCP: OAuth only" policy.
//
// Which credentials expire (migration 136 stamps the expiry on issue and
// rotation with triggers):
//   - user API keys, dhk_user_* / dhk_admin_* (users.api_key_hash)
//   - personal MCP keys, dhk_mcp_* (user_mcp_keys, coder per-turn keys excluded)
//   - Crew agent tokens, dhk_crew_* (crew_agent_tokens)
// Not covered: per-app service tokens (server-only, injected into the app's
// container, never held by a person), coder per-turn keys (one turn, at most
// 3 hours) and OAuth tokens (1 hour access, 30 day refresh, already expiring).
//
// The sweep moves an expired user key's hash out of api_key_hash, so every
// route that looks a user up by api_key_hash directly (not only requireAuth)
// stops accepting it. requireAuth checks expiry inline, so through it an
// expired key is refused the moment it expires; elsewhere within one sweep.

import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import { jobStarted, trackJob } from './jobHealth.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

export const MAX_AGE_SETTING = 'api_key_max_age_days';
export const OAUTH_ONLY_SETTING = 'mcp_oauth_only';
export const OAUTH_ONLY_EXEMPT_SETTING = 'mcp_oauth_only_exempt_user_ids';
export const MAX_AGE_DEFAULT_DAYS = 90;
export const MAX_AGE_MIN_DAYS = 7;
export const MAX_AGE_MAX_DAYS = 365;
export const WARN_DAYS = [14, 3];
export const EXPIRY_MAIL_SOURCE = 'api-key-expiry';
export const SWEEP_MS = 5 * 60_000;
const JOB_ID = 'api-key-expiry';

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

function putSetting(db, key, value, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(key, value, userId ?? null);
}

/** The window in days, clamped exactly as the migration 136 triggers clamp it. */
export function maxAgeDays(db = getDb()) {
  const n = parseInt(setting(db, MAX_AGE_SETTING) ?? '', 10);
  if (!Number.isFinite(n) || n <= 0) return MAX_AGE_DEFAULT_DAYS;
  return Math.max(MAX_AGE_MIN_DAYS, Math.min(MAX_AGE_MAX_DAYS, n));
}

export function isMcpOauthOnly(db = getDb()) {
  return setting(db, OAUTH_ONLY_SETTING) === 'true';
}

export function oauthOnlyExemptIds(db = getDb()) {
  try {
    const list = JSON.parse(setting(db, OAUTH_ONLY_EXEMPT_SETTING) || '[]');
    return Array.isArray(list) ? list.map(Number).filter((n) => Number.isInteger(n) && n > 0) : [];
  } catch (_) {
    return [];
  }
}

export function getPolicy(db = getDb()) {
  return {
    max_age_days: maxAgeDays(db),
    max_age_default_days: MAX_AGE_DEFAULT_DAYS,
    max_age_min_days: MAX_AGE_MIN_DAYS,
    max_age_max_days: MAX_AGE_MAX_DAYS,
    warn_days: WARN_DAYS,
    mcp_oauth_only: isMcpOauthOnly(db),
    mcp_oauth_only_exempt_user_ids: oauthOnlyExemptIds(db),
  };
}

/** Validate and store a policy change. Throws { status: 400 } on a bad value. */
export function updatePolicy(db, body, userId) {
  const out = {};
  if (body.max_age_days !== undefined) {
    const n = body.max_age_days;
    if (!Number.isInteger(n) || n < MAX_AGE_MIN_DAYS || n > MAX_AGE_MAX_DAYS) {
      throw Object.assign(new Error(`max_age_days must be a whole number from ${MAX_AGE_MIN_DAYS} to ${MAX_AGE_MAX_DAYS}`), { status: 400 });
    }
    out[MAX_AGE_SETTING] = String(n);
  }
  if (body.mcp_oauth_only !== undefined) {
    if (typeof body.mcp_oauth_only !== 'boolean') throw Object.assign(new Error('mcp_oauth_only must be a boolean'), { status: 400 });
    out[OAUTH_ONLY_SETTING] = body.mcp_oauth_only ? 'true' : 'false';
  }
  if (body.mcp_oauth_only_exempt_user_ids !== undefined) {
    const ids = body.mcp_oauth_only_exempt_user_ids;
    if (!Array.isArray(ids) || ids.length > 200 || !ids.every((n) => Number.isInteger(n) && n > 0)) {
      throw Object.assign(new Error('mcp_oauth_only_exempt_user_ids must be an array of user ids'), { status: 400 });
    }
    const unique = [...new Set(ids)];
    if (unique.length) {
      const found = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE id IN (${unique.map(() => '?').join(',')})`).get(...unique).n;
      if (found !== unique.length) throw Object.assign(new Error('mcp_oauth_only_exempt_user_ids names an unknown user'), { status: 400 });
    }
    out[OAUTH_ONLY_EXEMPT_SETTING] = JSON.stringify(unique);
  }
  db.transaction(() => { for (const [k, v] of Object.entries(out)) putSetting(db, k, v, userId); })();
  return getPolicy(db);
}

export function sqliteToIso(s) {
  if (!s) return null;
  const t = Date.parse(String(s).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z'));
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

export function isPast(sqliteTs, now = Date.now()) {
  const iso = sqliteToIso(sqliteTs);
  return !!iso && Date.parse(iso) <= now;
}

function day(sqliteTs) {
  return (sqliteToIso(sqliteTs) || '').slice(0, 10);
}

export function expiredMessage(sqliteTs, where = 'Settings → Account') {
  return `This API key expired on ${day(sqliteTs)}. Create a new one in ${where}.`;
}

// One audit row per expired credential per hour, so a client retrying an
// expired key in a loop cannot flood the audit log.
const auditedAt = new Map();
export function auditExpiredUse(userId, kind, credentialId, expiresAt, ip) {
  const k = `${kind}:${credentialId}`;
  const last = auditedAt.get(k);
  if (last && Date.now() - last < 3600_000) return;
  auditedAt.set(k, Date.now());
  if (auditedAt.size > 5000) auditedAt.clear();
  try {
    logAudit(userId ?? null, null, 'api-key.expired-used', { kind, credential_id: credentialId, expired_at: sqliteToIso(expiresAt), ip: ip || null });
  } catch (e) {
    log.warn(`[api-key-expiry] audit row skipped: ${e.message}`);
  }
}

export function _resetAuditThrottleForTests() { auditedAt.clear(); }

// api_key_hash is UNIQUE NOT NULL: 'expired:' || hash keeps both and matches
// no presented key (every real value is a hex SHA-256).
const MOVE_SQL = `UPDATE users SET api_key_expired_hash = api_key_hash, api_key_hash = 'expired:' || api_key_hash
                   WHERE id = ? AND api_key_hash NOT LIKE 'expired:%'`;

export function isExpiredHash(h) {
  return typeof h === 'string' && h.startsWith('expired:');
}

/** Move every expired user key's hash aside. Returns how many were expired. */
export function expireDueUserKeys(db = getDb()) {
  const rows = db.prepare(`SELECT id, api_key_expires_at FROM users
                            WHERE api_key_hash NOT LIKE 'expired:%' AND api_key_expires_at IS NOT NULL
                              AND api_key_expires_at <= datetime('now')`).all();
  const move = db.prepare(MOVE_SQL);
  for (const r of rows) {
    if (move.run(r.id).changes) {
      try { logAudit(r.id, null, 'api-key.expired', { kind: 'user', expired_at: sqliteToIso(r.api_key_expires_at) }); } catch (_) {}
    }
  }
  return rows.length;
}

/** Expire one user's key now (requireAuth calls this when it meets one past its date). */
export function expireUserKey(db, userId) {
  db.prepare(MOVE_SQL).run(userId);
}

function stageFor(expiresAt, now) {
  const left = Date.parse(sqliteToIso(expiresAt)) - now;
  if (!(left > 0)) return null;
  if (left <= 3 * 86400_000) return 3;
  if (left <= 14 * 86400_000) return 14;
  return null;
}

// Who is warned, per credential kind. A user API key is warned about only once
// it has been used since it was issued: SSO and SCIM provisioning give every
// account a random key nobody ever sees, and telling those people a key they
// never had is about to expire is noise. MCP keys and Crew tokens are always
// issued on purpose, so they are always warned about.
function dueCredentials(db) {
  const window = "datetime('now', '+14 days')";
  const human = "u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''";
  return [
    ...db.prepare(`SELECT 'user' AS kind, u.id AS cred_id, u.id AS user_id, u.name, u.email, u.api_key_expires_at AS expires_at,
                          'Your AppCrane API key' AS label
                     FROM users u
                    WHERE u.api_key_hash NOT LIKE 'expired:%' AND u.api_key_last_used_at IS NOT NULL
                      AND u.api_key_expires_at > datetime('now') AND u.api_key_expires_at <= ${window} AND ${human}`).all(),
    ...db.prepare(`SELECT 'mcp' AS kind, k.id AS cred_id, u.id AS user_id, u.name, u.email, k.expires_at,
                          'Your personal MCP key' || CASE WHEN k.label IS NOT NULL AND k.label != '' THEN ' "' || k.label || '"' ELSE '' END AS label
                     FROM user_mcp_keys k JOIN users u ON u.id = k.user_id
                    WHERE k.coder_session_id IS NULL AND k.revoked_at IS NULL
                      AND k.expires_at > datetime('now') AND k.expires_at <= ${window} AND ${human}`).all(),
    ...db.prepare(`SELECT 'crew' AS kind, t.id AS cred_id, u.id AS user_id, u.name, u.email, t.expires_at,
                          'The Crew token of your agent "' || a.name || '"' AS label
                     FROM crew_agent_tokens t JOIN crew_agents a ON a.id = t.agent_id JOIN users u ON u.id = a.owner_user_id
                    WHERE t.revoked_at IS NULL AND t.expires_at > datetime('now') AND t.expires_at <= ${window} AND ${human}`).all(),
  ];
}

const WHERE_TO_ROTATE = {
  user: { text: 'Settings > Account', path: '/settings#account' },
  mcp: { text: 'the MCP page', path: '/mcp' },
  crew: { text: 'My agents', path: '/crew' },
};

/** Queue the 14- and 3-day warnings that are due. Returns the idempotency keys queued. */
export function sendExpiryWarnings(db = getDb(), now = Date.now()) {
  const queued = [];
  const base = dashboardBaseUrl();
  for (const c of dueCredentials(db)) {
    const stage = stageFor(c.expires_at, now);
    if (!stage) continue;
    const when = day(c.expires_at);
    const where = WHERE_TO_ROTATE[c.kind];
    const greeting = `Hi${c.name ? ` ${c.name}` : ''},`;
    const intro = `${c.label} expires on ${when}, in ${stage === 3 ? 'about 3 days' : 'about 2 weeks'}. After that, anything using it gets a 401.`;
    const action = `Rotate it in ${where.text}: you get a new key once, and the old one stops working at once.`;
    const idempotencyKey = `${EXPIRY_MAIL_SOURCE}:${c.kind}:${c.cred_id}:${c.expires_at}:${stage}`;
    try {
      enqueueEmail({
        to: c.email,
        subject: `[AppCrane] ${c.label} expires on ${when}`,
        text: `${greeting}\n\n${intro}\n\n${action}\n\n${base}${where.path}\n`,
        html: renderBrandedEmail({
          preheader: `${c.label} expires on ${when}.`,
          greeting,
          intro,
          bodyHtml: `<p style="margin:12px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};">${esc(action)}</p>`,
          cta: { label: 'Rotate it', url: `${base}${where.path}` },
          footer: 'You get this because the key is yours. AppCrane keys expire after a fixed number of days, set by your platform admin.',
        }),
        idempotencyKey,
        appId: null,
        source: EXPIRY_MAIL_SOURCE,
      });
      queued.push(idempotencyKey);
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[api-key-expiry] warning for ${c.kind} ${c.cred_id} skipped: ${e.message}`);
    }
  }
  return queued;
}

export function runApiKeyExpiry(db = getDb(), now = Date.now()) {
  const expired = expireDueUserKeys(db);
  const warned = sendExpiryWarnings(db, now);
  return { expired, warned: warned.length };
}

let timer = null;
export function startApiKeyExpiryJob() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: SWEEP_MS });
  const tick = () => trackJob(JOB_ID, async () => runApiKeyExpiry()).catch((e) => log.warn(`[api-key-expiry] ${e.message}`));
  tick();
  timer = setInterval(tick, SWEEP_MS);
  timer.unref?.();
}
