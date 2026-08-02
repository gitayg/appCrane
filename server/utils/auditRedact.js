/**
 * Redaction for audit-log detail payloads (v2.28.0).
 *
 * The audit log records the arguments of every MCP tool call. Some of those
 * arguments are the very secrets the platform encrypts at rest:
 * `appcrane_set_secret({value})`, `appcrane_create_app({github_token})`,
 * `appcrane_set_app_meta({github_token})`. Writing them verbatim into
 * `audit_log.detail` stores them in PLAINTEXT, which quietly undoes the
 * AES-256-GCM encryption applied everywhere else — the audit log becomes the
 * softest place to steal a credential from.
 *
 * Secrets leak through channels nobody modelled (Docker Desktop once wrote
 * container env vars into its own application logs, CVE-2025-3911); a log
 * sink is exactly such a channel. So: mask by key name, and truncate large
 * values — a base64 file push would otherwise write megabytes per call into
 * SQLite.
 *
 * Masking is by KEY NAME, not by value inspection: we never try to detect
 * "this looks like a token", because that fails open. Unknown keys are kept
 * (an audit trail with no arguments is not much of an audit trail).
 */

// Argument names whose value is a credential. Matched case-insensitively,
// as a whole name or as a suffix (`github_token` matches via `token`).
const SECRET_KEY_PATTERNS = [
  'value',          // set_secret / set_env
  'token',          // github_token, staged_token, service token
  'secret',
  'password',
  'passwd',
  'api_key',
  'apikey',
  'credential',     // claude_credentials
  'private_key',
  'old_key',        // config import re-encryption key
  'encryption_key',
  'client_secret',
  'authorization',
];

// Strings longer than this are truncated. Generous enough to keep a useful
// prompt or path intact, small enough that a file push can't bloat the DB.
const MAX_STRING = 256;
const KEEP = 120;

function isSecretKey(key) {
  const k = String(key).toLowerCase();
  return SECRET_KEY_PATTERNS.some(p => k === p || k.endsWith(p) || k.endsWith(`_${p}`));
}

/**
 * Deep-copy `args`, masking credential-bearing keys and truncating long
 * strings. Never throws — a redaction failure must not lose the audit entry.
 *
 * @param {*} value    the arguments object (or any nested value)
 * @param {number} depth recursion guard
 * @returns {*} a safe-to-persist copy
 */
export function redactAuditArgs(value, depth = 0) {
  try {
    if (value == null) return value;
    if (depth > 6) return '[nested]';

    if (typeof value === 'string') {
      return value.length > MAX_STRING
        ? `${value.slice(0, KEEP)}…[truncated ${value.length - KEEP} chars]`
        : value;
    }
    if (typeof value !== 'object') return value;         // number, boolean

    if (Array.isArray(value)) {
      // Cap array length too — `files: [...]` on a bulk push can be long.
      const capped = value.slice(0, 20).map(v => redactAuditArgs(v, depth + 1));
      if (value.length > 20) capped.push(`[+${value.length - 20} more]`);
      return capped;
    }

    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSecretKey(k)) {
        // Record that a value WAS supplied, and its size, without the bytes.
        // "[redacted]" alone loses the difference between "rotated a token"
        // and "passed an empty string to clear it", which matters in a trail.
        out[k] = typeof v === 'string'
          ? (v.length === 0 ? '[redacted:empty]' : `[redacted:${v.length} chars]`)
          : '[redacted]';
      } else {
        out[k] = redactAuditArgs(v, depth + 1);
      }
    }
    return out;
  } catch (_) {
    return '[unserializable]';
  }
}

export const _internals = { isSecretKey, MAX_STRING, SECRET_KEY_PATTERNS };
