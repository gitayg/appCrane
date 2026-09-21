/**
 * Per-user Claude subscription tokens.
 *
 * Anthropic's own answer for "authenticate somewhere without a browser" is
 * `claude setup-token`: it runs the normal login flow, prints a one-year OAuth
 * token, and saves it nowhere. The token is consumed as the
 * CLAUDE_CODE_OAUTH_TOKEN environment variable. That is what we store here, one
 * per AppCrane user, so an agent session runs on the subscription of the person
 * who started it rather than on a platform API key.
 *
 * Two constraints come from Anthropic's precedence rules and shape every caller:
 *
 *   1. CLAUDE_CODE_OAUTH_TOKEN ranks BELOW ANTHROPIC_API_KEY. A container that
 *      gets both uses the key, and the user's subscription is silently ignored.
 *      Callers must pass one or the other, never both.
 *   2. The token does not refresh. It expires a year after `claude setup-token`
 *      and regenerating it needs a browser, so the expiry is stored and shown
 *      rather than discovered as a 401 mid-session.
 *
 * Write-only, like the per-app credential: there is no route that returns a
 * stored token, and `meta()` is what the UI reads.
 */
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';

/**
 * Upper bound on a stored token. Anthropic's setup-token output is ~100-200
 * characters; 4096 leaves room for a format change by an order of magnitude
 * while still refusing a pasted file. The bound is not cosmetic: the value
 * ends up in a container's environment block, which is finite.
 */
export const MAX_TOKEN_LENGTH = 4096;

/**
 * The lifetime Anthropic documents for a `claude setup-token` token. Used when
 * the caller supplies no expiry, so a stored token always carries a date the
 * UI can warn on instead of a NULL that reads as "never expires".
 */
export const DEFAULT_TOKEN_LIFETIME_DAYS = 365;

/**
 * Why the token is checked at WRITE time and not at spawn time.
 *
 * The value's only destination is an environment variable on a container. A
 * byte outside printable ASCII cannot survive that trip: Node's spawn env is
 * Latin-1 at the OS boundary, a CR or LF ends the variable early (and starts
 * whatever follows as a new one — env-var injection), and a NUL truncates it.
 * Every one of those failures happens minutes later, inside a deploy, with a
 * message that names neither this token nor the user who pasted it.
 *
 * So: printable ASCII only (0x21-0x7E), which rejects control characters,
 * CR/LF, NUL, non-Latin-1 bytes and embedded whitespace in one test.
 *
 * Returns null when the token is storable, or a human-readable reason. The
 * reason NEVER quotes the token, not even a prefix — a rejected paste is still
 * a credential, and the string is on its way into an HTTP response.
 */
export function validateUserClaudeToken(token) {
  if (typeof token !== 'string') return 'token must be a string';
  if (token.length === 0) return 'token must not be empty';
  if (token.length > MAX_TOKEN_LENGTH) return `token must be at most ${MAX_TOKEN_LENGTH} characters`;
  if (/[\r\n]/.test(token)) return 'token must not contain a line break';
  if (token.includes('\0')) return 'token must not contain a NUL byte';
  if (!/^[\x21-\x7E]+$/.test(token)) {
    return 'token must be printable ASCII with no spaces (it is passed to a container as an environment variable)';
  }
  return null;
}

// An ISO-8601 instant, or null when the input is unusable. Stored normalised so
// two writers cannot disagree about the format the UI parses.
function normaliseExpiry(expiresAt) {
  if (expiresAt === null || expiresAt === undefined || expiresAt === '') return null;
  const ms = Date.parse(expiresAt);
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString();
}

function defaultExpiry() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + DEFAULT_TOKEN_LIFETIME_DAYS);
  return d.toISOString();
}

/** The decrypted token for a user, or null. Never log or return this to a client. */
export function getUserClaudeToken(userId) {
  const row = getDb()
    .prepare('SELECT token_encrypted FROM user_claude_tokens WHERE user_id = ?')
    .get(userId);
  if (!row) return null;
  return decrypt(row.token_encrypted);
}

/** What the UI may see: { present, expiresAt }. Never the token itself. */
export function userClaudeTokenMeta(userId) {
  const row = getDb()
    .prepare('SELECT expires_at FROM user_claude_tokens WHERE user_id = ?')
    .get(userId);
  // Columns are named one at a time rather than SELECT *: a `...row` spread or
  // a widened SELECT is exactly how token_encrypted would reach a response.
  return { present: !!row, expiresAt: row ? row.expires_at : null };
}

/**
 * Store (or replace) a user's token. `expiresAt` is an ISO string or null; null
 * (or an unparseable date) stores the documented one-year lifetime instead, so
 * no row is ever written that claims to last forever.
 *
 * Validation runs HERE, not only at the route, so there is one writer and no
 * second caller can put an unspawnable value in the table. Throws on a bad
 * token; routes turn that into a 400.
 */
export function setUserClaudeToken(userId, token, expiresAt = null) {
  const reason = validateUserClaudeToken(token);
  if (reason) throw new Error(reason);

  const expiry = normaliseExpiry(expiresAt) || defaultExpiry();
  getDb().prepare(`
    INSERT INTO user_claude_tokens (user_id, token_encrypted, expires_at, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      token_encrypted = excluded.token_encrypted,
      expires_at      = excluded.expires_at,
      updated_at      = datetime('now')
  `).run(userId, encrypt(token), expiry);

  return { present: true, expiresAt: expiry };
}

/** Remove a user's token. Returns true when a row was removed. */
export function clearUserClaudeToken(userId) {
  const info = getDb().prepare('DELETE FROM user_claude_tokens WHERE user_id = ?').run(userId);
  return info.changes > 0;
}
