// Per-app Claude Code OAuth credentials helper.
//
// Operators upload a credentials.json (the file Claude Code writes after
// `claude login`) and we store it encrypted on the app row. At dispatch
// time we decrypt it into a per-call tmpfile, bind-mount that into the
// container as ~/.claude/credentials.json, and after the dispatch read
// the file back to capture any token refresh the CLI did.
//
// Why a tmpfile instead of mounting straight from a stable path:
//   - We need the file decrypted (the DB blob is encrypted)
//   - Each dispatch gets its own copy so concurrent runs don't fight
//   - Cleanup wipes the plaintext from disk after the run

import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';

function tmpRoot() {
  return resolve(process.env.DATA_DIR || './data', 'claude-credentials-tmp');
}

/**
 * Validate a credentials.json payload before storing. Throws on anything
 * that doesn't look like a real Claude Code credentials file so we don't
 * persist garbage that'd break dispatches later.
 */
export function validateCredentials(json) {
  if (!json || typeof json !== 'object') throw new Error('credentials must be a JSON object');
  if (typeof json.access_token !== 'string' || !json.access_token.length) {
    throw new Error('credentials.json missing access_token');
  }
  if (typeof json.refresh_token !== 'string' || !json.refresh_token.length) {
    throw new Error('credentials.json missing refresh_token (refresh would fail at expiry)');
  }
  return true;
}

/**
 * Public summary safe to return from API endpoints. Returns ONLY metadata —
 * never any portion of the access_token or refresh_token, not even a
 * truncated tail. Once an operator uploads credentials, the only allowed
 * actions are: replace (upload new) or delete. There is no download
 * endpoint and no field that exposes the secret value back to the client.
 *
 * Account UUID is kept since it's an identifier (not a credential) — useful
 * for the "yes this matches the account I expected" sanity check.
 * Expires-at is kept so the operator can see if the access token is stale.
 */
export function credentialsInfo(slug) {
  const row = getDb()
    .prepare('SELECT claude_credentials_encrypted FROM apps WHERE slug = ?')
    .get(slug);
  if (!row?.claude_credentials_encrypted) return { present: false };
  let parsed;
  try {
    parsed = JSON.parse(decrypt(row.claude_credentials_encrypted));
  } catch (err) {
    log.warn(`claudeCredentials: parse failed for ${slug}: ${err.message}`);
    return { present: true, malformed: true };
  }
  return {
    present: true,
    expiresAt: parsed.expires_at || null,
    accountUuid: parsed.accountUuid || parsed.account_uuid || null,
  };
}

/** Store an already-parsed credentials object (validates first). */
export function setCredentials(slug, json) {
  validateCredentials(json);
  const enc = encrypt(JSON.stringify(json));
  const result = getDb()
    .prepare('UPDATE apps SET claude_credentials_encrypted = ? WHERE slug = ?')
    .run(enc, slug);
  if (result.changes === 0) throw new Error(`app ${slug} not found`);
  log.info(`claudeCredentials: stored for ${slug}`);
}

/** Wipe the stored credentials for an app. */
export function clearCredentials(slug) {
  getDb()
    .prepare('UPDATE apps SET claude_credentials_encrypted = NULL WHERE slug = ?')
    .run(slug);
  log.info(`claudeCredentials: cleared for ${slug}`);
}

/**
 * Prepare a per-call tmpfile holding the decrypted credentials. Returns:
 *   - { tmpFile, cleanup } when the app has credentials configured
 *   - null when the app has no credentials (caller should fall back to API key)
 *
 * The cleanup callback:
 *   1. Reads the tmpfile back. If the CLI inside the container refreshed
 *      the token, the file on disk now holds the new tokens.
 *   2. Re-encrypts and updates the DB so the next dispatch starts fresh.
 *   3. Wipes the tmpfile.
 *
 * Mounted r/w because Claude Code rewrites the file on token refresh.
 * The file stays on disk only for the duration of the dispatch.
 */
export function prepareClaudeCredentialsMount(appSlug) {
  if (!appSlug) return null;
  const row = getDb()
    .prepare('SELECT claude_credentials_encrypted FROM apps WHERE slug = ?')
    .get(appSlug);
  if (!row?.claude_credentials_encrypted) return null;

  let payload;
  try {
    payload = decrypt(row.claude_credentials_encrypted);
    JSON.parse(payload); // sanity — make sure it'll parse inside the container
  } catch (err) {
    log.warn(`claudeCredentials: stored credentials for ${appSlug} are unreadable, skipping mount: ${err.message}`);
    return null;
  }

  mkdirSync(tmpRoot(), { recursive: true });
  const tmpDir = join(tmpRoot(), randomUUID());
  mkdirSync(tmpDir, { mode: 0o700 });
  const tmpFile = join(tmpDir, 'credentials.json');
  writeFileSync(tmpFile, payload, { mode: 0o600 });

  return {
    tmpFile,
    cleanup: () => {
      try {
        // Capture refreshed token if the CLI rewrote the file.
        if (existsSync(tmpFile)) {
          const after = readFileSync(tmpFile, 'utf8');
          if (after && after !== payload) {
            try {
              const parsed = JSON.parse(after);
              validateCredentials(parsed);
              const enc = encrypt(after);
              getDb()
                .prepare('UPDATE apps SET claude_credentials_encrypted = ? WHERE slug = ?')
                .run(enc, appSlug);
              log.info(`claudeCredentials: captured refreshed token for ${appSlug}`);
            } catch (err) {
              log.warn(`claudeCredentials: refused to persist refreshed token for ${appSlug} (validation failed): ${err.message}`);
            }
          }
        }
      } finally {
        try { rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
      }
    },
  };
}
