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

import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, chmodSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';

function tmpRoot() {
  return resolve(process.env.DATA_DIR || './data', 'claude-credentials-tmp');
}

/**
 * Pull the OAuth fields from a credentials.json regardless of which
 * Claude Code release wrote it. Two shapes seen in the wild:
 *   1. Legacy / API-key style — fields at the top level in snake_case:
 *        { access_token, refresh_token, expires_at, accountUuid }
 *   2. Current `claude login` output — wrapped in `claudeAiOauth` with
 *        camelCase fields:
 *        { claudeAiOauth: { accessToken, refreshToken, expiresAt, scopes, ... } }
 *
 * Returns the normalized fields (always snake_case), or { access_token: '' }
 * if neither shape is recognized so validateCredentials can give a clean
 * error.
 */
function extractTokens(json) {
  if (!json || typeof json !== 'object') return {};
  const oauth = json.claudeAiOauth && typeof json.claudeAiOauth === 'object' ? json.claudeAiOauth : null;
  return {
    access_token:  json.access_token  || oauth?.accessToken  || '',
    refresh_token: json.refresh_token || oauth?.refreshToken || '',
    expires_at:    json.expires_at    || oauth?.expiresAt    || null,
    account_uuid:  json.accountUuid   || json.account_uuid   || oauth?.accountUuid || null,
  };
}

/**
 * Validate a credentials.json payload before storing. Accepts both the
 * legacy top-level snake_case shape and the current `claudeAiOauth`
 * wrapped/camelCase shape — see extractTokens for the conversion. Throws
 * on anything that doesn't carry both an access + refresh token so we
 * don't persist garbage that'd break dispatches later.
 *
 * The file is round-tripped to the container as-is (we don't rewrite the
 * shape on disk), so Claude Code inside the container reads exactly
 * what was uploaded.
 */
export function validateCredentials(json) {
  if (!json || typeof json !== 'object') throw new Error('credentials must be a JSON object');
  const t = extractTokens(json);
  if (typeof t.access_token !== 'string' || !t.access_token.length) {
    throw new Error('credentials.json missing access_token (or claudeAiOauth.accessToken)');
  }
  if (typeof t.refresh_token !== 'string' || !t.refresh_token.length) {
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
  const t = extractTokens(parsed);
  return {
    present: true,
    expiresAt: t.expires_at,
    accountUuid: t.account_uuid,
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

// ── several holders of one login ───────────────────────────────────────────
//
// One app's login can be held by several copies at once: the long-lived app
// container's (builder/appContainer.js, for as long as it lives) and one per
// per-turn container (a Crew coder turn, Improve, Ask). Claude Code refreshes
// the token in whichever container hits expiry, rewrites its own copy, and the
// refresh rotates the refresh token, so the old one is dead from then on.
// Before v2.131.0 every copy was written back blindly when its holder ended:
// the app container kept a refresh token another holder had rotated out, a
// turn started from a DB the app container had not written yet, and a holder
// ending later wrote an older login over a newer one.
//
// So every live copy is tracked with the stored blob and text it last agreed
// with. A copy its CLI changed is stored only if the DB still holds what the
// copy started from (compare-and-swap on the ciphertext) or the copy expires
// later than what is stored now; then every unchanged or older copy is
// rewritten in place (same inode, so the bind mount sees it) with the stored
// login. This runs whenever a copy is taken or handed back, and at each app
// coder turn boundary (syncClaudeCredentials).
const liveCopies = new Map(); // slug -> Set<{ tmpFile, blob, text }>

function storedBlob(slug) {
  return getDb()
    .prepare('SELECT claude_credentials_encrypted FROM apps WHERE slug = ?')
    .get(slug)?.claude_credentials_encrypted || null;
}

function expiresOf(text) {
  try { return Number(extractTokens(JSON.parse(text)).expires_at) || 0; } catch (_) { return 0; }
}

function readCopy(copy) {
  try { return existsSync(copy.tmpFile) ? readFileSync(copy.tmpFile, 'utf8') : null; } catch (_) { return null; }
}

function pushCopy(slug, copy) {
  const after = readCopy(copy);
  if (!after || after === copy.text) return;
  try {
    validateCredentials(JSON.parse(after));
  } catch (err) {
    log.warn(`claudeCredentials: refused to persist refreshed token for ${slug} (validation failed): ${err.message}`);
    return;
  }
  const blob = storedBlob(slug);
  // Cleared by the operator while held: a running copy does not bring it back.
  if (!blob) return;
  if (blob !== copy.blob) {
    let current = null;
    try { current = decrypt(blob); } catch (_) {}
    if (current !== null && expiresOf(after) <= expiresOf(current)) return;
  }
  const enc = encrypt(after);
  const r = getDb()
    .prepare('UPDATE apps SET claude_credentials_encrypted = ? WHERE slug = ? AND claude_credentials_encrypted = ?')
    .run(enc, slug, blob);
  if (r.changes) {
    copy.blob = enc;
    copy.text = after;
    log.info(`claudeCredentials: captured refreshed token for ${slug}`);
  }
}

function pullCopy(slug, copy) {
  const blob = storedBlob(slug);
  if (!blob || blob === copy.blob) return;
  let text;
  try { text = decrypt(blob); JSON.parse(text); } catch (_) { return; }
  const file = readCopy(copy);
  if (file === null) return;
  if (file !== copy.text && expiresOf(file) > expiresOf(text)) return;
  try {
    if (file !== text) writeFileSync(copy.tmpFile, text);
    copy.blob = blob;
    copy.text = text;
  } catch (err) {
    log.warn(`claudeCredentials: could not hand the current login to a live copy for ${slug}: ${err.message}`);
  }
}

/**
 * Reconcile every live copy of `slug`'s login with the DB: store the newest
 * rotation, then hand it to every copy still holding an older one.
 */
export function syncClaudeCredentials(slug) {
  const copies = liveCopies.get(slug);
  if (!copies?.size) return;
  try {
    for (const c of copies) pushCopy(slug, c);
    for (const c of copies) pullCopy(slug, c);
  } catch (err) {
    log.warn(`claudeCredentials: sync failed for ${slug}: ${err.message}`);
  }
}

/**
 * Prepare a per-call tmpfile holding the decrypted credentials. Returns:
 *   - { tmpFile, cleanup } when the app has credentials configured
 *   - null when the app has no credentials (caller should fall back to API key)
 *
 * The copy starts from the newest login any live copy holds (see above). The
 * cleanup callback stores this copy's refresh if it is the newest, hands it
 * to the other live copies, and wipes the tmpfile.
 *
 * Mounted r/w because Claude Code rewrites the file on token refresh.
 * The file stays on disk only for the duration of the dispatch.
 */
export function prepareClaudeCredentialsMount(appSlug) {
  if (!appSlug) return null;
  syncClaudeCredentials(appSlug);
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
  // 0o755 dir + 0o666 file (not chown) because the studio image's
  // `studio` user is created via Alpine's `adduser -S` which picks an
  // arbitrary system UID — usually NOT 1000 — so a chown to a hard-coded
  // UID misses. World-rw is acceptable here: host file is root-owned in
  // /var/lib/appcrane/... where only AppCrane runs, and the container is
  // isolated; only reader is the dispatched Claude CLI inside.
  //
  // CRITICAL: writeFileSync's `mode` is masked by the process umask
  // (default 022 → 0o666 becomes 0o644). The container's `studio` user
  // is "others" relative to root and gets read-only — Claude CLI then
  // fails to refresh the token (write) and surfaces as "Not logged in".
  // chmodSync bypasses umask. Same for the dir.
  mkdirSync(tmpDir, { mode: 0o755 });
  chmodSync(tmpDir, 0o755);
  const tmpFile = join(tmpDir, 'credentials.json');
  writeFileSync(tmpFile, payload, { mode: 0o666 });
  chmodSync(tmpFile, 0o666);

  const copy = { tmpFile, blob: row.claude_credentials_encrypted, text: payload };
  if (!liveCopies.has(appSlug)) liveCopies.set(appSlug, new Set());
  liveCopies.get(appSlug).add(copy);

  return {
    tmpFile,
    cleanup: () => {
      const copies = liveCopies.get(appSlug);
      try {
        // Capture refreshed token if the CLI rewrote the file.
        pushCopy(appSlug, copy);
      } finally {
        copies?.delete(copy);
        if (copies && !copies.size) liveCopies.delete(appSlug);
        try { rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
        syncClaudeCredentials(appSlug);
      }
    },
  };
}
