/**
 * The backup recovery key (v2.145.0): the ENCRYPTION_KEY that platform
 * backups no longer carry, handed to a platform admin so it can be kept
 * somewhere other than this host and its backup bucket.
 *
 * Only the fingerprint, the time and the person are stored here, so Settings >
 * Backup can say whether the current key has ever been taken off the host.
 */
import { getDb } from '../db.js';
import { keyFingerprint, liveKeyHex, shortFingerprint } from './backupCrypto.js';

const K = {
  at: 'backup_recovery_key_downloaded_at',
  by: 'backup_recovery_key_downloaded_by',
  fp: 'backup_recovery_key_downloaded_fp',
  history: 'backup_key_fingerprint_history',
};
const HISTORY_LIMIT = 20;

export const LOSS_WARNING = 'Platform backups do not contain this key. If it is lost along with this host, every platform backup is unrestorable: '
  + 'keep this file somewhere other than this host and its backup bucket (a password manager or an offline copy).';

function get(db, k) { return db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value || null; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v ?? ''), userId ?? null);
}

function readHistory(db) {
  try { const v = JSON.parse(get(db, K.history) || '[]'); return Array.isArray(v) ? v : []; } catch (_) { return []; }
}

/**
 * Remember every key fingerprint this server has run under, with when it was
 * first seen and when (if ever) its recovery key was downloaded. After
 * `crane rotate-key` (any of its paths) or a hand edit of .env, the first check
 * on the next start records the new key, so the previous key's fingerprint and
 * its active period stay on record for restoring older keyless archives.
 * Fingerprints only; never a key.
 */
export function noteKeyFingerprint(db = getDb(), now = new Date(), { downloaded = false } = {}) {
  const fp = keyFingerprint(liveKeyHex());
  if (!fp) return readHistory(db);
  const list = readHistory(db);
  let cur = list.find((e) => e.fingerprint === fp);
  const before = JSON.stringify(list);
  if (!cur) { cur = { fingerprint: fp, first_seen: now.toISOString(), downloaded_at: null }; list.push(cur); }
  if (downloaded) cur.downloaded_at = now.toISOString();
  const kept = list.slice(-HISTORY_LIMIT);
  if (JSON.stringify(kept) !== before) set(db, K.history, JSON.stringify(kept), null);
  return kept;
}

/** Earlier keys of this host, newest first, each with the time it was replaced. */
export function previousKeys(db = getDb()) {
  const fp = keyFingerprint(liveKeyHex());
  const list = readHistory(db);
  return list.map((e, i) => ({
    fingerprint: shortFingerprint(e.fingerprint), first_seen: e.first_seen,
    replaced_at: list[i + 1]?.first_seen ?? null, downloaded_at: e.downloaded_at ?? null, full: e.fingerprint,
  })).filter((e) => e.full !== fp).reverse().map(({ full, ...rest }) => rest);
}

/** A sentence about a fingerprint this host once ran under, or '' when it never did. */
export function describeKnownKey(fingerprint, db = getDb()) {
  const list = readHistory(db);
  const i = list.findIndex((e) => e.fingerprint === fingerprint);
  if (i < 0) return '';
  const until = list[i + 1]?.first_seen;
  const dl = list[i].downloaded_at ? `its recovery key was downloaded at ${list[i].downloaded_at}` : 'its recovery key was never downloaded from this server';
  return `That key was this host's key from ${list[i].first_seen}${until ? ` until ${until}` : ''}; ${dl}.`;
}

export const RECOVERY_KEY_NOT_DOWNLOADED = 'The backup recovery key for the current ENCRYPTION_KEY has not been downloaded. '
  + 'Platform backups do not contain it, so if this host is lost they cannot be restored. '
  + 'Download it in Settings > Backup > Backup recovery key and keep it away from this host and its bucket.';

/** What Settings > Backup shows. Never the key. */
export function recoveryKeyStatus(db = getDb()) {
  const fp = keyFingerprint(liveKeyHex());
  const lastFp = get(db, K.fp);
  const byId = parseInt(get(db, K.by) || '', 10);
  const by = Number.isFinite(byId) ? db.prepare('SELECT id, username, name FROM users WHERE id = ?').get(byId) || null : null;
  return {
    available: !!fp,
    fingerprint: shortFingerprint(fp),
    downloaded_at: lastFp === fp ? get(db, K.at) : null,
    downloaded_by: lastFp === fp && by ? (by.name || by.username || `user ${by.id}`) : null,
    downloaded_for_current_key: !!fp && lastFp === fp,
    warning: LOSS_WARNING,
    previous_keys: previousKeys(db),
  };
}

/** The key and the file text that carries it; records who took it. Throws 409 when no key is loaded. */
export function issueRecoveryKey(userId, { db = getDb(), now = new Date() } = {}) {
  const key = liveKeyHex();
  if (!key) throw Object.assign(new Error('This process has no ENCRYPTION_KEY loaded, so there is no recovery key to download.'), { status: 409, code: 'NO_KEY' });
  const fp = keyFingerprint(key);
  const host = (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '') || 'appcrane';
  const text = [
    '# AppCrane backup recovery key',
    `# Host: ${host}`,
    `# Fingerprint: ${fp}`,
    `# Downloaded: ${now.toISOString()}`,
    '#',
    `# ${LOSS_WARNING}`,
    '# To restore a platform backup on a new host, put this line in its .env before',
    '# the first start, or paste the value into Settings > Backup > Import.',
    `ENCRYPTION_KEY=${key}`,
    '',
  ].join('\n');
  set(db, K.at, now.toISOString(), userId);
  set(db, K.by, String(userId), userId);
  set(db, K.fp, fp, userId);
  noteKeyFingerprint(db, now, { downloaded: true });
  return { key, fingerprint: fp, file_name: `appcrane-recovery-key-${host}-${fp.slice(0, 12)}.txt`, file_text: text };
}
