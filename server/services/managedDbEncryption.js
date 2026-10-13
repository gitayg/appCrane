/**
 * "Encrypt MariaDB data at rest" for the shared managed MariaDB server — the
 * state, the key, the files and the server flags. managedDb.js runs them.
 *
 * Kept free of managedDb.js imports, like managedDbSettings.js, so the routes,
 * the boot hook and the tests can read the state without loading the engine.
 *
 * =========================================================================
 * WHAT IT PROTECTS, AND WHAT IT DOES NOT
 * =========================================================================
 * MariaDB's own data-at-rest encryption (InnoDB tablespaces, the redo log,
 * temporary tablespaces and files, Aria tables created while it is on) with
 * the file_key_management plugin. The key lives on the same host as the data,
 * so this protects copies of the data directory — a copied .ibd file, a tar of
 * DATA_DIR/managed-db/mariadb, a stray volume snapshot — and not someone who
 * holds the whole machine (disk encryption or a KMS covers that). Postgres has
 * no community equivalent (TDE exists only in forks), so this is MariaDB only.
 *
 * =========================================================================
 * WHERE THE KEY LIVES — THREE PLACES, NONE OF THEM THE DATA VOLUME
 * =========================================================================
 *   SQLite settings.managed_db_mariadb_encryption_key_enc
 *       The 256-bit key, ONLY through encryption.js encrypt(). The settings
 *       table is what deployhub.db, the config export (configMigration.js
 *       re-encrypts any value shaped like an encrypt() blob for the target
 *       instance's key), the local nightly and the off-site upload all carry,
 *       so every backup that can restore AppCrane can restore this key.
 *
 *   DATA_DIR/managed-db/_tde/mariadb/keys.enc   (dirs 0700, file 0600)
 *       The key file the plugin reads, ITSELF ENCRYPTED in the format the
 *       plugin's file_key_management_filekey option expects (OpenSSL `enc`
 *       AES-256-CBC, EVP_BytesToKey/SHA-1 — measured accepted by mariadb:11.4
 *       when written by wrapKeyFile below). Bind-mounted READ-ONLY into the
 *       MariaDB container only. A sibling of the data volume, never inside it,
 *       for the reason managedDb.envFileFor() gives: the volume is the
 *       database's own directory, the server can read anything in it for the
 *       life of the container, and on Linux it takes ownership of it.
 *
 *   The wrapping secret ("filekey")
 *       HMAC-SHA256(ENCRYPTION_KEY, fixed label) — derived, never stored. It
 *       reaches the container through the --env-file of the one `docker run`
 *       (the file is deleted right after, as the root password's is), and the
 *       start command writes it to a tmpfs inside the container and unsets it
 *       before the server starts, so it is in no file under DATA_DIR and not in
 *       mariadbd's environment. It IS in the container's config (`docker
 *       inspect`), exactly like MARIADB_ROOT_PASSWORD: reading that needs the
 *       docker socket, which is root-equivalent anyway.
 *
 * Why the extra wrapping is worth it: with a plaintext key file, a copy of
 * DATA_DIR (the volume AND the sibling _tde directory) decrypts on its own.
 * With the wrapped file, that copy also needs ENCRYPTION_KEY, which lives in
 * AppCrane's .env, outside DATA_DIR. It costs nothing at run time.
 *
 * CONSEQUENCE: ENCRYPTION_KEY is now required to read MariaDB data. Losing it
 * loses the key (SQLite copy) and the means to unwrap the key file.
 *
 * =========================================================================
 * THE STATE MACHINE (the server-side safety rule lives in unloadRefusal())
 * =========================================================================
 *   enabled  key_loaded   mode       the server runs with
 *   on       1            encrypt    plugin + every *_encrypt_* ON
 *   off      1            decrypt    plugin + every *_encrypt_* OFF (threads
 *                                    decrypt in the background)
 *   off      0            none       no plugin
 * The key is unloaded (key_loaded 0) ONLY by managedDb.unloadMariadbEncryptionKey,
 * ONLY when unloadRefusal() finds nothing encrypted, and deleted ONLY after
 * that (deleteKey() refuses while key_loaded is 1).
 */

import crypto from 'crypto';
import { join, resolve, relative, isAbsolute } from 'path';
import { mkdirSync, chmodSync, writeFileSync, renameSync, rmSync, existsSync } from 'fs';
import { encrypt, decrypt, deriveSecret } from './encryption.js';

export const SETTING_KEYS = {
  enabled: 'managed_db_mariadb_encryption',
  keyEnc: 'managed_db_mariadb_encryption_key_enc',
  keyLoaded: 'managed_db_mariadb_encryption_key_loaded',
};

/**
 * Every setting this module owns starts with this. routes/settings.js refuses
 * the generic PUT /api/settings/:key for them: overwriting the key row is data
 * loss, and writing key_loaded=0 directly would skip the safety rule.
 */
export const RESERVED_SETTING_PREFIX = 'managed_db_mariadb_encryption';

/** The only key id. innodb_default_encryption_key_id defaults to 1, and the
 *  server logs "Using encryption key id 1 for temporary files" (measured), so
 *  no key 2 is needed. */
export const KEY_ID = 1;

/** Read-only source inside the container (the host _tde/mariadb directory). */
export const KEY_MOUNT_PATH = '/etc/appcrane-tde';
/** tmpfs the start command copies into, owned by mysql. Never on disk. */
export const KEY_RUNTIME_PATH = '/run/appcrane-tde';
export const KEY_FILE = 'keys.enc';
export const FILEKEY_ENV = 'APPCRANE_TDE_FILEKEY';
const FILEKEY_LABEL = 'appcrane/managed-db/mariadb/file-key-management/filekey/v1';

/** The MariaDB data directory inside the container (managedDb ENGINES). */
const DATA_PATH = '/var/lib/mysql';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

function readRaw(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

function writeRaw(db, key, value, userId = null) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(key, value, userId);
}

/** { enabled, keyLoaded, keyExists }. Never decrypts. */
export function getState(db) {
  return {
    enabled: readRaw(db, SETTING_KEYS.enabled) === 'on',
    keyLoaded: readRaw(db, SETTING_KEYS.keyLoaded) === '1',
    keyExists: Boolean(readRaw(db, SETTING_KEYS.keyEnc)),
  };
}

/** 'encrypt' | 'decrypt' | 'none' — what the server is created with. */
export function modeFor(state) {
  if (!state.keyLoaded) return 'none';
  return state.enabled ? 'encrypt' : 'decrypt';
}

/**
 * The key, generated on first use and never regenerated while a row exists:
 * a second key would make everything encrypted with the first unreadable.
 * Returns true when this call created it.
 */
export function ensureKey(db, userId = null) {
  if (readRaw(db, SETTING_KEYS.keyEnc)) return false;
  writeRaw(db, SETTING_KEYS.keyEnc, encrypt(crypto.randomBytes(32).toString('hex')), userId);
  return true;
}

/** Turn ON: key (once), loaded, enabled — in that order, so a crash between
 *  writes never leaves "enabled" without a key. */
export function enable(db, userId = null) {
  const created = ensureKey(db, userId);
  writeRaw(db, SETTING_KEYS.keyLoaded, '1', userId);
  writeRaw(db, SETTING_KEYS.enabled, 'on', userId);
  return { keyCreated: created };
}

/** Turn OFF. The key STAYS loaded: decryption needs it. */
export function disable(db, userId = null) {
  writeRaw(db, SETTING_KEYS.enabled, 'off', userId);
}

export function markKeyLoaded(db, userId = null) {
  writeRaw(db, SETTING_KEYS.keyLoaded, '1', userId);
}

/** Only managedDb.unloadMariadbEncryptionKey calls this, after unloadRefusal(). */
export function markKeyUnloaded(db, userId = null) {
  if (getState(db).enabled) throw new Error('managedDbEncryption: refusing to unload the key while encryption is on');
  writeRaw(db, SETTING_KEYS.keyLoaded, '0', userId);
}

/** Delete the key row. Refused while the server still loads it. */
export function deleteKey(db) {
  const s = getState(db);
  if (s.enabled || s.keyLoaded) {
    throw new Error('managedDbEncryption: refusing to delete the MariaDB key while it is loaded (data may still be encrypted with it)');
  }
  db.prepare('DELETE FROM settings WHERE key = ?').run(SETTING_KEYS.keyEnc);
}

function keyHex(db) {
  const enc = readRaw(db, SETTING_KEYS.keyEnc);
  if (!enc) return null;
  const hex = decrypt(enc);
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('managedDbEncryption: stored MariaDB key is malformed');
  return hex;
}

// ---------------------------------------------------------------------------
// The key file
// ---------------------------------------------------------------------------

/** The wrapping secret. Derived from ENCRYPTION_KEY, never stored. */
export function fileKey() {
  return deriveSecret(FILEKEY_LABEL);
}

/**
 * A one-way tag of the wrapping secret for the container's config label: if
 * ENCRYPTION_KEY changes, keys.enc is rewritten under the new secret, and a
 * container still holding the old one in its environment must be recreated
 * rather than fail at its next restart.
 */
export function fileKeyFingerprint() {
  return crypto.createHash('sha256').update(`fp:${fileKey()}`).digest('hex').slice(0, 12);
}

// OpenSSL's EVP_BytesToKey with SHA-1, one round — what the plugin uses to
// turn file_key_management_filekey into an AES-256-CBC key and IV.
function bytesToKey(secret, salt) {
  let out = Buffer.alloc(0);
  let prev = Buffer.alloc(0);
  while (out.length < 48) {
    prev = crypto.createHash('sha1').update(Buffer.concat([prev, Buffer.from(secret, 'utf8'), salt])).digest();
    out = Buffer.concat([out, prev]);
  }
  return { key: out.subarray(0, 32), iv: out.subarray(32, 48) };
}

/** `openssl enc -aes-256-cbc -md sha1` output: "Salted__" + salt + ciphertext. */
export function wrapKeyFile(plain, secret) {
  const salt = crypto.randomBytes(8);
  const { key, iv } = bytesToKey(secret, salt);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([Buffer.from('Salted__'), salt, c.update(plain, 'utf8'), c.final()]);
}

export function unwrapKeyFile(buf, secret) {
  if (buf.subarray(0, 8).toString('latin1') !== 'Salted__') throw new Error('not a wrapped key file');
  const { key, iv } = bytesToKey(secret, buf.subarray(8, 16));
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString('utf8');
}

function managedDbRoot() {
  return join(resolve(process.env.DATA_DIR || './data'), 'managed-db');
}

/** The MariaDB data volume on the host (managedDb.dataDirFor('mariadb')). */
export function dataVolumeDir() {
  return join(managedDbRoot(), 'mariadb');
}

/** The host directory bind-mounted read-only. Not created here. */
export function keyDir() {
  return join(managedDbRoot(), '_tde', 'mariadb');
}

function privateDir(p) {
  mkdirSync(p, { recursive: true, mode: 0o700 });
  chmodSync(p, 0o700);
  return p;
}

/** True when `child` is `parent` or anywhere below it. */
export function isWithin(child, parent) {
  const rel = relative(resolve(parent), resolve(child));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Write keys.enc from the SQLite copy. Called before every create/start of
 * the MariaDB container and at AppCrane boot, so a restored host — deployhub.db
 * back, DATA_DIR/managed-db/_tde gone — has its key file again before MariaDB
 * is started. Throws when the key row is missing: starting the server without
 * it cannot work, and saying why beats InnoDB's own error.
 */
export function writeKeyFile(db) {
  const dir = keyDir();
  if (isWithin(dir, dataVolumeDir()) || isWithin(dataVolumeDir(), dir)) {
    throw new Error(`managedDbEncryption: the key directory ${dir} overlaps the MariaDB data volume; refusing`);
  }
  const hex = keyHex(db);
  if (!hex) {
    throw new Error('MariaDB encryption is in use but its key is missing from AppCrane\'s database. ' +
      'Restore deployhub.db from a backup taken while encryption was on (with the same ENCRYPTION_KEY); ' +
      'without that key the encrypted MariaDB data cannot be read.');
  }
  privateDir(join(managedDbRoot(), '_tde'));
  privateDir(dir);
  const path = join(dir, KEY_FILE);
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, wrapKeyFile(`${KEY_ID};${hex}\n`, fileKey()), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  return dir;
}

/** Remove the key FILE (the SQLite row is deleteKey()'s business). */
export function removeKeyFile() {
  rmSync(keyDir(), { recursive: true, force: true });
}

/** Boot hook: rewrite the key file when the server is meant to load it. */
export function syncKeyFileAtBoot(db) {
  const s = getState(db);
  if (modeFor(s) === 'none') return false;
  writeKeyFile(db);
  return true;
}

// ---------------------------------------------------------------------------
// The container
// ---------------------------------------------------------------------------

/** `docker run` arguments: the read-only key mount and the private tmpfs. */
export function runArgs(hostDir) {
  return [
    '-v', `${hostDir}:${KEY_MOUNT_PATH}:ro`,
    '--tmpfs', `${KEY_RUNTIME_PATH}:rw,noexec,nosuid,nodev,size=1m,mode=0700`,
  ];
}

/** The --env-file line carrying the wrapping secret (hex; no quoting needed). */
export function envFileLine() {
  return `${FILEKEY_ENV}=${fileKey()}\n`;
}

/**
 * Runs as root before the entrypoint drops to mysql: copy the wrapped key file
 * to the tmpfs, write the wrapping secret next to it from the environment,
 * hand both to mysql at 0600, and unset the variable so mariadbd never has it.
 * A copy rather than reading the mount for the reason managedDbTls.
 * installSnippet() gives: the bind mount carries the HOST owner and mode, and
 * a 0600 file owned by AppCrane's uid is unreadable to mysql (999) on Linux.
 *
 * A FIXED literal. The secret is read from the environment by the shell; it is
 * never part of this string or of any argv.
 */
export function installSnippet() {
  const R = KEY_RUNTIME_PATH;
  return `mkdir -p ${R} && cp ${KEY_MOUNT_PATH}/${KEY_FILE} ${R}/${KEY_FILE} && printf %s "$${FILEKEY_ENV}" > ${R}/filekey `
    + `&& unset ${FILEKEY_ENV} && chown -R mysql ${R} && chmod 700 ${R} && chmod 600 ${R}/${KEY_FILE} ${R}/filekey`;
}

/**
 * mariadbd flags for a mode. Option names checked against mariadb:11.4
 * (`mariadbd --plugin-load-add=file_key_management --verbose --help`).
 *
 *   --file-key-management=FORCE   the server refuses to start if the plugin
 *       cannot load (key file missing, wrong wrapping secret) instead of
 *       starting without a key and failing table by table.
 *   AES_CTR   supported by 11.4's plugin (the default is AES_CBC); the
 *       algorithm MariaDB's docs recommend.
 *   innodb_encryption_threads=4 + rotate_key_age=1   background threads that
 *       encrypt (or decrypt) EXISTING tablespaces; with rotate_key_age 0 they
 *       would leave existing tablespaces alone.
 *   encrypt_binlog is NOT set: the managed server runs without a binary log
 *       (measured: @@log_bin = 0), so there is nothing for it to encrypt.
 *
 * In decrypt mode the flags are the same with every *_encrypt_* OFF, and the
 * plugin stays loaded so the threads can read what they are decrypting.
 */
export function serverArgs(mode) {
  if (mode === 'none') return [];
  if (mode !== 'encrypt' && mode !== 'decrypt') throw new Error(`managedDbEncryption: bad mode ${JSON.stringify(mode)}`);
  const v = mode === 'encrypt' ? 'ON' : 'OFF';
  return [
    '--plugin-load-add=file_key_management',
    '--file-key-management=FORCE',
    `--file-key-management-filename=${KEY_RUNTIME_PATH}/${KEY_FILE}`,
    `--file-key-management-filekey=FILE:${KEY_RUNTIME_PATH}/filekey`,
    '--file-key-management-encryption-algorithm=AES_CTR',
    `--innodb-encrypt-tables=${v}`,
    `--innodb-encrypt-log=${v}`,
    `--innodb-encrypt-temporary-tables=${v}`,
    `--encrypt-tmp-files=${v}`,
    `--aria-encrypt-tables=${v}`,
    '--innodb-encryption-threads=4',
    '--innodb-encryption-rotate-key-age=1',
  ];
}

/**
 * Run once the server is up in decrypt mode. MEASURED on mariadb:11.4:
 * starting with --innodb-encrypt-tables=OFF does NOT make the threads decrypt
 * anything — every tablespace still read ENCRYPTION_SCHEME=1 a minute later —
 * while this statement, issued on the running server, had them all at 0
 * within seconds. (Starting with ON does encrypt existing tablespaces.)
 */
export const DECRYPT_KICK_SQL = 'SET GLOBAL innodb_encrypt_tables = OFF;';

// ---------------------------------------------------------------------------
// Progress and the safety rule
// ---------------------------------------------------------------------------

/**
 * Two statements, two one-row result sets: tablespace counts, then the live
 * settings. A tablespace counts as ENCRYPTED when every page carries a key
 * version (scheme 1, min key version >= 1, no rotation running), PLAIN when
 * none does (scheme 0, min key version 0, no rotation) — the two states
 * measured on 11.4 before and after the threads ran — and anything else is
 * mid-way and counts as neither.
 *
 * NOT one statement. MEASURED on mariadb:11.4: in an aggregate SELECT over
 * information_schema.INNODB_TABLESPACES_ENCRYPTION, `@@innodb_encrypt_log`
 * reads 0 while SHOW VARIABLES and a plain `SELECT @@innodb_encrypt_log` both
 * say ON — which would have made a server with its redo log still encrypted
 * look decrypted to the safety rule below.
 */
export const STATUS_SQL = [
  'SELECT COUNT(*),',
  ' COALESCE(SUM(ENCRYPTION_SCHEME <> 0 AND MIN_KEY_VERSION >= 1 AND ROTATING_OR_FLUSHING = 0), 0),',
  ' COALESCE(SUM(ENCRYPTION_SCHEME = 0 AND MIN_KEY_VERSION = 0 AND ROTATING_OR_FLUSHING = 0), 0)',
  ' FROM information_schema.INNODB_TABLESPACES_ENCRYPTION;',
  'SELECT @@innodb_encrypt_tables, @@innodb_encrypt_log, @@encrypt_tmp_files, @@aria_encrypt_tables,',
  " (SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'file_key_management' AND PLUGIN_STATUS = 'ACTIVE');",
].join('\n');

const on = (v) => v === '1' || /^(on|force)$/i.test(v);

/** Parse `mariadb --batch` output of STATUS_SQL: header, counts, header, settings. */
export function parseStatus(out) {
  const lines = String(out || '').trim().split('\n').filter(Boolean);
  const counts = lines[1]?.split('\t') || [];
  const live = lines[3]?.split('\t') || [];
  if (lines.length !== 4 || counts.length !== 3 || !counts.every(v => /^\d+$/.test(v)) || live.length !== 5) {
    throw new Error('managedDbEncryption: unexpected tablespace status output');
  }
  const [total, encrypted, plain] = counts.map(Number);
  return {
    total,
    encrypted,
    plain,
    in_progress: total - encrypted - plain,
    live: {
      innodb_encrypt_tables: live[0].toUpperCase(),
      innodb_encrypt_log: on(live[1]),
      encrypt_tmp_files: on(live[2]),
      aria_encrypt_tables: on(live[3]),
      plugin_active: live[4] !== '0',
    },
  };
}

/**
 * Aria has no information_schema view of its encryption, and an Aria table
 * created while encryption was on STAYS encrypted after it is turned off
 * (measured: with the plugin removed, SELECT on it fails with "ERROR 199 ...
 * Initialization of encryption failed"). The engine's own aria_chk, which
 * loads no key plugin, says exactly that about an encrypted table and
 * describes a plain one. Run from /tmp so it does not wait 30 s per file on
 * the live server's aria_log_control lock. A table aria_chk cannot describe
 * for any OTHER reason is reported as UNREADABLE and also blocks unloading:
 * unknown is not plain. A FIXED literal.
 */
export const ARIA_SCAN_SNIPPET = `cd /tmp && find ${DATA_PATH} -name '*.MAI' | while IFS= read -r f; do `
  + `out=$(aria_chk -d --read-only "$f" 2>&1); rc=$?; `
  + `case "$out" in *'Initialization of encryption failed'*) printf 'ENCRYPTED %s\\n' "$f";; `
  + `*) [ "$rc" -eq 0 ] || printf 'UNREADABLE %s\\n' "$f";; esac; done; echo ARIA_SCAN_DONE`;

export function parseAriaScan(out) {
  const lines = String(out || '').split('\n').map(l => l.trim()).filter(Boolean);
  return {
    complete: lines.includes('ARIA_SCAN_DONE'),
    encrypted: lines.filter(l => l.startsWith('ENCRYPTED ')).map(l => l.slice(10)),
    unreadable: lines.filter(l => l.startsWith('UNREADABLE ')).map(l => l.slice(11)),
  };
}

/**
 * ALTER TABLE ... ENGINE=Aria for each encrypted Aria file — a rebuild, which
 * under aria_encrypt_tables=OFF writes the table unencrypted (measured on
 * 11.4, including every mysql.* system table of a server that was initialised
 * with encryption on: after the rebuild aria_chk described them all and the
 * server started without the plugin). Only for paths whose database and table
 * directory names are plain identifiers, which is what lets them go into SQL:
 * MariaDB encodes any other character in a file name (@00xx), and those are
 * left for unloadRefusal() to report rather than guessed at.
 */
const ARIA_FILE = new RegExp(`^${DATA_PATH}/([A-Za-z0-9_]{1,64})/([A-Za-z0-9_]{1,64})\\.MAI$`);
export function ariaRebuildSql(paths) {
  const sql = [];
  const skipped = [];
  for (const p of paths) {
    const m = ARIA_FILE.exec(p);
    if (m) sql.push(`ALTER TABLE \`${m[1]}\`.\`${m[2]}\` ENGINE=Aria;`);
    else skipped.push(p);
  }
  return { sql, skipped };
}

/**
 * THE SAFETY RULE. Null when the key may be unloaded; otherwise the reason it
 * may not. Everything here must be TRUE of the RUNNING server, measured just
 * now — not inferred from settings:
 *   - encryption is off in AppCrane's state
 *   - the running server has the plugin (so what it reports is real) and
 *     every *_encrypt_* setting off, i.e. it was restarted in decrypt mode,
 *     which is also what rewrote the redo log without encryption
 *   - every InnoDB tablespace is plain
 *   - no Aria table is encrypted, and none is of unknown state
 */
export function unloadRefusal({ state, status, aria }) {
  if (state.enabled) return 'Encryption is on. Turn it off first and wait for decryption to finish.';
  if (!status) return 'The MariaDB server is not running, so AppCrane cannot check that nothing is still encrypted.';
  const l = status.live;
  if (!l.plugin_active) return 'The running MariaDB server does not have the key plugin loaded, so its encryption state cannot be checked.';
  if (l.innodb_encrypt_tables !== 'OFF' || l.innodb_encrypt_log || l.encrypt_tmp_files || l.aria_encrypt_tables) {
    return 'The running MariaDB server still has encryption settings on; it has not been restarted with encryption off yet.';
  }
  if (status.total === 0) return 'MariaDB reported no InnoDB tablespaces, so AppCrane cannot confirm they are decrypted.';
  if (status.plain !== status.total) {
    return `${status.total - status.plain} of ${status.total} InnoDB tablespaces are still encrypted or being decrypted. `
      + 'Background decryption normally finishes within minutes; a table created with ENCRYPTED=YES is never decrypted in the background '
      + 'and needs ALTER TABLE ... ENCRYPTED=NO first.';
  }
  if (!aria || !aria.complete) return 'The check of Aria tables did not complete, so AppCrane cannot confirm they are unencrypted.';
  if (aria.encrypted.length) {
    return `${aria.encrypted.length} Aria table(s) are encrypted (${aria.encrypted.slice(0, 5).join(', ')}). `
      + 'Aria does not decrypt in the background and AppCrane could not rebuild these: rebuild each with ALTER TABLE ... ENGINE=Aria while encryption is off, then retry.';
  }
  if (aria.unreadable.length) {
    return `aria_chk could not describe ${aria.unreadable.length} Aria table(s) (${aria.unreadable.slice(0, 5).join(', ')}), so they may be encrypted.`;
  }
  return null;
}

/** What the settings card shows. `status` null = server not running/never created. */
export function phaseFor(state, status) {
  const mode = modeFor(state);
  if (mode === 'none') return 'off';
  if (mode === 'encrypt') return status && status.total > 0 && status.encrypted === status.total ? 'on' : 'encrypting';
  return status && status.total > 0 && status.plain === status.total ? 'decrypted' : 'decrypting';
}

/** Shown next to the switch (operator-approved wording). */
export const CAVEAT = 'The key is stored on the same server as the data. This protects copied database files, '
  + 'dumps of the data volume and stray snapshots, not someone holding the whole disk; disk encryption or a KMS covers that.';
