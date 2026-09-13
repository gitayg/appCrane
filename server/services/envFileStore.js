/**
 * .env files that a Crane-hosted app keeps OUTSIDE its git repository.
 *
 * capture: at upload conversion, read each .env* entry of a release (never
 *          following a symlink out of the release) so uploadConversion.js can
 *          store it encrypted in app_env_files (migration 095).
 * restore: at deploy, write this environment's stored files back into the fresh
 *          clone, before the build, with this environment's env vars layered on
 *          (the stored file is the base; see restoreStoredEnvFiles). Called from deployer.js right after the
 *          local-repo clone/pin.
 *
 * Paths are the one thing either side trusts from storage, so both sides use
 * the same rule (assertEnvRelPath): relative, no empty / "." / ".." segment, no
 * ".git" component, no backslash or NUL, and the last segment must be a .env*
 * name. restore additionally refuses a parent that is a symlink or not a
 * directory, and a destination that exists as anything but a regular file, and
 * opens the file with O_NOFOLLOW.
 *
 * Contents never leave this module except encrypted (capture returns them to the
 * caller for encryption) or into the release file itself. Errors and return
 * values carry paths only.
 */

import {
  closeSync, constants, fchmodSync, lstatSync, mkdirSync, openSync, realpathSync, statSync, writeSync,
} from 'fs';
import { join, sep } from 'path';
import { decrypt, encrypt } from './encryption.js';
import { readNoFollow } from './uploadConversionScan.js';
import { APPEND_KEY_RE, appendDotenvText, isLoadableEnvName, mergeDotenvText } from './dotenvMerge.js';

export const ENV_FILE_MAX_BYTES = 1024 * 1024;
export const ENVS = ['production', 'sandbox'];

export function isEnvFileName(name) {
  return typeof name === 'string' && name.startsWith('.env');
}

function refused(relPath, why) {
  return Object.assign(new Error(`refusing stored env file path ${JSON.stringify(relPath)}: ${why}`), { code: 'ENV_FILE_PATH_REFUSED' });
}

/** Validate a stored relative path; returns its segments. */
export function assertEnvRelPath(relPath) {
  if (typeof relPath !== 'string' || relPath.length === 0 || relPath.length > 1024) throw refused(relPath, 'empty or too long');
  if (relPath.includes('\0') || relPath.includes('\\')) throw refused(relPath, 'NUL or backslash');
  if (relPath.startsWith('/')) throw refused(relPath, 'absolute');
  const segs = relPath.split('/');
  for (const s of segs) {
    if (s === '' || s === '.' || s === '..') throw refused(relPath, 'empty, "." or ".." segment');
    if (s.toLowerCase() === '.git') throw refused(relPath, '.git component');
  }
  if (!isEnvFileName(segs[segs.length - 1])) throw refused(relPath, 'not a .env file name');
  return segs;
}

/**
 * Read the .env* entries a scan found in a release.
 *
 * `envFiles` is scanRelease(...).envFiles. Returns
 *   { files: [{ rel_path, mode, bytes, content: Buffer }], warnings: [{ path, reason }], tooLarge: [path] }
 *
 * A symlinked .env file is stored with its TARGET's content and mode, at the
 * symlink's own path, only when the target resolves inside the release. One
 * pointing outside is not read (warning env_symlink_outside_release): that is
 * what promote leaves in a production release, `.env` -> <shared>/.env.production,
 * a file promote generates from production's own env_vars, which the deploy
 * already injects into the container.
 */
export function captureEnvFiles(root, envFiles) {
  const files = [];
  const warnings = [];
  const tooLarge = [];
  const rootReal = realpathSync(root);
  for (const f of envFiles) {
    try { assertEnvRelPath(f.path); } catch (_) { warnings.push({ path: f.path, reason: 'env_path_not_storable' }); continue; }
    const abs = join(root, f.path);
    const st = lstatSync(abs);
    let readFrom = abs;
    let mode = st.mode & 0o777;
    if (st.isDirectory()) { warnings.push({ path: f.path, reason: 'env_directory_not_kept' }); continue; }
    if (st.isSymbolicLink()) {
      let real;
      try { real = realpathSync(abs); } catch (_) { warnings.push({ path: f.path, reason: 'env_symlink_dangling' }); continue; }
      if (!real.startsWith(rootReal + sep)) { warnings.push({ path: f.path, reason: 'env_symlink_outside_release' }); continue; }
      const tst = statSync(real);
      if (!tst.isFile()) { warnings.push({ path: f.path, reason: 'env_symlink_not_a_file' }); continue; }
      readFrom = real;
      mode = tst.mode & 0o777;
    } else if (!st.isFile()) {
      warnings.push({ path: f.path, reason: 'env_not_a_file' });
      continue;
    }
    let content;
    try {
      content = readNoFollow(readFrom, ENV_FILE_MAX_BYTES);
    } catch (e) {
      if (e.code === 'FILE_TOO_LARGE') { tooLarge.push(f.path); continue; }
      throw e;
    }
    files.push({ rel_path: f.path, mode, bytes: content.length, content });
  }
  return { files, warnings, tooLarge };
}

/** Encrypt captured files for storage. The Buffer is base64'd so any bytes round-trip. */
export function encryptEnvFiles(files) {
  return files.map((f) => ({ rel_path: f.rel_path, mode: f.mode, bytes: f.bytes, content_encrypted: encrypt(f.content.toString('base64')) }));
}

export function storeEnvFiles(db, appId, env, encryptedFiles) {
  if (!ENVS.includes(env)) throw new Error(`invalid env ${JSON.stringify(env)}`);
  const up = db.prepare(`
    INSERT INTO app_env_files (app_id, env, rel_path, mode, bytes, content_encrypted)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(app_id, env, rel_path) DO UPDATE SET
      mode = excluded.mode, bytes = excluded.bytes, content_encrypted = excluded.content_encrypted, updated_at = datetime('now')
  `);
  for (const f of encryptedFiles) {
    assertEnvRelPath(f.rel_path);
    up.run(appId, env, f.rel_path, f.mode & 0o777, f.bytes, f.content_encrypted);
  }
}

/** Stored paths per env, for status output. Paths only. */
export function storedEnvFilePaths(db, appId) {
  const out = { production: [], sandbox: [] };
  for (const r of db.prepare('SELECT env, rel_path FROM app_env_files WHERE app_id = ? ORDER BY env, rel_path').all(appId)) out[r.env].push(r.rel_path);
  return out;
}

/** This environment's env vars, decrypted. Keys that fail to decrypt are returned by name, never applied. */
function envVarsFor(db, appId, env) {
  const vars = new Map();
  const undecryptable = [];
  for (const r of db.prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ? ORDER BY key').all(appId, env)) {
    try { vars.set(r.key, decrypt(r.value_encrypted)); } catch (_) { undecryptable.push(r.key); }
  }
  return { vars, undecryptable };
}

/**
 * Write this environment's stored .env files into `releaseDir`, with this
 * environment's AppCrane env vars layered on (dotenvMerge.js):
 *   - OVERRIDE: in every loadable file (LOADABLE_ENV_NAMES, root or nested) a
 *     key that is also an env var takes the env var's value; only that
 *     assignment is rewritten. Example/sample/template and other names are
 *     written exactly as stored.
 *   - APPEND: env vars that no ROOT-level loadable file defines are appended to
 *     the root .env only, never to a nested file. When no root .env is stored,
 *     the clone's own regular .env (if the repository has one) is the base, else
 *     a new one is created with mode 0600. Nothing is created for an app with no
 *     stored files: this function returns before reading env vars.
 * app_env_files is never written; the merge exists only in this release copy,
 * so an env var edited or deleted in AppCrane changes the next deploy's file.
 *
 * Returns { files: [{ path, overridden, appended, unrepresentable, created, not_merged }], undecryptable }.
 * Key names and paths only. Throws ENV_FILE_PATH_REFUSED before writing a file
 * whose path or parents are unsafe.
 */
export function restoreStoredEnvFiles(db, app, env, releaseDir) {
  if (!ENVS.includes(env)) throw new Error(`invalid env ${JSON.stringify(env)}`);
  const rows = db.prepare('SELECT rel_path, mode, content_encrypted FROM app_env_files WHERE app_id = ? AND env = ? ORDER BY rel_path').all(app.id, env);
  if (rows.length === 0) return { files: [], undecryptable: [] };
  const rootReal = realpathSync(releaseDir);

  const files = rows.map((row) => {
    const segs = assertEnvRelPath(row.rel_path);
    const mode = Number(row.mode);
    if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) throw refused(row.rel_path, 'invalid mode');
    return { rel_path: row.rel_path, segs, mode, content: Buffer.from(decrypt(row.content_encrypted), 'base64') };
  });

  if (!files.some((f) => f.rel_path === '.env')) {
    const existing = join(rootReal, '.env');
    let st = null;
    try { st = lstatSync(existing); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (st && st.isFile()) files.push({ rel_path: '.env', segs: ['.env'], mode: st.mode & 0o777, content: readNoFollow(existing, ENV_FILE_MAX_BYTES), fromRelease: true });
  }

  const { vars, undecryptable } = envVarsFor(db, app.id, env);
  const rootDefined = new Set();
  for (const f of files) {
    f.info = { path: f.rel_path, overridden: [], appended: [], unrepresentable: [], created: false, not_merged: null };
    if (!isLoadableEnvName(f.segs[f.segs.length - 1])) continue;
    const text = f.content.toString('utf8');
    const merged = mergeDotenvText(text, vars);
    if (f.segs.length === 1) for (const k of merged.defined) rootDefined.add(k);
    if (!Buffer.from(text, 'utf8').equals(f.content)) { f.info.not_merged = 'not_utf8'; continue; }
    if (merged.parseError) { f.info.not_merged = 'parse_error'; continue; }
    f.content = Buffer.from(merged.text, 'utf8');
    f.info.overridden = merged.overridden;
    f.info.unrepresentable = merged.unrepresentable;
  }

  const toAppend = [...vars].filter(([k]) => APPEND_KEY_RE.test(k) && !rootDefined.has(k)).sort(([a], [b]) => (a < b ? -1 : 1));
  if (toAppend.length) {
    let root = files.find((f) => f.rel_path === '.env');
    if (!root) {
      root = { rel_path: '.env', segs: ['.env'], mode: 0o600, content: Buffer.alloc(0) };
      root.info = { path: '.env', overridden: [], appended: [], unrepresentable: [], created: true, not_merged: null };
      files.push(root);
    }
    if (root.info.not_merged) {
      root.info.append_skipped = root.info.not_merged;
    } else {
      const a = appendDotenvText(root.content.toString('utf8'), toAppend);
      root.content = Buffer.from(a.text, 'utf8');
      root.info.appended = a.appended;
      root.info.unrepresentable.push(...a.unrepresentable);
    }
  }

  const out = [];
  for (const f of files) {
    if (f.fromRelease && !f.info.overridden.length && !f.info.appended.length) continue;
    let dir = rootReal;
    for (const seg of f.segs.slice(0, -1)) {
      dir = join(dir, seg);
      let st;
      try {
        st = lstatSync(dir);
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
        mkdirSync(dir, { mode: 0o755 });
        st = lstatSync(dir);
      }
      if (st.isSymbolicLink() || !st.isDirectory()) throw refused(f.rel_path, `parent ${JSON.stringify(seg)} is a symlink or not a directory`);
    }
    const target = join(dir, f.segs[f.segs.length - 1]);
    try {
      if (!lstatSync(target).isFile()) throw refused(f.rel_path, 'destination exists and is not a regular file');
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW || 0), f.mode);
    try {
      let off = 0;
      while (off < f.content.length) off += writeSync(fd, f.content, off, f.content.length - off);
      fchmodSync(fd, f.mode);
    } finally {
      closeSync(fd);
    }
    out.push(f.info);
  }
  return { files: out, undecryptable };
}

/** One deploy-log line: paths and key NAMES only. */
export function describeRestoredEnvFiles({ files, undecryptable }) {
  const parts = files.map((i) => {
    const notes = [];
    if (i.created) notes.push('created');
    if (i.overridden.length) notes.push(`overridden: ${i.overridden.join(', ')}`);
    if (i.appended.length) notes.push(`appended: ${i.appended.join(', ')}`);
    if (i.unrepresentable.length) notes.push(`not written, no exact dotenv quoting: ${i.unrepresentable.join(', ')}`);
    if (i.not_merged) notes.push(`env vars not layered: ${i.not_merged}`);
    return notes.length ? `${i.path} (${notes.join('; ')})` : i.path;
  });
  let line = `Restored ${files.length} stored .env file(s) into the release, outside the repository: ${parts.join(', ')}`;
  if (undecryptable.length) line += `. Env vars not layered (could not decrypt): ${undecryptable.join(', ')}`;
  return line;
}
