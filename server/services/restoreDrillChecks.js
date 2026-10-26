import { join, resolve, sep } from 'path';
import { mkdir, readFile, readdir, stat } from 'fs/promises';
import { existsSync } from 'fs';
import { createHash } from 'crypto';
import { execFile } from 'child_process';
import Database from 'better-sqlite3';
import { extractTar, sha256File, readHead } from './backupFiles.js';
import { runRepoTask, REPO_MANIFEST, REPO_BUNDLE } from './repoArchive.js';
import { MANIFEST } from './configBackup.js';
import { decrypt } from './encryption.js';

// The checks a restore drill runs against a backup restored into its scratch
// directory. Every function here reads only below the scratch path it is
// given (and the live database through the read handle the caller passes for
// the row-count comparison); none writes outside the scratch path.

export const KEY_TABLES = ['users', 'apps', 'settings', 'env_vars', 'deployments', 'managed_databases', 'app_user_roles'];
const ENGINES = ['postgres', 'mariadb', 'mongo', 'redis'];
const DUMP_RE = /^[a-z][a-z0-9_]{0,62}\.dump$/;

export const check = (id, label, status, detail = null) => ({ id, label, status, detail });

const sha = (s) => createHash('sha256').update(String(s)).digest('hex');

/** Refuse any path that is not strictly inside `root`. */
export function assertInside(root, p) {
  const r = resolve(root);
  const abs = resolve(p);
  if (abs !== r && !abs.startsWith(r + sep)) throw new Error('path escapes the drill scratch area');
  return abs;
}

export async function extractInto(archive, dest, { gzip }) {
  await mkdir(dest, { recursive: true, mode: 0o700 });
  try {
    await extractTar(archive, dest, { gzip });
    return check('archive_extract', 'Archive extracts', 'pass');
  } catch (e) {
    return check('archive_extract', 'Archive extracts', 'fail', String(e.message).slice(0, 300));
  }
}

function envKey(text) {
  const m = /^\s*(?:export\s+)?ENCRYPTION_KEY\s*=\s*["']?([0-9a-fA-F]{32,})["']?\s*$/m.exec(text);
  return m ? m[1] : null;
}

function countRows(db, table) {
  const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
  if (!exists) return null;
  return db.prepare(`SELECT COUNT(*) AS n FROM "${table}"`).get().n;
}

/**
 * Row counts of KEY_TABLES in the restored database against the live one. A
 * nightly backup is up to a day behind, so a table may differ by the larger of
 * `tolerancePct` of the live count or 10 rows.
 */
export function compareRowCounts(restored, live, tolerancePct) {
  const rows = [];
  let failed = 0;
  for (const t of KEY_TABLES) {
    const l = countRows(live, t);
    const r = countRows(restored, t);
    if (l === null && r === null) continue;
    const allowed = Math.max(10, Math.ceil((l || 0) * tolerancePct / 100));
    const ok = r !== null && l !== null && Math.abs(r - l) <= allowed;
    if (!ok) failed++;
    rows.push({ table: t, live: l, restored: r, allowed_delta: allowed, ok });
  }
  return check('row_counts', `Key table row counts within ${tolerancePct}% of live`, failed ? 'fail' : 'pass', rows);
}

/**
 * The restored data archive: manifest, SQLite integrity, row counts, that its
 * encrypted values decrypt, the ENCRYPTION_KEY it carries, and every managed
 * database dump it holds.
 */
export async function verifyDataTree(dir, { liveDb, tolerancePct, pgRestoreList }) {
  const checks = [];
  let manifest = null;
  try {
    manifest = JSON.parse(await readFile(join(dir, MANIFEST), 'utf8'));
    checks.push(check('manifest', 'Backup manifest reads', 'pass', { version: manifest.version || null, exported_at: manifest.exported_at || null }));
  } catch (e) {
    checks.push(check('manifest', 'Backup manifest reads', 'fail', String(e.message).slice(0, 200)));
  }

  let backupKey = null;
  const envFile = join(dir, '.env');
  if (existsSync(envFile)) {
    backupKey = envKey(await readFile(envFile, 'utf8'));
    const live = process.env.ENCRYPTION_KEY ? process.env.ENCRYPTION_KEY.slice(0, 64) : null;
    if (!backupKey) checks.push(check('encryption_key', 'Backup carries an ENCRYPTION_KEY', 'fail', 'the .env in the backup has no ENCRYPTION_KEY'));
    else if (live && sha(backupKey.slice(0, 64)) !== sha(live)) checks.push(check('encryption_key', 'Backup carries an ENCRYPTION_KEY', 'warn', 'the key in the backup differs from the live key; the backup decrypts only with its own'));
    else checks.push(check('encryption_key', 'Backup carries an ENCRYPTION_KEY', 'pass', 'matches the live key'));
  } else {
    checks.push(check('encryption_key', 'Backup carries an ENCRYPTION_KEY', 'warn', 'no .env in the backup; secrets decrypt only if this host keeps its key'));
  }

  const dbFile = join(dir, 'deployhub.db');
  if (!existsSync(dbFile)) {
    checks.push(check('db_integrity', 'SQLite integrity_check', 'fail', 'the backup has no deployhub.db'));
  } else {
    let restored = null;
    try {
      restored = new Database(dbFile, { readonly: true, fileMustExist: true });
      const res = restored.pragma('integrity_check').map((r) => r.integrity_check);
      const ok = res.length === 1 && res[0] === 'ok';
      checks.push(check('db_integrity', 'SQLite integrity_check', ok ? 'pass' : 'fail', ok ? 'ok' : res.slice(0, 5).join('; ').slice(0, 300)));
      if (ok) {
        checks.push(compareRowCounts(restored, liveDb, tolerancePct));
        checks.push(decryptSample(restored, backupKey));
      }
    } catch (e) {
      checks.push(check('db_integrity', 'SQLite integrity_check', 'fail', String(e.message).slice(0, 300)));
    } finally {
      try { restored?.close(); } catch (_) {}
    }
  }

  checks.push(...await verifyManagedDumps(dir, { pgRestoreList }));
  return { checks, manifest };
}

function decryptSample(restored, backupKey) {
  const label = 'Encrypted values in the backup decrypt';
  let rows;
  try {
    rows = restored.prepare("SELECT value_encrypted FROM env_vars WHERE value_encrypted IS NOT NULL AND value_encrypted != '' ORDER BY id LIMIT 3").all();
  } catch (e) {
    return check('secrets_decrypt', label, 'skipped', 'no env_vars table');
  }
  if (!rows.length) return check('secrets_decrypt', label, 'skipped', 'no encrypted values to try');
  const keys = [...(backupKey ? [['the backup key', backupKey.slice(0, 64)]] : []), ['the live key', undefined]];
  for (const [name, key] of keys) {
    let ok = 0;
    for (const r of rows) {
      try { decrypt(r.value_encrypted, key); ok++; } catch (_) { /* counted */ }
    }
    if (ok === rows.length) return check('secrets_decrypt', label, 'pass', `${ok} of ${rows.length} sampled values decrypted with ${name}`);
  }
  return check('secrets_decrypt', label, 'fail', `sampled values did not decrypt with ${keys.map((k) => k[0]).join(' or ')}`);
}

const MAGIC = {
  postgres: (h) => h.subarray(0, 5).toString('latin1') === 'PGDMP',
  redis: (h) => h.subarray(0, 5).toString('latin1') === 'REDIS',
  mongo: (h) => h[0] === 0x1f && h[1] === 0x8b,
  mariadb: (h) => {
    const s = h.toString('utf8');
    return /^(--|\/\*)/.test(s) && /dump/i.test(s);
  },
};

export function defaultPgRestoreList(file) {
  return new Promise((res) => {
    execFile('pg_restore', ['--list', file], { timeout: 120_000, maxBuffer: 32 * 1024 * 1024 }, (err, stdout) => {
      if (err && err.code === 'ENOENT') return res({ available: false });
      if (err) return res({ available: true, ok: false, error: String(err.message).split('\n')[0].slice(0, 200) });
      res({ available: true, ok: true, entries: String(stdout).split('\n').filter((l) => l && !l.startsWith(';')).length });
    });
  });
}

/**
 * Structural check of every managed-db/<engine>/<db>.dump: non-empty and the
 * engine's header. Postgres dumps also get `pg_restore --list` when the host
 * has pg_restore; without it the check says so instead of claiming more.
 */
export async function verifyManagedDumps(dir, { pgRestoreList = defaultPgRestoreList } = {}) {
  const root = join(dir, 'managed-db');
  if (!existsSync(root)) return [check('managed_db_dumps', 'Managed database dumps', 'skipped', 'the backup holds no managed database dumps')];
  const results = [];
  let failed = 0;
  let deepSkipped = 0;
  for (const engine of ENGINES) {
    const edir = join(root, engine);
    if (!existsSync(edir)) continue;
    for (const name of (await readdir(edir)).sort()) {
      if (!DUMP_RE.test(name)) continue;
      const file = assertInside(root, join(edir, name));
      const bytes = (await stat(file)).size;
      const head = await readHead(file, 4096);
      const headerOk = bytes > 0 && MAGIC[engine](head);
      const entry = { engine, db: name.slice(0, -5), bytes, header_ok: headerOk, deep: null };
      if (headerOk && engine === 'postgres') {
        const r = await pgRestoreList(file);
        if (!r.available) { entry.deep = 'skipped: pg_restore is not installed on this host (header check only)'; deepSkipped++; }
        else if (r.ok) entry.deep = `pg_restore --list: ${r.entries} entries`;
        else { entry.deep = `pg_restore --list failed: ${r.error}`; entry.header_ok = false; }
      }
      if (!entry.header_ok) failed++;
      results.push(entry);
    }
  }
  if (!results.length) return [check('managed_db_dumps', 'Managed database dumps', 'skipped', 'the backup holds no managed database dumps')];
  return [check('managed_db_dumps', `Managed database dumps (${results.length})${deepSkipped ? ', header check only for some' : ''}`, failed ? 'fail' : 'pass', results)];
}

/**
 * One repository archive (appcrane-repo-*.tar): its bundle's SHA-256 against
 * its manifest, then localGit's stageRepoFromBundleSync (git bundle verify,
 * unbundle, recreate refs, fsck --full) into `stageDir` under the scratch
 * area, and the restored HEAD against the manifest.
 */
export async function verifyRepoArchive(tarPath, scratch, { slug: expectSlug = null } = {}) {
  const tag = expectSlug || 'repository';
  const work = assertInside(scratch, join(scratch, 'repos', `${tag}-${Math.random().toString(36).slice(2, 8)}`));
  const stageDir = assertInside(scratch, join(scratch, 'repo-stage'));
  await mkdir(work, { recursive: true, mode: 0o700 });
  await mkdir(stageDir, { recursive: true, mode: 0o700 });
  try {
    await extractTar(tarPath, work);
    const manifest = JSON.parse(await readFile(join(work, REPO_MANIFEST), 'utf8'));
    if (expectSlug && manifest.slug !== expectSlug) throw new Error(`archive is for '${manifest.slug}'`);
    const bundlePath = join(work, REPO_BUNDLE);
    const hasBundle = existsSync(bundlePath);
    if (!!manifest.bundle !== hasBundle) throw new Error('bundle presence does not match the manifest');
    if (hasBundle && (await sha256File(bundlePath)) !== manifest.bundle.sha256) throw new Error('bundle SHA-256 does not match the manifest');
    const r = await runRepoTask({ op: 'stage', stageDir, slug: manifest.slug, head: manifest.head, bundlePath: hasBundle ? bundlePath : null });
    if ((r.headSha || null) !== (manifest.head_sha || null)) throw new Error('restored HEAD differs from the manifest');
    return { slug: manifest.slug, ok: true, refs: r.refs, head_sha: r.headSha };
  } catch (e) {
    return { slug: expectSlug, ok: false, error: String(e.message).split('\n')[0].slice(0, 200) };
  }
}

export function summarizeRepos(results, uncovered) {
  const failed = results.filter((r) => !r.ok).length;
  const checks = [];
  if (results.length) {
    checks.push(check('repo_bundles', `Repository bundles verify (${results.length})`, failed ? 'fail' : 'pass', results));
  }
  if (uncovered.length) {
    checks.push(check('repo_coverage', 'Every managed repository has an archive', 'warn', { without_archive: uncovered }));
  } else if (!results.length) {
    checks.push(check('repo_bundles', 'Repository bundles verify', 'skipped', 'no managed repositories'));
  }
  return checks;
}
