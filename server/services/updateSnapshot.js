/**
 * Pre-update data snapshots (v2.27.0).
 *
 * AppCrane already rolls CODE back when a self-update won't boot
 * (maybeAutoRollback in index.js pins previous_sha). That does nothing for
 * DATA. The canonical failure in this category is a self-hosted PaaS update
 * that damaged persistent state — Coolify's update path once clobbered the
 * `.env` holding the app key, making every encrypted value permanently
 * unrecoverable ("The MAC is invalid"). Rolling the code back doesn't bring
 * those bytes back.
 *
 * So: immediately before `git reset --hard`, snapshot the two irreplaceable
 * artifacts — the SQLite database and `.env` (which holds ENCRYPTION_KEY, the
 * key that makes every stored secret readable). Both live under DATA_DIR
 * already; this copies them to a timestamped folder alongside, so a bad
 * upgrade is recoverable rather than terminal.
 *
 * Restore is deliberately NOT automatic. Copying a database over a running
 * instance is itself a way to lose data; the operator restores explicitly
 * (see `crane snapshots` / the README) once they know what broke.
 */

import { existsSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, readdirSync, rmSync, statSync, chmodSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

const KEEP = 5; // retain the last N snapshots; older ones are pruned

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * MUST resolve to the same directory as `selfUpdateDataDir()` in index.js —
 * that function writes the pending-update file that points an operator at the
 * snapshot they are about to need. A cwd-relative fallback here would drift
 * apart from index.js's module-relative one whenever DATA_DIR is unset and the
 * process wasn't started from the repo root, and the split would stay invisible
 * until a restore was attempted and the snapshot wasn't where the pending file
 * said it was. This file sits at server/services/, so the repo-root `data` dir
 * is two levels up.
 */
export function dataDir() {
  return resolve(process.env.DATA_DIR || join(__dirname, '..', '..', 'data'));
}

export function snapshotRoot() {
  return join(dataDir(), 'update-snapshots');
}

export function listSnapshots() {
  const root = snapshotRoot();
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter(d => /^\d{8}T\d{6}Z(-|$)/.test(d))
    .map(id => {
      const dir = join(root, id);
      let manifest = null;
      try { manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')); } catch (_) {}
      let bytes = 0;
      try {
        for (const f of readdirSync(dir)) bytes += statSync(join(dir, f)).size;
      } catch (_) {}
      return { id, dir, bytes, ...manifest };
    })
    .sort((a, b) => (a.id < b.id ? 1 : -1)); // newest first
}

function prune() {
  const all = listSnapshots();
  for (const old of all.slice(KEEP)) {
    try { rmSync(old.dir, { recursive: true, force: true }); log.info(`[snapshot] pruned ${old.id}`); }
    catch (e) { log.warn(`[snapshot] could not prune ${old.id}: ${e.message}`); }
  }
}

/**
 * Snapshot the DB + .env before an update. Never throws — a snapshot failure
 * must not block the upgrade, but it IS reported so the caller can surface
 * "upgrading without a restore point" rather than implying one exists.
 *
 * @param {string} cwd  repo root (where .env lives)
 * @param {object} meta {from, to, sha} recorded in the manifest
 * @returns {{ok:boolean, id?:string, dir?:string, files?:string[], bytes?:number, error?:string}}
 */
export function createPreUpdateSnapshot(cwd, meta = {}, dbHandle = null) {
  try {
    // Ids are second-resolution, and two snapshots can genuinely land in the
    // same second — a pre-migration snapshot at boot followed by a pre-update
    // one, or a tight retry. Without a uniquifier they share a directory, and
    // because `VACUUM INTO` refuses to overwrite an existing file the second
    // snapshot would silently keep the FIRST one's database while still
    // reporting success. Suffix until the directory is free.
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    let id = stamp;
    for (let n = 2; existsSync(join(snapshotRoot(), id)); n++) id = `${stamp}-${n}`;
    const dir = join(snapshotRoot(), id);
    // 0700: the contents are a whole database and the ENCRYPTION_KEY. env.backup
    // is chmod 0600 below, but a 0755 directory still lets any local account
    // enumerate what restore points exist and when an upgrade happened. mkdir's
    // mode is masked by umask, so the explicit chmod is the part that's load-
    // bearing; both are best-effort, since no permission problem is worth
    // losing the snapshot itself over.
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { chmodSync(snapshotRoot(), 0o700); } catch (_) {}
    try { chmodSync(dir, 0o700); } catch (_) {}
    const files = [];

    // Database: VACUUM INTO produces a consistent copy of a LIVE database
    // (a plain file copy can catch a torn write mid-transaction). Requires
    // SQLite >= 3.27, which better-sqlite3 has shipped for years.
    // dbHandle lets a caller that is still mid-initialisation (db.js, snapshotting
    // before it applies migrations) pass its own live handle instead of going
    // through the module singleton, which isn't published yet at that point.
    const dbCopy = join(dir, 'deployhub.db');
    let dbError = null;
    try {
      (dbHandle || getDb()).prepare('VACUUM INTO ?').run(dbCopy);
      files.push('deployhub.db');
    } catch (e) {
      dbError = e.message;
      log.error(`[snapshot] database copy failed: ${e.message}`);
    }

    // .env — holds ENCRYPTION_KEY. Losing it means every encrypted env var and
    // stored token is permanently unreadable, so this is the single most
    // important file here. 0600: it is as sensitive as the original.
    const envSrc = join(cwd, '.env');
    if (existsSync(envSrc)) {
      const envCopy = join(dir, 'env.backup');
      copyFileSync(envSrc, envCopy);
      try { chmodSync(envCopy, 0o600); } catch (_) {}
      files.push('env.backup');
    }

    const manifest = {
      created_at: new Date().toISOString(),
      // 'pre-update' (taken by /api/self-update before the pull) or
      // 'pre-migration' (taken at boot before schema changes are applied).
      reason: meta.reason ?? 'pre-update',
      from_version: meta.from ?? null,
      to_version: meta.to ?? null,
      previous_sha: meta.sha ?? null,
      pending_migrations: meta.pending ?? null,
      files,
      note: 'Pre-update snapshot. Restore is manual and deliberate — stop the service, copy these back, then start it.',
    };
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));

    let bytes = 0;
    for (const f of readdirSync(dir)) bytes += statSync(join(dir, f)).size;

    prune();

    // A snapshot without the database is not a restore point. Reporting ok
    // here would tell an operator they can roll back when they can't — the
    // exact "the jobs run but the evidence doesn't" failure this feature
    // exists to avoid. The .env copy is still kept; it's the harder half to
    // reconstruct.
    if (dbError) {
      log.error(`[snapshot] ${id} has NO database copy — not a usable restore point`);
      return { ok: false, id, dir, files, bytes, error: `database copy failed: ${dbError}` };
    }

    log.info(`[snapshot] ${meta.reason ?? 'pre-update'} snapshot ${id} (${files.join(', ')}, ${Math.round(bytes / 1024)} KB)`);
    return { ok: true, id, dir, files, bytes };
  } catch (e) {
    log.error(`[snapshot] pre-update snapshot FAILED: ${e.message}`);
    return { ok: false, error: e.message };
  }
}
