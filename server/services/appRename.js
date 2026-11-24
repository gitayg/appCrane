import { existsSync, lstatSync, readlinkSync, renameSync, symlinkSync, unlinkSync } from 'fs';
import { join, relative, resolve, sep } from 'path';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { resolveSafe } from '../utils/paths.js';
import { reloadCaddy } from './caddy.js';
import { AppError } from '../utils/errors.js';
import { slugRefusal, slugTakenRefusal } from '../utils/slugPolicy.js';
import { isAppOwnerOrPlatformAdmin } from './permissions.js';
import log from '../utils/logger.js';
import { syncAppCoders } from './crew.js';
import { reconcilerLive } from './reconcileState.js';
import { appDirsFor, dataRoot } from './appTrash.js';

// Renaming an app, for both front doors.
//
// This lived inline in POST /api/apps/:slug/rename, which made it REST-only —
// and REST is closed to the credential agents hold (dhk_mcp_* keys reach
// /api/mcp and /api/files/staged, nothing else). So the one operation that
// moves an app's whole identity was the one an agent could not perform, and the
// workaround people reached for instead was recreating the app, which loses
// the history a rename preserves.

export const RENAMES_PER_DAY = 3;

/**
 * Rename an app in place.
 *
 * Not destructive: deployments, env vars, ports, roles and grants are all keyed
 * on apps.id, so a slug change does not touch them. The old slug is kept in
 * slug_aliases and keeps redirecting unless `redirect` is false.
 *
 * The app's owner or a platform admin. Owners always keep the redirect and are
 * held to RENAMES_PER_DAY; releasing an old slug (redirect=false) is a platform
 * admin's call, because whoever takes it next receives the app's old links.
 *
 * Returns { old_slug, new_slug, redirect, redeploying }.
 */
export async function renameApp({ app, newSlug, redirect = true, user }) {
  const db = getDb();
  const oldSlug = app.slug;
  const userId = user?.id;
  const platformAdmin = user?.role === 'platform_admin';

  if (!isAppOwnerOrPlatformAdmin(user, app)) {
    throw new AppError('Only the app owner or a platform admin can rename an app.', 403, 'FORBIDDEN');
  }
  if (!redirect && !platformAdmin) {
    throw new AppError(
      'Only a platform admin can release the old slug (redirect: false). Rename with the redirect kept.',
      403, 'FORBIDDEN',
    );
  }
  if (!newSlug) throw new AppError('new_slug is required', 400, 'VALIDATION');
  const slugProblem = slugRefusal(newSlug, user);
  if (slugProblem) throw new AppError(slugProblem, 400, 'VALIDATION');
  if (newSlug === oldSlug) throw new AppError('New slug is the same as current slug', 400, 'VALIDATION');
  const taken = slugTakenRefusal(db, newSlug, app.id);
  if (taken) throw new AppError(taken, 400, 'SLUG_TAKEN');

  // The target directory has to be free too, and it is not implied by the slug
  // being free: deleting an app clears its rows and leaves data/apps/<slug> on
  // disk. renameSync onto a non-empty directory fails with ENOTEMPTY, and it
  // would fail below — after the containers were stopped — instead of here,
  // before anything has been touched.
  // resolveSafe, not a hand-rolled comparison. v2.54.0 shipped one that read
  //   resolve(join(base, slug)) !== join(base, slug)
  // which is only ever equal when DATA_DIR is already absolute. The default is
  // './data', so on a normal install that test was true for every slug and
  // every rename failed with "Invalid slug path" — a message about the slug,
  // for a bug that had nothing to do with it. Every test used an absolute
  // mkdtemp DATA_DIR, so the suite could not see it.
  const appsBase = join(process.env.DATA_DIR || './data', 'apps');
  const oldDir = resolveSafe(appsBase, oldSlug);
  const newDir = resolveSafe(appsBase, newSlug);
  if (existsSync(newDir)) {
    throw new AppError(
      `'${newSlug}' is free as a slug but data/apps/${newSlug} still exists on disk — most likely `
      + `left behind by an app deleted before deletes moved it to the trash. A platform admin can `
      + `move it to the trash from the Reconcile page (orphan directory), then rename.`,
      409, 'TARGET_DIR_EXISTS',
    );
  }
  // A Crane-hosted repository is named after the slug too (localGit.repoPath),
  // and was never moved: the renamed app pointed at a repository that did not
  // exist, and the old one sat under the old name.
  const reposBase = join(process.env.DATA_DIR || './data', 'repos');
  const oldRepo = resolveSafe(reposBase, `${oldSlug}.git`);
  const newRepo = resolveSafe(reposBase, `${newSlug}.git`);
  if (existsSync(oldRepo) && existsSync(newRepo)) {
    throw new AppError(
      `'${newSlug}' is free as a slug but repos/${newSlug}.git still exists on disk. A platform admin can `
      + `move it to the trash from the Reconcile page (orphan repository), then rename.`,
      409, 'TARGET_REPO_EXISTS',
    );
  }
  // Every other per-app directory is named after the slug too: backups, the
  // coder's transcripts, attestations, the studio npm cache.
  const oldDirs = appDirsFor(oldSlug);
  const newDirs = new Map(appDirsFor(newSlug).dirs);
  const extraMoves = [];
  for (const [kind, from] of oldDirs.dirs) {
    if (kind === 'app_dir' || kind === 'repo') continue;
    const to = newDirs.get(kind);
    if (!to) {
      if (existsSync(from)) throw new AppError(`'${newSlug}' cannot hold this app's ${kind} directory: that name is the platform's own there. Choose a different slug.`, 400, 'VALIDATION');
      continue;
    }
    if (existsSync(from) && existsSync(to)) {
      throw new AppError(
        `'${newSlug}' is free as a slug but ${relative(dataRoot(), to)} still exists on disk. `
        + 'A platform admin can move it to the trash from the Reconcile page, then rename.',
        409, 'TARGET_DIR_EXISTS',
      );
    }
    extraMoves.push([kind, from, to]);
  }
  for (const r of oldDirs.refused) {
    if (r.kind === 'backups' && db.prepare('SELECT 1 FROM backups WHERE app_id = ?').get(app.id)) {
      throw new AppError(`This app's backups are in ${r.path}, which also holds the platform's own archives, so they cannot be moved by a rename.`, 409, 'BACKUPS_NOT_MOVABLE');
    }
  }
  // The coder container mounts app-containers/<slug>; a turn in flight would
  // lose its workspace under it.
  const coderDir = extraMoves.find(([k]) => k === 'coder_workspace');
  let coder = null;
  if (coderDir && existsSync(coderDir[1])) {
    coder = await import('./builder/appContainer.js');
    if (coder.getContainer(oldSlug)?.busy) {
      throw new AppError('The app\'s coder is running a turn. Rename when it has finished.', 409, 'CODER_BUSY');
    }
  }


  // The database write comes FIRST, and carries app_skills with it.
  //
  // app_skills.app_slug references apps.slug — by slug, not by app_id, and with
  // ON UPDATE NO ACTION — so `UPDATE apps SET slug` raises a foreign key error
  // for any app with a skill attached. This used to run last, after the
  // containers were stopped and the directory moved, so that failure left the
  // app stopped, its data at the new path, and the row still naming the old
  // slug. Retrying then failed against a directory that had already moved.
  //
  // defer_foreign_keys because neither order works without it: the child first
  // points at a slug that does not exist yet, the parent first orphans the
  // child. Deferring moves the check to COMMIT, where the two rows agree.
  //
  // The checks above are repeated inside an IMMEDIATE transaction, which takes
  // the write lock before reading: the row is re-read (a concurrent rename may
  // have moved it), the throttle is counted, and the slug is checked once more,
  // so nothing can change between the check and the write. The apps.slug
  // UNIQUE constraint and migration 124's triggers back that up for writers
  // that do not come through here.
  let previousAliases = null;
  let renameLogId = null;
  const applyRename = db.transaction(() => {
    const current = db.prepare('SELECT slug, slug_aliases FROM apps WHERE id = ?').get(app.id);
    if (!current || current.slug !== oldSlug) {
      throw new AppError('The app was renamed while this request was in flight. Reload and try again.', 409, 'CONFLICT');
    }
    if (!platformAdmin) {
      const recent = db.prepare(
        "SELECT COUNT(*) AS n FROM app_slug_renames WHERE app_id = ? AND renamed_at > datetime('now', '-1 day')"
      ).get(app.id).n;
      if (recent >= RENAMES_PER_DAY) {
        throw new AppError(
          `This app has been renamed ${RENAMES_PER_DAY} times in the last 24 hours, the most allowed. Try again later.`,
          429, 'RENAME_LIMIT',
        );
      }
    }
    const takenNow = slugTakenRefusal(db, newSlug, app.id);
    if (takenNow) throw new AppError(takenNow, 400, 'SLUG_TAKEN');

    previousAliases = current.slug_aliases;
    let aliases = [];
    try { aliases = JSON.parse(current.slug_aliases || '[]'); } catch (_) {}
    // Returning to one of its own old slugs: that one stops being a redirect.
    aliases = aliases.filter(a => a !== newSlug);
    if (redirect && !aliases.includes(oldSlug)) aliases.push(oldSlug);

    db.pragma('defer_foreign_keys = ON');
    db.prepare('UPDATE app_skills SET app_slug = ? WHERE app_slug = ?').run(newSlug, oldSlug);
    db.prepare('UPDATE apps SET slug = ?, slug_aliases = ? WHERE id = ?')
      .run(newSlug, aliases.length ? JSON.stringify(aliases) : null, app.id);
    renameLogId = db.prepare('INSERT INTO app_slug_renames (app_id, old_slug, new_slug, renamed_by) VALUES (?, ?, ?, ?)')
      .run(app.id, oldSlug, newSlug, userId ?? null).lastInsertRowid;
  });
  try {
    applyRename.immediate();
  } catch (e) {
    if (/SLUG_TAKEN/.test(e.message) && !(e instanceof AppError)) {
      throw new AppError(`Slug '${newSlug}' is already used by another app. Choose a different slug.`, 400, 'SLUG_TAKEN');
    }
    throw e;
  }

  try {
    const { stopApp } = await import('./docker.js');
    await stopApp(oldSlug, 'production').catch(() => {});
    await stopApp(oldSlug, 'sandbox').catch(() => {});
    // The per-env volume declared paths are mounted through is named after the
    // slug and bound to the OLD directory. Left behind it is a stale record
    // (startApp recreates one under the new name); removed here so it does not
    // outlive the slug. The daemon's record only: the data moves with the dir.
    const { removeAppVolumes } = await import('./docker.js');
    await removeAppVolumes(oldSlug).catch(() => {});
  } catch (_) {}

  // Stopped the way an idle sweep stops it (uncommitted work preserved to a
  // branch), so nothing writes to the directory while it moves.
  if (coder) {
    try { coder.evict(oldSlug, 'app renamed'); } catch (e) { log.warn(`Rename ${oldSlug} -> ${newSlug}: coder container not evicted: ${e.message}`); }
  }

  // The row already says newSlug, so a failure here is the inconsistency in the
  // other direction — a row naming a path that is not there. Put it back.
  // Absolute paths under the moved directories are rewritten in the same
  // step: deployments.release_path (rollback and promote refuse a release
  // whose directory is missing), backups.file_path and each database dump's
  // file (restore confines dumps to backups/<slug>), deploy_attestations.dir
  // and coder_sessions (the coder resumes its conversation by app_slug).
  // A failure anywhere moves every directory back and restores the slug.
  const moved = [];
  const moves = [['app_dir', oldDir, newDir], ['repo', oldRepo, newRepo], ...extraMoves].filter(([, from]) => existsSync(from));
  try {
    for (const [, from, to] of moves) { renameSync(from, to); moved.push([from, to]); }
    rewritePaths(db, app.id, oldSlug, newSlug, moves);
  } catch (e) {
    for (const [from, to] of moved.reverse()) {
      try { renameSync(to, from); } catch (err) { log.error(`Rename rollback: could not move ${to} back: ${err.message}`); }
    }
    db.transaction(() => {
      db.pragma('defer_foreign_keys = ON');
      db.prepare('UPDATE app_skills SET app_slug = ? WHERE app_slug = ?').run(oldSlug, newSlug);
      db.prepare('UPDATE apps SET slug = ?, slug_aliases = ? WHERE id = ?')
        .run(oldSlug, previousAliases, app.id);
      db.prepare('DELETE FROM app_slug_renames WHERE id = ?').run(renameLogId);
    })();
    throw new AppError(
      `Could not move the app's data directory (${e.message}). The rename was rolled back; `
      + `the app is still '${oldSlug}' and its containers have been stopped — redeploy it.`,
      500, 'RENAME_FAILED',
    );
  }
  const oldPrefix = oldDir + sep;

  // Each env's `current` is an absolute link into the directory just moved, so
  // it dangled until a redeploy replaced it, and an env that is not redeployed
  // (nothing live) kept a dead link.
  for (const env of ['production', 'sandbox']) {
    const link = join(newDir, env, 'current');
    try {
      if (!lstatSync(link, { throwIfNoEntry: false })?.isSymbolicLink()) continue;
      const target = readlinkSync(link);
      if (!target.startsWith(oldPrefix)) continue;
      unlinkSync(link);
      symlinkSync(newDir + sep + target.slice(oldPrefix.length), link);
    } catch (e) {
      log.warn(`Rename ${oldSlug} -> ${newSlug}: could not re-point ${env}/current: ${e.message}`);
    }
  }

  await reloadCaddy().catch((e) => log.warn(`Caddy reload after rename: ${e.message}`));

  // The app's Crew coder is named after the slug ("<slug>-coder").
  syncAppCoders(db, app.id);

  // Each probe timer holds the slug it was armed with; re-arm under the new one.
  if (reconcilerLive()) {
    try { (await import('./healthChecker.js')).refreshAppChecks(app.id); } catch (e) { log.warn(`Rename: health checks not re-armed: ${e.message}`); }
  }

  // DISTINCT: past releases keep status 'live', so without it this was one
  // redeploy per release ever shipped, all started at once.
  const liveEnvs = db.prepare("SELECT DISTINCT env FROM deployments WHERE app_id = ? AND status = 'live'").all(app.id);
  const updatedApp = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  const ports = getPortsForSlot(updatedApp.slot);

  for (const { env } of liveEnvs) {
    try {
      const result = db.prepare(
        "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)"
      ).run(app.id, env, userId);
      const { deployApp } = await import('./deployer.js');
      deployApp(result.lastInsertRowid, updatedApp, env, ports).catch((err) => {
        log.error(`Rename redeploy failed (${env}): ${err.message}`);
      });
    } catch (e) {
      log.warn(`Could not queue rename redeploy for ${env}: ${e.message}`);
    }
  }

  return { old_slug: oldSlug, new_slug: newSlug, redirect, redeploying: liveEnvs.map((r) => r.env) };
}

/** Every stored absolute path under a moved directory, re-pointed, in one transaction. */
export function rewritePaths(db, appId, oldSlug, newSlug, moves) {
  const pairs = moves.map(([kind, from, to]) => [kind, from + sep, to + sep]);
  // routes/backups.js stores paths joined from DATA_DIR as configured, which
  // may be relative; compared resolved, written back absolute.
  const swap = (p, [, from, to]) => {
    if (typeof p !== 'string') return p;
    const abs = resolve(p);
    return abs.startsWith(from) ? to + abs.slice(from.length) : p;
  };
  const prefixUpdate = (table, col, where = 'app_id = ?') => {
    const stmt = db.prepare(`UPDATE ${table} SET ${col} = ? || substr(${col}, ?) WHERE ${where} AND substr(${col}, 1, ?) = ?`);
    return (args, [, from, to]) => stmt.run(to, from.length + 1, ...args, from.length, from).changes;
  };
  db.transaction(() => {
    const byKind = new Map(pairs.map((p) => [p[0], p]));
    if (byKind.has('app_dir')) prefixUpdate('deployments', 'release_path')([appId], byKind.get('app_dir'));
    if (byKind.has('backups')) {
      const swapBackup = (p) => swap(p, byKind.get('backups'));
      for (const b of db.prepare('SELECT id, file_path, databases FROM backups WHERE app_id = ?').all(appId)) {
        const list = b.databases ? JSON.parse(b.databases).map((d) => ({ ...d, file: swapBackup(d.file) })) : null;
        db.prepare('UPDATE backups SET file_path = ?, databases = ? WHERE id = ?').run(swapBackup(b.file_path), list ? JSON.stringify(list) : null, b.id);
      }
    }
    if (byKind.has('attestations')) prefixUpdate('deploy_attestations', 'dir')([appId], byKind.get('attestations'));
    if (byKind.has('coder_workspace')) prefixUpdate('coder_sessions', 'workspace_dir', 'app_slug = ?')([oldSlug], byKind.get('coder_workspace'));
    db.prepare('UPDATE coder_sessions SET app_slug = ? WHERE app_slug = ?').run(newSlug, oldSlug);
  })();
}
