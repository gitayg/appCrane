import { existsSync, renameSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { reloadCaddy } from './caddy.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';

// Renaming an app, for both front doors.
//
// This lived inline in POST /api/apps/:slug/rename, which made it REST-only —
// and REST is closed to the credential agents hold (dhk_mcp_* keys reach
// /api/mcp and /api/files/staged, nothing else). So the one operation that
// moves an app's whole identity was the one an agent could not perform, and the
// workaround people reached for instead was recreating the app, which loses
// the history a rename preserves.

/** `data/apps/<slug>`, refusing anything that escapes the apps directory. */
function appDir(appsBase, slug) {
  const dir = resolve(join(appsBase, slug));
  if (dir !== join(appsBase, slug)) throw new AppError('Invalid slug path', 400, 'VALIDATION');
  return dir;
}

/**
 * Rename an app in place.
 *
 * Not destructive: deployments, env vars, ports, roles and grants are all keyed
 * on apps.id, so a slug change does not touch them. The old slug is kept in
 * slug_aliases and keeps redirecting unless `redirect` is false.
 *
 * Returns { old_slug, new_slug, redirect, redeploying }.
 */
export async function renameApp({ app, newSlug, redirect = true, userId }) {
  const db = getDb();
  const oldSlug = app.slug;

  if (!newSlug) throw new AppError('new_slug is required', 400, 'VALIDATION');
  if (!/^[a-z0-9][a-z0-9-]*$/.test(newSlug)) {
    throw new AppError('Slug must be lowercase alphanumeric with dashes', 400, 'VALIDATION');
  }
  if (newSlug === oldSlug) throw new AppError('New slug is the same as current slug', 400, 'VALIDATION');
  if (db.prepare('SELECT id FROM apps WHERE slug = ?').get(newSlug)) {
    throw new AppError(`Slug '${newSlug}' is already in use`, 409, 'DUPLICATE');
  }

  // The target directory has to be free too, and it is not implied by the slug
  // being free: deleting an app clears its rows and leaves data/apps/<slug> on
  // disk. renameSync onto a non-empty directory fails with ENOTEMPTY, and it
  // would fail below — after the containers were stopped — instead of here,
  // before anything has been touched.
  const appsBase = join(process.env.DATA_DIR || './data', 'apps');
  const oldDir = appDir(appsBase, oldSlug);
  const newDir = appDir(appsBase, newSlug);
  if (existsSync(newDir)) {
    throw new AppError(
      `'${newSlug}' is free as a slug but data/apps/${newSlug} still exists on disk — most likely `
      + `left behind by a deleted app, which clears the database rows but not the directory. `
      + `Remove that directory on the server, then rename.`,
      409, 'TARGET_DIR_EXISTS',
    );
  }

  let aliases = [];
  try { aliases = JSON.parse(app.slug_aliases || '[]'); } catch (_) {}
  if (redirect && !aliases.includes(oldSlug)) aliases.push(oldSlug);

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
  const applyRename = db.transaction(() => {
    db.pragma('defer_foreign_keys = ON');
    db.prepare('UPDATE app_skills SET app_slug = ? WHERE app_slug = ?').run(newSlug, oldSlug);
    db.prepare('UPDATE apps SET slug = ?, slug_aliases = ? WHERE id = ?')
      .run(newSlug, aliases.length ? JSON.stringify(aliases) : null, app.id);
  });
  applyRename();

  try {
    const { stopApp } = await import('./docker.js');
    await stopApp(oldSlug, 'production').catch(() => {});
    await stopApp(oldSlug, 'sandbox').catch(() => {});
  } catch (_) {}

  // The row already says newSlug, so a failure here is the inconsistency in the
  // other direction — a row naming a path that is not there. Put it back.
  if (existsSync(oldDir)) {
    try {
      renameSync(oldDir, newDir);
    } catch (e) {
      db.transaction(() => {
        db.pragma('defer_foreign_keys = ON');
        db.prepare('UPDATE app_skills SET app_slug = ? WHERE app_slug = ?').run(oldSlug, newSlug);
        db.prepare('UPDATE apps SET slug = ?, slug_aliases = ? WHERE id = ?')
          .run(oldSlug, app.slug_aliases, app.id);
      })();
      throw new AppError(
        `Could not move the app's data directory (${e.message}). The rename was rolled back; `
        + `the app is still '${oldSlug}' and its containers have been stopped — redeploy it.`,
        500, 'RENAME_FAILED',
      );
    }
  }

  await reloadCaddy().catch((e) => log.warn(`Caddy reload after rename: ${e.message}`));

  const liveEnvs = db.prepare("SELECT env FROM deployments WHERE app_id = ? AND status = 'live'").all(app.id);
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
