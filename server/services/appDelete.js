import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { deleteAppCoderRows } from './crewAppCoderAgents.js';
import { announce } from './crew.js';
import { retainedAppSecrets } from './secretRefs.js';
import { existsSync } from 'fs';
import { join, sep } from 'path';
import { logAudit } from '../middleware/audit.js';
import { appDirsFor, dataRoot, moveToTrash } from './appTrash.js';
import { reconcilerLive, rescheduleHealthChecks } from './reconcileState.js';

// The body of DELETE /api/apps/:slug, moved here unchanged so appcrane_delete_app
// runs the same teardown. Caddy is reloaded by the caller.
export async function deleteApp(app) {
  const db = getDb();
  const slug = app.slug;

  // Stop containers
  try {
    const { stopApp } = await import('../services/docker.js');
    await stopApp(slug, 'production').catch(() => {});
    await stopApp(slug, 'sandbox').catch(() => {});
    // Nothing removed a deleted app's images, so every delete left them on
    // disk forever. Before the rows go: it reads this app's deployments.
    const { removeAppImages } = await import('../services/docker.js');
    await removeAppImages(app.id, slug).catch(() => {});
    // And the per-env volumes its declared paths were mounted through. The
    // daemon's record only; the data on disk stays, as it always has.
    const { removeAppVolumes } = await import('../services/docker.js');
    await removeAppVolumes(slug).catch(() => {});
  } catch (e) {}

  // v2.65.0: drop the app's managed databases BEFORE the row goes away.
  //
  // Migration 085's foreign key cascades the managed_databases ROW when apps is
  // deleted, and that is the whole of what SQLite can do — it cannot reach into
  // Postgres or MariaDB. So a delete that skipped this would leave the database
  // itself and a live login role standing, holding the deleted app's data, with
  // nothing left in AppCrane pointing at either and anyone who still has the
  // credentials able to open it. The cascade makes the leak INVISIBLE rather
  // than loud, which is why this runs first rather than being left to a sweeper.
  //
  // After stopApp on purpose: the engine-side drop is what has to survive a
  // container that has not finished shutting down (managedDb uses
  // DROP DATABASE ... WITH (FORCE) for exactly that), but there is no reason to
  // race it when stopping first is free.
  //
  // Called plainly, not wrapped: deprovisionApp catches per row and logs, and
  // returns {requested, dropped} counts rather than throwing, so a database
  // server that is down leaves a warning in the log and a deletable app. Read
  // rather than assumed — server/services/managedDb.js, deprovisionApp().
  // The counts are safe to return: they are integers, never a name or a secret.
  const { deprovisionApp } = await import('../services/managedDb.js');
  const dbDrop = await deprovisionApp(app.id);
  if (dbDrop.requested !== dbDrop.dropped) {
    log.warn(
      `App delete '${slug}': ${dbDrop.requested - dbDrop.dropped} of ${dbDrop.requested} managed ` +
      'databases could not be dropped — they are now orphaned in the engine',
    );
  }

  // The app's AWS secrets stay. AppCrane holds no delete call and its IAM policy
  // no secretsmanager:DeleteSecret; a backup restored later brings the app and its
  // secrets back together; and they may be the only copy. Nothing can read them
  // meanwhile, since the path is the app's own random namespace, which no later
  // app gets. So the operator is told where they are, while the row can still say.
  const awsRetained = retainedAppSecrets(app, db.prepare('SELECT env, value_encrypted FROM env_vars WHERE app_id = ?').all(app.id));
  if (awsRetained) {
    log.warn(
      `App delete '${slug}': AWS Secrets Manager secrets under ${awsRetained.path_prefix} are left in place ` +
      `(${awsRetained.referenced.length} referenced at delete). Delete them in AWS when you are done`,
    );
  }

  // The backups rows go with the app (backups.app_id cascades and is NOT NULL),
  // so what they said is read now and kept in the backups trash entry.
  const backupRows = db.prepare('SELECT id, env, size_bytes, file_path, databases, created_at FROM backups WHERE app_id = ? ORDER BY id').all(app.id);
  const offSite = await offSiteCopiesFor(slug);

  // Delete related records first to avoid FK constraint failures
  const appId = app.id;
  let crewTaskIds = [];
  db.transaction(() => {
    // The app's Crew coder identity (crew_agents.app_id, no foreign key: see
    // migration 162) and, by cascade, the tasks sent to it.
    crewTaskIds = deleteAppCoderRows(db, appId);
    db.prepare('DELETE FROM app_user_roles WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM app_identity_secrets WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM app_settings WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM app_domain_aliases WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM deployments WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM env_vars WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM health_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM health_state WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM webhook_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM backups WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM notification_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM identity_sessions WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM apps WHERE id = ?').run(appId);
  })();
  // Open task streams and a running coder turn for those tasks end on 'deleted'.
  if (crewTaskIds.length) announce(crewTaskIds, 'deleted');

  // The rows are gone; the directories used to stay, and the next app given
  // this slug found them (rename refused TARGET_DIR_EXISTS, a new managed app
  // refused the old repository). Moved to the trash, not removed: the data
  // directory, the Crane-hosted repository, per-app backups, the coder's
  // transcripts and attachments, image attestations and the studio npm cache.
  const trashed = [];
  const kept = [];
  const { dirs, refused } = appDirsFor(slug);
  for (const r of refused) {
    if (existsSync(join(dataRoot(), r.path))) kept.push({ kind: r.kind, error: `${r.path} is not this app's alone (the platform keeps its own files there); left in place` });
  }
  if (dirs.some(([kind, path]) => kind === 'coder_workspace' && existsSync(path))) {
    // The coder container mounts this directory; stop it (its uncommitted work
    // is preserved to a branch, as on an idle eviction) before the move.
    try { (await import('./builder/appContainer.js')).evict(slug, 'app deleted'); } catch (e) { log.warn(`App delete '${slug}': coder container not evicted: ${e.message}`); }
  }
  for (const [kind, path] of dirs) {
    if (!existsSync(path)) continue;
    const detail = kind === 'backups'
      ? (to) => ({ backups: backupRows.map((b) => backupInTrash(b, path, to)), ...(offSite && { off_site: offSite }) })
      : (kind === 'app_dir' || kind === 'repo') && offSite ? { off_site: offSite } : null;
    try {
      const row = moveToTrash(db, { kind, path, slug, appId, reason: 'app deleted', detail });
      trashed.push({ kind, trash_id: row.id, expires_at: row.expires_at, ...(kind === 'backups' && { backups: backupRows.length }) });
    } catch (e) {
      kept.push({ kind, error: e.message });
      log.warn(`App delete '${slug}': could not move ${kind} to the trash: ${e.message}`);
    }
  }
  if (offSite) {
    log.warn(`App delete '${slug}': off-site backups in bucket ${offSite.bucket} still hold this app (${offSite.holds.join('; ')}). AppCrane does not delete remote objects`);
  }
  if (trashed.length) logAudit(null, null, 'app-trash', { slug, app_id: appId, trashed, ...(offSite && { off_site: offSite }) });

  // A deleted config keeps its probe timer until the checker is re-armed.
  if (reconcilerLive()) await rescheduleHealthChecks().catch((e) => log.warn(`App delete '${slug}': health checks not re-armed: ${e.message}`));

  return {
    slug, managed_databases: dbDrop, moved_to_trash: trashed,
    ...(kept.length && { leftovers_kept: kept }),
    ...(awsRetained && { aws_secrets_retained: awsRetained }),
    ...(offSite && { off_site_copies_retained: offSite }),
  };
}

// A backups row as it was, with its file paths pointing at where the files are now.
function backupInTrash(b, from, to) {
  const move = (p) => (typeof p === 'string' && p.startsWith(from + sep) ? to + p.slice(from.length) : p);
  let databases = null;
  try { databases = b.databases ? JSON.parse(b.databases).map((d) => ({ ...d, file: move(d.file) })) : null; } catch (_) {}
  return { id: b.id, env: b.env, created_at: b.created_at, size_bytes: b.size_bytes, file_path: move(b.file_path), original_file_path: b.file_path, databases };
}

// Off-site sets are platform-wide: each holds the whole DATA_DIR archive (this
// app's /data, icons and managed-database dumps among it) and, when repositories
// are included, one archive per Crane-hosted repository. They are not deleted;
// the entry says where they are. Bucket and prefix only, never a credential.
async function offSiteCopiesFor(slug) {
  try {
    const { offSiteState, getBackupConfig } = await import('./backupScheduler.js');
    const st = offSiteState();
    if (!st.has_off_site_copy) return null;
    const cfg = getBackupConfig();
    const { normalizePrefix } = await import('./backupS3Sets.js');
    const prefix = normalizePrefix(cfg.prefix);
    return {
      bucket: cfg.bucket, prefix, endpoint: cfg.endpoint || null, last_run: st.last_run,
      holds: [
        `${prefix}<set>/data.tar.gz* (apps/${slug}, backups/${slug} and its managed-database dumps)`,
        ...(cfg.include_repos ? [`${prefix}<set>/repos/appcrane-repo-${slug}-* (the Crane-hosted repository)`] : []),
      ],
      note: 'Remote objects are not deleted by AppCrane; they age out under the off-site retention (daily/weekly/monthly) or can be deleted in the bucket.',
    };
  } catch (e) {
    log.warn(`App delete '${slug}': off-site backup state not read: ${e.message}`);
    return null;
  }
}
