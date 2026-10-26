import { getDb } from '../db.js';
import log from '../utils/logger.js';

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

  // Delete related records first to avoid FK constraint failures
  const appId = app.id;
  db.transaction(() => {
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

  return { slug, managed_databases: dbDrop };
}
