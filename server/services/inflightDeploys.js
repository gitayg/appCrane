// Which in-flight deployments should hold up a self-update or restart.
//
// Killing the process mid-build orphans the build and leaves dangling layers,
// so self-update and restart refuse while a deploy is running. But a row can be
// left in pending/building/deploying inside the CURRENT process's lifetime —
// a build that hung, or a code path that threw before writing a final status —
// and the boot sweep only clears rows from a previous process. One such row
// used to block every update until someone forced it from the browser console.
//
// deployments has no last-activity column: status transitions do not touch a
// timestamp, so started_at is the only clock there is. A deploy that started
// more than STALE_INFLIGHT_MINUTES ago is far past any real build and is
// reported as stale instead of blocking. Rows are only described here, never
// changed: reclaiming them is the deploy guard's job (assertNoInflightDeploy).

const DEFAULT_STALE_MINUTES = 60;

export const STALE_INFLIGHT_MINUTES = (() => {
  const n = parseInt(process.env.SELF_UPDATE_STALE_DEPLOY_MINUTES, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_STALE_MINUTES;
})();

export function listInflightDeploys(db, staleMinutes = STALE_INFLIGHT_MINUTES) {
  const rows = db.prepare(`
    SELECT d.id, d.app_id, d.env, d.status, d.started_at,
           a.slug AS app_slug, a.name AS app_name,
           (strftime('%s','now') - strftime('%s', d.started_at)) AS age_seconds
    FROM deployments d
    LEFT JOIN apps a ON a.id = d.app_id
    WHERE d.status IN ('pending','building','deploying')
    ORDER BY d.started_at ASC, d.id ASC
  `).all();

  const all = rows.map((r) => ({
    id: r.id,
    app_id: r.app_id,
    app_slug: r.app_slug,
    app_name: r.app_name,
    env: r.env,
    status: r.status,
    // SQLite datetime('now') is UTC without a zone marker; say so, or a browser
    // parses it as local time and the age shown is off by the UTC offset.
    started_at: r.started_at ? `${r.started_at.replace(' ', 'T')}Z` : null,
    age_seconds: r.age_seconds ?? null,
    stale: r.age_seconds != null && r.age_seconds >= staleMinutes * 60,
  }));
  return {
    blocking: all.filter((r) => !r.stale),
    stale: all.filter((r) => r.stale),
  };
}

/**
 * The 409 body for a self-update/restart blocked by in-flight deploys, or null
 * when nothing blocks. Stale rows are listed so the operator can see them, but
 * on their own they never cause a refusal.
 */
export function inflightRefusal(db, action, staleMinutes = STALE_INFLIGHT_MINUTES) {
  const { blocking, stale } = listInflightDeploys(db, staleMinutes);
  if (blocking.length === 0) return null;
  return {
    error: {
      code: 'BUILDS_IN_FLIGHT',
      message: `Refusing to ${action}: ${blocking.length} deployment(s) currently in progress. `
        + 'Wait for them to finish or POST again with ?force=1.',
      in_flight: blocking,
      stale,
      stale_after_minutes: staleMinutes,
    },
  };
}
