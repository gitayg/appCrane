import os from 'os';
import { getDb } from '../db.js';

// Does the sum of every app's configured memory limit fit in the host?
//
// AppCrane enforces a per-container ceiling and has never had an opinion about
// the total. On a 7.6 GB host, 50+ apps at the 512 MB default commit ~25 GB of
// theoretical maximum. That is not automatically wrong — containers idle near
// zero and the kernel only cares about resident pages — but it means the host
// has no headroom guarantee at all, and a correlated event (a post-reboot cold
// start, where every container loads at once) resolves it the only way the
// kernel can: the global OOM killer picks the largest process and the host may
// never recover. That is the August 2026 shape.
//
// REPORT, DO NOT BLOCK — a deliberate decision, not an omission.
// The fleet is ALREADY over-committed by roughly 3x. A guard that refused any
// change while the sum exceeds host RAM would reject every ordinary edit on
// every app from the moment it shipped, including edits that REDUCE the total.
// A gate that must be disabled to get work done is not a safety control.
//
// So: always answer the question, and warn on the change that makes it worse.

const DEFAULT_MB = 512;

// A deployed app commits its limit TWICE: production and sandbox are separate
// containers created from the same `resource_limits` row.
const ENVS_PER_APP = 2;

const TOP_N = 5;

const MB = 1024 * 1024;

/**
 * The per-container limit an app actually carries.
 * `resource_limits` is free-form JSON on the apps row, so it can be null, be
 * unparseable, or simply not mention memory — every one of those is the 512 MB
 * default that `docker run` will be handed, not zero.
 */
function limitMbOf(resourceLimits) {
  let parsed;
  try {
    parsed = JSON.parse(resourceLimits || '{}');
  } catch {
    parsed = {};
  }
  const mb = Number(parsed?.max_ram_mb);
  return Number.isFinite(mb) && mb > 0 ? mb : DEFAULT_MB;
}

/** Total host RAM in MB. */
export function hostMemoryMb() {
  return Math.round(os.totalmem() / MB);
}

/**
 * One picture of the fleet, optionally with one app's limit replaced.
 *
 * The override runs through the same query and the same arithmetic as the
 * plain reading, so a proposal and the status quo can never be computed two
 * different ways — including `top`, which has to re-rank when the proposed
 * number is the largest one on the host.
 *
 * An app with no rows in `deployments` has no container and so commits
 * nothing; overriding its limit therefore moves no total, which is the honest
 * answer rather than a special case.
 */
function picture(db, overrideAppId, overrideMb) {
  const rows = db.prepare(`
    SELECT a.id, a.slug, a.resource_limits
      FROM apps a
     WHERE EXISTS (SELECT 1 FROM deployments d WHERE d.app_id = a.id)
     ORDER BY a.slug
  `).all();

  const override = Number(overrideMb);
  const overriding = overrideAppId != null && Number.isFinite(override) && override > 0;

  const apps = rows.map(r => ({
    slug: r.slug,
    max_ram_mb: overriding && Number(r.id) === Number(overrideAppId)
      ? override
      : limitMbOf(r.resource_limits),
  }));

  const host_mb = hostMemoryMb();
  const committed_mb = apps.reduce((total, a) => total + a.max_ram_mb * ENVS_PER_APP, 0);

  return {
    host_mb,
    committed_mb,
    headroom_mb: host_mb - committed_mb,
    // Exactly filling the host is not over-committing it. It is the last
    // configuration whose promise the kernel can still keep.
    over_committed: committed_mb > host_mb,
    ratio: host_mb > 0 ? Math.round((committed_mb / host_mb) * 100) / 100 : 0,
    app_count: apps.length,
    top: [...apps]
      .sort((a, b) => b.max_ram_mb - a.max_ram_mb || a.slug.localeCompare(b.slug))
      .slice(0, TOP_N),
  };
}

/**
 * The whole picture, in one read.
 * @returns {{
 *   host_mb: number, committed_mb: number, headroom_mb: number,
 *   over_committed: boolean, ratio: number, app_count: number,
 *   top: Array<{slug: string, max_ram_mb: number}>
 * }}
 * `committed_mb` counts BOTH environments for every app that has a container,
 * because a post-reboot cold start brings both up at once — counting one would
 * understate the exact scenario this exists to describe.
 */
export function memoryBudget(db = getDb()) {
  return picture(db, null, null);
}

// Named in every message, because the number alone reads as an accounting
// nicety. What makes over-commitment worth reporting is that the kernel
// resolves it globally: the process it kills is the largest one on the host,
// not the one whose limit was raised.
const CONSEQUENCE =
  'Nothing enforces the total — every limit is a per-container ceiling — so a correlated ' +
  'cold start, where a host reboot brings production and sandbox up for every app at once, ' +
  'resolves the only way the kernel can: a global OOM kill, which picks the largest process ' +
  'on the host and not necessarily the one that grew.';

/**
 * Assess a proposed change to one app's limit.
 * @param {number|null} nextMb  the limit being set, or null when only reading
 * @returns {{ level: 'ok'|'notice'|'warn', message: string, budget: object }}
 *   'warn'   — this change pushes the committed total past host RAM, or the
 *              fleet is already over and this makes it materially worse.
 *   'notice' — already over-committed, and this change does not worsen it.
 *   'ok'     — the total still fits.
 * Never throws on an over-committed fleet: see the header.
 */
export function assessMemoryChange(db, appId, nextMb) {
  const handle = db || getDb();
  const before = picture(handle, null, null);
  const after = picture(handle, appId, nextMb);
  const delta = after.committed_mb - before.committed_mb;

  const row = handle.prepare('SELECT slug, resource_limits FROM apps WHERE id = ?').get(appId);
  const slug = row?.slug ?? `app ${appId}`;
  const proposed = Number(nextMb);
  const appliedMb = Number.isFinite(proposed) && proposed > 0
    ? proposed
    : limitMbOf(row?.resource_limits);
  const over = after.committed_mb - after.host_mb;

  if (!after.over_committed) {
    const fixed = before.over_committed
      ? ` That brings the fleet back inside the host: it was ${before.committed_mb} MB.`
      : '';
    return {
      level: 'ok',
      message:
        `The fleet commits ${after.committed_mb} MB against ${after.host_mb} MB of host RAM ` +
        `(${after.headroom_mb} MB headroom) across ${after.app_count} deployed app` +
        `${after.app_count === 1 ? '' : 's'}, both environments each.${fixed}`,
      budget: after,
    };
  }

  // "Materially worse" is any increase at all, deliberately. The alternative is
  // a MB floor under which growth is free, and a floor is exactly the kind of
  // number that reads as a guarantee and is not one: there is no size of
  // increase that the kernel forgives once the total no longer fits.
  if (delta > 0) {
    return {
      level: 'warn',
      message:
        `Setting ${slug} to ${appliedMb} MB per container ` +
        `takes the fleet from ${before.committed_mb} MB to ${after.committed_mb} MB ` +
        `committed against ${after.host_mb} MB of host RAM — ${after.ratio}x, ${over} MB more than ` +
        `the host has. ${CONSEQUENCE}`,
      budget: after,
    };
  }

  const direction = delta < 0
    ? `this change gives back ${-delta} MB of that and is an improvement`
    : 'this change does not move that total';
  return {
    level: 'notice',
    message:
      `The fleet already commits ${after.committed_mb} MB against ${after.host_mb} MB of host RAM ` +
      `(${after.ratio}x, ${over} MB more than the host has); ${direction}. ${CONSEQUENCE}`,
    budget: after,
  };
}
