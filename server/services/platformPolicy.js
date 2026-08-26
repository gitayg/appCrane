// Platform-wide policy that CONSTRAINS per-app settings.
//
// Until now every control was per-app: an owner set visibility, auth_mode and
// so on, and nothing above them could say "not on this platform". A platform
// admin could see a public app but not prevent the next one.
//
// Two levers, both off by default so an upgrade changes nothing:
//   ban_public_apps        — refuse visibility=public anywhere
//   mandate_security_scans — every app is scanned; owners cannot opt out, and
//                            apps without a recent scan are reported
//
// Deliberately NOT retroactive on its own. Turning ban_public_apps on does not
// reach into the database and flip existing public apps private: that would
// break live URLs with no warning and no way to see what changed. It refuses
// the NEXT write and reports the apps already in violation, so an admin
// converts them deliberately.

import { AppError } from '../utils/errors.js';

export const POLICY_KEYS = {
  banPublicApps: 'policy_ban_public_apps',
  mandateScans:  'policy_mandate_security_scans',
};

// The scan runs daily. A 24h window would flag every app for the minutes
// between the check and that day's run, so the threshold is two missed runs:
// past 48h the daily scan is not merely late, it has stopped happening.
const SCAN_STALE_AFTER = '-48 hours';

function get(db, k) { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r?.value ?? ''; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v ?? ''), userId ?? null);
}

/** @returns {{ ban_public_apps: boolean, mandate_security_scans: boolean }} */
export function getPolicy(db) {
  // Absent key reads as '' reads as false. That is the default-off promise:
  // an upgrade that has never written these rows enforces nothing.
  return {
    ban_public_apps: get(db, POLICY_KEYS.banPublicApps) === '1',
    mandate_security_scans: get(db, POLICY_KEYS.mandateScans) === '1',
  };
}

/** Patch is partial; only supplied keys change. Returns the full policy. */
export function setPolicy(db, patch, userId) {
  const p = patch || {};
  const map = {
    ban_public_apps: v => set(db, POLICY_KEYS.banPublicApps, v ? '1' : '0', userId),
    mandate_security_scans: v => set(db, POLICY_KEYS.mandateScans, v ? '1' : '0', userId),
  };
  for (const [k, fn] of Object.entries(map)) if (p[k] !== undefined) fn(p[k]);
  return getPolicy(db);
}

/**
 * Throw when `visibility` is forbidden by policy. Called on every write path
 * that can set visibility, so the refusal cannot be routed around by using a
 * different surface.
 */
export function assertVisibilityAllowed(db, visibility) {
  if (visibility !== 'public') return;
  if (!getPolicy(db).ban_public_apps) return;
  // The message names the key, not just "policy": an owner refused here has no
  // way to read the settings table and no reason to guess which of the platform
  // levers stopped them. Naming it is the difference between a refusal they can
  // act on and a ticket.
  throw new AppError(
    "Platform policy 'ban_public_apps' is on: apps on this platform cannot be public. "
    + "Use visibility 'private' or 'hidden', or ask a platform admin to turn the policy off.",
    403, 'POLICY_BAN_PUBLIC_APPS',
  );
}

/** Apps that violate current policy right now — reported, never auto-changed. */
export function policyViolations(db) {
  const policy = getPolicy(db);
  const violations = [];

  if (policy.ban_public_apps) {
    // public_access is the other half of the same fact (see appVisibility.js),
    // and a row where the two disagree is exactly the one an admin needs to see.
    for (const a of db.prepare(`
      SELECT id, slug, name, visibility, public_access FROM apps
      WHERE visibility = 'public' OR public_access = 1 ORDER BY slug
    `).all()) {
      violations.push({
        app_id: a.id, slug: a.slug, name: a.name,
        policy: 'ban_public_apps',
        detail: `visibility='${a.visibility}', public_access=${a.public_access}`,
      });
    }
  }

  if (policy.mandate_security_scans) {
    // app_vuln_scans arrives with the scanner. This lever can be turned on by an
    // admin on a box whose migrations have not reached it yet, and a missing
    // table must not take the policy page down with a SQLITE_ERROR — nor read as
    // "everything is scanned", which is the failure the whole feature exists to
    // avoid. No table means nothing has ever been scanned, and that is reported.
    const scansExist = !!db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_vuln_scans'"
    ).get();

    const rows = scansExist
      // Newest row across ALL envs: the mandate is "this app gets scanned", and
      // an app that only ever ran in production would otherwise be reported
      // forever for a sandbox that does not exist.
      //
      // datetime() rather than a raw string compare because the column takes
      // both datetime('now') and ISO timestamps; an unparseable value yields
      // NULL, which fails the freshness test — a timestamp nobody can read is
      // not evidence of a recent scan.
      ? db.prepare(`
          SELECT a.id, a.slug, a.name,
                 (SELECT MAX(datetime(s.scanned_at)) FROM app_vuln_scans s
                   WHERE s.app_id = a.id AND s.status != 'error') AS last_ok_scan
          FROM apps a ORDER BY a.slug
        `).all()
      : db.prepare('SELECT id, slug, name, NULL AS last_ok_scan FROM apps ORDER BY slug').all();

    const cutoff = db.prepare("SELECT datetime('now', ?) AS t").get(SCAN_STALE_AFTER).t;
    for (const a of rows) {
      if (a.last_ok_scan && a.last_ok_scan >= cutoff) continue;
      violations.push({
        app_id: a.id, slug: a.slug, name: a.name,
        policy: 'mandate_security_scans',
        // A completed scan that found nothing and a scan that never ran are
        // different states and are reported as different states.
        detail: a.last_ok_scan
          ? `last completed scan ${a.last_ok_scan} is older than the 48h daily cadence`
          : 'never scanned successfully',
      });
    }
  }

  return violations;
}
