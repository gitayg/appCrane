/**
 * One-shot owner backfill (v2.5.13+).
 *
 * Replaces the failed migration 055 — running this as a SQL migration
 * was too risky: any SQL hiccup tanked the migration runner's
 * transaction, the boot crashed, and the safe-boot rollback fired.
 * Symptom for the operator: "self-update failed - error 502."
 *
 * Same intent: every app whose creator is still active should have an
 * owner row in app_user_roles. Apps created before v2.5.12 missed this
 * because the create-paths only wrote `app_users` (membership) and
 * forgot the role row.
 *
 * Runs at server boot, logs success / failure, NEVER throws. AppCrane
 * stays bootable even if this can't run.
 */

import { getDb } from '../db.js';
import log from '../utils/logger.js';

let _ran = false;

export function backfillAppOwners() {
  if (_ran) return; // idempotent — safe to call multiple times per process
  _ran = true;

  try {
    const db = getDb();
    const result = db.prepare(`
      INSERT OR IGNORE INTO app_user_roles (app_id, user_id, app_role)
      SELECT a.id, a.created_by, 'owner'
      FROM apps a
      JOIN users u ON u.id = a.created_by AND u.active = 1
      WHERE a.created_by IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM app_user_roles aur
          WHERE aur.app_id = a.id AND aur.app_role = 'owner'
        )
    `).run();
    if (result.changes > 0) {
      log.info(`[owner-backfill] promoted ${result.changes} app creator(s) to owner`);
    } else {
      log.info('[owner-backfill] no orphan apps to promote');
    }
  } catch (e) {
    // Defensive log + continue. The server staying up matters more than
    // this housekeeping task succeeding. The "⚠ No owner" badge keeps
    // showing for affected apps until an admin grants ownership manually.
    log.warn(`[owner-backfill] failed (continuing without): ${e.message}`);
  }
}
