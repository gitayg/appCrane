-- repo_migrations -- the per-app outcome of moving a GitHub-backed managed app
-- to <DATA_DIR>/repos/<slug>.git (services/repoMigration.js, run at boot).
--
-- A SEPARATE TABLE, not columns on apps:
--   - apps is guarded by the "newest apps rebuild restates every live
--     column" tests; adding status columns there forces a full rebuild of the
--     most important table for bookkeeping data.
--   - apps.repo_backend stays the ONLY routing input (see 090). A status
--     column next to it on the same row is one careless WHERE away from being
--     read as a second routing input. Here it cannot be.
--   - one row per app, overwritten per attempt, so the table stays as small as
--     the app count and "what happened to app X last boot" is a single lookup.
--
-- No FOREIGN KEY to apps: apps is rebuilt by DROP + RENAME (086/088/090), and a
-- reference that survives those rebuilds only by accident is worse than none.
-- An orphan row (app deleted) is harmless; the status route joins apps.
--
-- status: 'running' (written before any work -- left behind only if the process
--         died mid-app; the next boot overwrites it), 'migrated', 'failed',
--         'skipped' (not attempted for a reason that retrying will not fix by
--         itself, e.g. a local repo already on disk), 'deferred' (boot budget
--         ran out before this app; retried next boot).
-- refs_json: for 'migrated', the ref -> SHA map that GitHub and the staged
--            copy agreed on; for a SHA mismatch, the differing refs.
-- error never holds a credential: every message is scrubbed at the writer.

CREATE TABLE IF NOT EXISTS repo_migrations (
  app_id       INTEGER PRIMARY KEY,
  slug         TEXT NOT NULL,
  status       TEXT NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  error_code   TEXT,
  error        TEXT,
  refs_json    TEXT,
  branch       TEXT,
  started_at   TEXT,
  finished_at  TEXT,
  duration_ms  INTEGER
);
