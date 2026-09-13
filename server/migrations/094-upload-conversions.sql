-- upload_conversions -- the per-app outcome of turning an uploaded app
-- (source_type='upload') into a Crane-hosted one (source_type='managed',
-- repo_backend='local'), run at boot by services/uploadConversion.js.
--
-- A separate table for the same reasons 091 gives for repo_migrations: the apps
-- table is not rebuilt for bookkeeping, and apps.source_type / apps.repo_backend
-- stay the only routing inputs.
--
-- One row per app, overwritten per attempt. No FOREIGN KEY to apps (it is
-- rebuilt by DROP + RENAME); the status route joins apps.
--
-- status: 'running'      written before any work
--         'installing'   the repo was staged and verified and is about to be
--                        renamed into place; tip holds the commit it must have.
--                        Left behind only by a crash between the rename and the
--                        database flip, which the next boot completes after
--                        re-checking the repo against tip.
--         'flip_failed'  the repo is in place but the database flip did not
--                        commit; retried next boot the same way as 'installing'
--         'converted', 'failed', 'skipped', 'deferred'
--
-- NEVER holds an environment variable value: imported_keys_json,
-- kept_existing_json and invalid_keys_json are key NAMES, excluded_json is
-- paths, and parse errors carry line numbers only.

CREATE TABLE IF NOT EXISTS upload_conversions (
  app_id              INTEGER PRIMARY KEY,
  slug                TEXT NOT NULL,
  status              TEXT NOT NULL,
  attempts            INTEGER NOT NULL DEFAULT 0,
  error_code          TEXT,
  error               TEXT,
  tip                 TEXT,
  commits_json        TEXT,
  imported_keys_json  TEXT,
  kept_existing_json  TEXT,
  invalid_keys_json   TEXT,
  warnings_json       TEXT,
  excluded_json       TEXT,
  excluded_count      INTEGER,
  skipped_files_json  TEXT,
  detail_json         TEXT,
  tracked_bytes       INTEGER,
  started_at          TEXT,
  finished_at         TEXT,
  duration_ms         INTEGER
);
