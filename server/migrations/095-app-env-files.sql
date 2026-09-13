-- app_env_files -- .env files an app must still have in its release but that
-- must NEVER be committed to its repository.
--
-- Written by services/uploadConversion.js when an uploaded app becomes
-- Crane-hosted: every .env* file of each environment's release, with its path
-- relative to the release root and its file mode. The content is encrypted with
-- services/encryption.js (the same AES-256-GCM as env_vars.value_encrypted) and
-- is never logged or recorded anywhere else.
--
-- Read by services/envFileStore.js at deploy time: deployer.js writes each file
-- back into the fresh clone of the local repository, before the build, so the
-- build context is what the uploaded bundle had. Production reads only
-- env='production' rows and sandbox only env='sandbox' rows.
--
-- Why not in git: a committed secret is in every repository backup forever and
-- readable through the managed-repo read tools and Ask Claude's local-repo tools.
-- deployhub.db, where this table lives, is already in the data archive.
--
-- A new migration rather than an edit of 094: 094 may already be recorded as
-- applied in a database that ran this tree, and the runner keys on file name, so
-- an edited 094 would never reach it.
--
-- ON DELETE CASCADE, unlike 091/094's outcome tables: those rows are harmless
-- bookkeeping, these are secrets, and an app delete (routes/apps.js deletes the
-- apps row with foreign_keys = ON) must take them with it. env_vars has carried
-- the same REFERENCES apps(id) ON DELETE CASCADE through every apps rebuild
-- (086/088/090 rebuild with foreign_keys OFF and rename into the name `apps`,
-- which is the name a reference binds to).

CREATE TABLE IF NOT EXISTS app_env_files (
  app_id             INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env                TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  rel_path           TEXT NOT NULL,
  mode               INTEGER NOT NULL,
  bytes              INTEGER NOT NULL,
  content_encrypted  TEXT NOT NULL,
  source             TEXT NOT NULL DEFAULT 'upload_conversion',
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env, rel_path)
);
