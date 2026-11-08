-- migration:no-transaction
--
-- (Required: SQLite ignores PRAGMA foreign_keys inside a transaction, so a
-- wrapped rebuild would run DROP TABLE apps with foreign keys ON and cascade-
-- delete every child row -- deployments, roles, env. Same as 081-156.)
--
-- apps.secrets_namespace -- the path segment of an app's AWS Secrets Manager
-- secrets: <prefix>/<secrets_namespace>/<env>/<NAME>. Random, because neither
-- thing an app is otherwise known by stays with that app:
--
--   slug  freed by a delete or a rename, and the next holder would read the old
--         app's secrets. The secrets outlive the app, in AWS.
--   id    AUTOINCREMENT keeps its counter in sqlite_sequence, inside the same
--         file a restore swaps. Measured with exportDataArchive + importDataArchive:
--         back up at seq=2, create app id 3, restore, and the next new app is
--         id 3 again. A new host starts over at 1 against the same AWS prefix.
--
-- This value travels with the row through a backup, an import and a rename, and
-- a row that is not in the database has no way to read it back.
--
-- The default fills every existing row and every INSERT, from any writer, with
-- its own value (randomblob runs per row; a rebuild is the only way to get this:
-- ADD COLUMN refuses a non-constant default). A LATER REBUILD MUST NAME THIS
-- COLUMN IN ITS INSERT, or every app silently moves to a new, empty namespace:
-- test/secret-namespace-restore.test.js fails when it does not.
--
-- A TABLE REBUILD, NOT `ALTER TABLE apps ADD COLUMN`, for the reason 086, 090,
-- 102 and 156 give: the newest migration containing `CREATE TABLE apps_new` must
-- describe the live table exactly. The column list is 156's, restated unchanged,
-- plus secrets_namespace; the INSERT now names custom_domain_auth, since rows
-- written since 156 hold values in it.

PRAGMA foreign_keys = OFF;

CREATE TABLE apps_new (
  id                          INTEGER PRIMARY KEY AUTOINCREMENT,
  name                        TEXT NOT NULL,
  slug                        TEXT UNIQUE NOT NULL,
  slot                        INTEGER UNIQUE NOT NULL,
  domain                      TEXT,
  source_type                 TEXT NOT NULL DEFAULT 'github'
                                CHECK(source_type IN ('github', 'managed', 'managed_legacy', 'upload', 'image')),
  github_url                  TEXT,
  branch                      TEXT DEFAULT 'main',
  github_token_encrypted      TEXT,
  resource_limits             TEXT DEFAULT '{"max_ram_mb":512,"max_cpu_percent":50}',
  created_by                  INTEGER REFERENCES users(id),
  created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
  description                 TEXT,
  public_access               INTEGER NOT NULL DEFAULT 0,
  runtime                     TEXT NOT NULL DEFAULT 'docker',
  category                    TEXT,
  slug_aliases                TEXT,
  visibility                  TEXT NOT NULL DEFAULT 'private',
  image_retention             INTEGER NOT NULL DEFAULT 0,
  frame_ancestors             TEXT,
  claude_credentials_encrypted TEXT,
  auth_mode                   TEXT NOT NULL DEFAULT 'authenticated',
  auth_bypass_paths           TEXT,
  service_token_hash          TEXT,
  service_token_encrypted     TEXT,
  email_from_name             TEXT,
  last_managed_push_sha       TEXT,
  multitenant                 INTEGER NOT NULL DEFAULT 0,
  ingress_type                TEXT NOT NULL DEFAULT 'http',
  public_port                 INTEGER,
  data_plane_port             INTEGER,
  sandbox_public_port         INTEGER,
  image_ref                   TEXT,
  container_port              INTEGER,
  health_path                 TEXT,
  catalog_slug                TEXT,
  container_command           TEXT,
  volume_paths                TEXT,
  repo_backend                TEXT,
  data_plane_protocol         TEXT
                                CHECK(data_plane_protocol IS NULL OR data_plane_protocol IN ('tcp', 'udp')),
  custom_domain_auth          INTEGER NOT NULL DEFAULT 0,
  secrets_namespace           TEXT NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16))))
);

-- secrets_namespace is absent from both lists on purpose: every existing app
-- gets its own value from the default.
INSERT INTO apps_new (
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port,
  image_ref, container_port, health_path, catalog_slug,
  container_command, volume_paths, repo_backend, data_plane_protocol,
  custom_domain_auth
)
SELECT
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port,
  image_ref, container_port, health_path, catalog_slug,
  container_command, volume_paths, repo_backend, data_plane_protocol,
  custom_domain_auth
FROM apps;

-- The counter comes across too. Filling apps_new leaves it at MAX(id), so the
-- rebuilds before this one handed out again the id of the newest deleted app
-- (measured), and id-keyed rows with no foreign key would land on the next app.
DELETE FROM sqlite_sequence WHERE name = 'apps_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'apps_new', seq FROM sqlite_sequence WHERE name = 'apps';

DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;

-- Dropping the table dropped its indexes with it. These three are the explicit
-- ones; the UNIQUE constraints on slug and slot rebuild themselves from the
-- column definitions above. The two partial unique indexes are what stop two
-- apps claiming one host port (076), so losing them here would silently undo
-- per-env port safety.
CREATE INDEX IF NOT EXISTS idx_apps_service_token ON apps(service_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_public_port
  ON apps(public_port) WHERE public_port IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_sandbox_public_port
  ON apps(sandbox_public_port) WHERE sandbox_public_port IS NOT NULL;

-- Dropping the table dropped its triggers too. These are 124's, restated
-- unchanged: without them the database stops refusing an old app name
-- (kept as a redirect) to another app.
CREATE TRIGGER IF NOT EXISTS apps_slug_not_alias_insert
BEFORE INSERT ON apps
WHEN EXISTS (
  SELECT 1 FROM apps a,
    json_each(CASE WHEN json_valid(a.slug_aliases) THEN a.slug_aliases ELSE '[]' END) j
  WHERE j.value = NEW.slug
)
BEGIN
  SELECT RAISE(ABORT, 'SLUG_TAKEN');
END;

CREATE TRIGGER IF NOT EXISTS apps_slug_not_alias_update
BEFORE UPDATE OF slug ON apps
WHEN NEW.slug <> OLD.slug AND EXISTS (
  SELECT 1 FROM apps a,
    json_each(CASE WHEN json_valid(a.slug_aliases) THEN a.slug_aliases ELSE '[]' END) j
  WHERE j.value = NEW.slug AND a.id <> NEW.id
)
BEGIN
  SELECT RAISE(ABORT, 'SLUG_TAKEN');
END;

-- Once set it never changes: changing it is how an app would come to read
-- another app's secrets, or lose its own. Nothing in AppCrane writes it.
CREATE TRIGGER IF NOT EXISTS apps_secrets_namespace_immutable
BEFORE UPDATE OF secrets_namespace ON apps
WHEN NEW.secrets_namespace IS NOT OLD.secrets_namespace
BEGIN
  SELECT RAISE(ABORT, 'SECRETS_NAMESPACE_IMMUTABLE');
END;

PRAGMA foreign_keys = ON;
