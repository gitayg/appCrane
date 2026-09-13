-- migration:no-transaction
--
-- apps.repo_backend -- WHERE a managed app's git repository lives.
--
--   NULL    -> GitHub: the AMC_<slug> repo on the service account. Every row
--              that exists when this migration runs keeps NULL, so every
--              existing managed app keeps exactly today's behaviour with zero
--              data change.
--   'local' -> <DATA_DIR>/repos/<slug>.git on this host (services/localGit.js).
--              New managed apps are created with this value
--              (appcrane_create_managed_app).
--
-- THE COLUMN IS THE ONLY THING THAT DECIDES. services/managedRepo.js reads it
-- and nothing else: not whether <DATA_DIR>/repos/<slug>.git happens to exist,
-- not the shape of github_url. A stray directory left by a deleted app, or a
-- restored backup, must never silently move a production app off GitHub.
-- Moving an existing app (a later phase) is a deliberate UPDATE of this column
-- after its SHAs have been verified, one app at a time.
--
-- An unrecognised value is not treated as NULL. managedRepo.js refuses it, so a
-- typo fails the deploy or push loudly instead of routing to GitHub.
--
-- NO CHECK, following 072/075/076/077/078/085/086/088: SQLite cannot ALTER a
-- CHECK, so one here would force another rebuild the day a third backend is
-- added. The value set is enforced at the single reader (managedRepo.js) and
-- the single writer (mcpTools.js, appcrane_create_managed_app).
--
-- ================================================================
-- WHY THIS IS A TABLE REBUILD AND NOT `ALTER TABLE apps ADD COLUMN`
-- ================================================================
-- Same reason 086 and 088 give: test/app-catalog-slug.test.js and
-- test/upload-source-type.test.js assert that the NEWEST migration containing
-- `CREATE TABLE apps_new` restates the live apps table column for column. A
-- column added by ALTER after the newest rebuild is invisible to whoever writes
-- the next one, and a rebuild that does not name a column drops it without an
-- error. For this column that failure would be the worst kind: every local app
-- silently reads NULL afterwards and is routed to a GitHub repo that does not
-- exist.
--
-- BACKFILL: none, deliberately -- see NULL above.
--
-- The column list below is the live schema as of 089, verified against
-- PRAGMA table_info(apps) on a freshly migrated database: the 38 columns 088
-- restated, unchanged, plus repo_backend. Unlike 088 the INSERT names
-- container_command and volume_paths: rows written since 088 can hold values
-- in them, and a rebuild that left them out would drop every declared volume.

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
  repo_backend                TEXT
);

-- repo_backend is absent from both lists on purpose: every existing row must
-- come out NULL (GitHub), and leaving it out is the only way that is true by
-- construction rather than by a literal someone could get wrong.
INSERT INTO apps_new (
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port,
  image_ref, container_port, health_path, catalog_slug,
  container_command, volume_paths
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
  container_command, volume_paths
FROM apps;

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

PRAGMA foreign_keys = ON;
