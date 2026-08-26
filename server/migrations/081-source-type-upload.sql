-- migration:no-transaction
--
-- v2.53.0: let apps.source_type be 'upload' again.
--
-- 052 removed it, correctly for the time: an uploaded release recorded
-- commit_hash = whatever the uploader typed, or the literal 'unknown', so the
-- source type named a deploy path with no provenance behind it. 080 supplies
-- the missing piece — a SHA-256 AppCrane computes over the received bytes — so
-- the value is reinstated on that basis rather than by reversing the judgement.
--
-- 'managed_legacy' stays in the allowed set and is NOT revived as a
-- destination. It remains a deprecation marker for pre-052 rows whose deployer
-- branch replays an old release directory instead of accepting new uploads;
-- folding those into 'upload' would make dead apps look current.
--
-- Table rebuild, matching 046 / 048 / 049 / 052. The writable_schema shortcut
-- was tried first and is genuinely unavailable: better-sqlite3 runs with
-- SQLITE_DBCONFIG_DEFENSIVE and rejects the UPDATE with "table sqlite_master
-- may not be modified", exactly as 052's comment warned.
--
-- The column list below is the live schema as of 080. A rebuild that omits a
-- column drops its data silently, and apps has gained eleven columns since 052
-- (auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
-- email_from_name, last_managed_push_sha, multitenant, ingress_type,
-- public_port, data_plane_port, sandbox_public_port). test/upload-source-type.test.js
-- compares the rebuilt table against the pre-migration column set so that a
-- future omission fails a test instead of losing a column in production.

PRAGMA foreign_keys = OFF;

CREATE TABLE apps_new (
  id                          INTEGER PRIMARY KEY AUTOINCREMENT,
  name                        TEXT NOT NULL,
  slug                        TEXT UNIQUE NOT NULL,
  slot                        INTEGER UNIQUE NOT NULL,
  domain                      TEXT,
  source_type                 TEXT NOT NULL DEFAULT 'github'
                                CHECK(source_type IN ('github', 'managed', 'managed_legacy', 'upload')),
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
  sandbox_public_port         INTEGER
);

INSERT INTO apps_new (
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port
)
SELECT
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port
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
