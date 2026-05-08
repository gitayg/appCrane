-- migration:no-transaction
--
-- v2.3.1: hard-remove the 'upload' source_type while preserving legacy data.
--
-- Existing upload-based apps (e.g. ClientPortal) keep their on-disk releases
-- under data/apps/<slug>/<env>/releases/<ts>-upload/ and need to keep
-- redeploying from those artifacts until they're migrated to a service-
-- account repo. We alias their source_type to 'managed_legacy' so:
--
--   * deployer.js can branch on a clearly-labeled deprecated value
--   * the apps table CHECK no longer accepts 'upload' for new rows
--   * a future migration tool can find them with a single query
--
-- Going forward, only 'github' and 'managed' (service-account-owned repo)
-- are valid source_types for new apps. 'managed_legacy' exists solely as a
-- deprecation marker and is rejected by POST/PUT /api/apps.
--
-- Pattern matches 046 / 048 / 049: foreign_keys=OFF + table rebuild outside
-- a transaction. Required because the original CHECK was IN ('github',
-- 'upload'), so a plain UPDATE to 'managed_legacy' would fail the
-- constraint. The writable_schema approach is blocked by better-sqlite3's
-- defensive guard; rebuild is the only path that works.

PRAGMA foreign_keys = OFF;

CREATE TABLE apps_new (
  id                          INTEGER PRIMARY KEY AUTOINCREMENT,
  name                        TEXT NOT NULL,
  slug                        TEXT UNIQUE NOT NULL,
  slot                        INTEGER UNIQUE NOT NULL,
  domain                      TEXT,
  source_type                 TEXT NOT NULL DEFAULT 'github'
                                CHECK(source_type IN ('github', 'managed', 'managed_legacy')),
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
  claude_credentials_encrypted TEXT
);

-- Copy + remap on the way: any 'upload' row becomes 'managed_legacy' so
-- the data is preserved without violating the new CHECK.
INSERT INTO apps_new (
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted
)
SELECT
  id, name, slug, slot, domain,
  CASE WHEN source_type = 'upload' THEN 'managed_legacy' ELSE source_type END,
  github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted
FROM apps;

DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;

PRAGMA foreign_keys = ON;
