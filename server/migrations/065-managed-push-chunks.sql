-- v2.21.17: pure-MCP large-file push for managed apps.
-- appcrane_managed_push_chunk stages a file part-by-part here; appcrane_managed_assemble
-- concatenates the parts in order, verifies the combined SHA-256, and commits to AMC_<slug>.
-- No HTTP side channel — the bytes travel entirely through MCP tool calls, split small
-- enough that inline emission stays reliable. Rows are deleted on assemble; stale sessions
-- (never assembled) are swept by age.
CREATE TABLE IF NOT EXISTS managed_push_chunks (
  session    TEXT    NOT NULL,           -- caller-chosen opaque upload id (groups the parts)
  user_id    INTEGER NOT NULL,           -- owner of the upload; only this user may add/assemble
  slug       TEXT    NOT NULL,           -- target managed app slug
  path       TEXT    NOT NULL,           -- repo-relative destination path
  part       INTEGER NOT NULL,           -- 1-based part number
  of_total   INTEGER NOT NULL,           -- declared total number of parts
  encoding   TEXT    NOT NULL DEFAULT 'utf-8',  -- 'utf-8' or 'base64' — how `content` decodes
  content    TEXT    NOT NULL,           -- this part's bytes, encoded per `encoding`
  sha256     TEXT,                       -- optional: SHA-256 (hex) of this part's decoded bytes
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (session, part)
);
CREATE INDEX IF NOT EXISTS idx_managed_push_chunks_created ON managed_push_chunks(created_at);
