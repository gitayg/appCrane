-- v2.54.0: chunked file staging over MCP, with no app or repo attached.
--
-- managed_push_chunks already carries base64 parts over JSON-RPC with a
-- per-part SHA-256, which is exactly the transport needed here — but every row
-- is bound to a managed app and a repo-relative path, because assembly commits
-- to AMC_<slug> on GitHub. That destination is the one an expired
-- service-account PAT closes, and it is the wrong destination for an upload
-- app, which has no repo at all.
--
-- This table is the same transport pointed somewhere else: parts belong to a
-- user and a session, and assembly produces a staged_files row that
-- appcrane_deploy_artifact already knows how to consume. No slug, because the
-- bytes are not an app's until a deploy claims them.
CREATE TABLE IF NOT EXISTS stage_chunks (
  session    TEXT    NOT NULL,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  part       INTEGER NOT NULL,
  of_total   INTEGER NOT NULL,
  content    TEXT    NOT NULL,
  sha256     TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (session, part)
);

CREATE INDEX IF NOT EXISTS idx_stage_chunks_user ON stage_chunks(user_id);
