-- v2.2.18: staged-uploads table for MCP-E (large-file push to containers).
--
-- An MCP client (Claude Code, etc.) uploads a file to /api/files/staged,
-- which writes it to <DATA_DIR>/staged/<token>/<filename> and inserts a row
-- here. The client then calls the appcrane_push_staged_file MCP tool with
-- the token, which docker-cp's the staged file into a target container at
-- a path validated by validateContainerPath (/app or /data only).
--
-- The token is the row's primary key (opaque base64url, 16 bytes random).
-- It's also used as the scratch directory name, so leaking the scratch path
-- requires guessing the token (effectively impossible).
--
-- Lifetime: rows + scratch dirs are reaped by a 5-minute sweep job once
-- expires_at < now. Default TTL is 10 minutes from upload — long enough for
-- the agent to call push, short enough that an idle leak self-heals.

CREATE TABLE IF NOT EXISTS staged_files (
  token        TEXT PRIMARY KEY,
  user_id      INTEGER NOT NULL,
  filename     TEXT NOT NULL,
  size_bytes   INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  scratch_path TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at   TEXT NOT NULL,
  pushed_at    TEXT,                  -- set when appcrane_push_staged_file consumed it
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_staged_files_expires ON staged_files(expires_at);
CREATE INDEX IF NOT EXISTS idx_staged_files_user    ON staged_files(user_id);
