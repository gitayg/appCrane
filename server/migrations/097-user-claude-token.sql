-- user_claude_tokens -- the per-user Claude subscription token, so an agent
-- session runs on the subscription of the person who started it instead of on
-- a platform-wide API key.
--
-- The value is what Anthropic's `claude setup-token` prints: a one-year OAuth
-- token that the CLI saves nowhere and that is consumed as the
-- CLAUDE_CODE_OAUTH_TOKEN environment variable. Two properties of that token
-- shape this table:
--
--   expires_at   it does not refresh. It dies one year after it was generated
--                and regenerating it needs a browser, so the expiry is stored
--                at write time and shown in the UI rather than discovered as a
--                401 in the middle of a session. NULL only for a row written
--                before the column had a value to put in it; the writer
--                (services/userClaudeToken.js) always fills it, defaulting to
--                one year out.
--
--   ONE ROW PER USER, user_id as the PRIMARY KEY. There is no version history
--   and no second token: a user has a subscription token or does not, and
--   PUT replaces. A second row would make "which token does this session get"
--   a choice, and the wrong choice is a silent fallback to an expired token.
--
-- token_encrypted holds a services/encryption.js envelope (AES-256-GCM,
-- iv:tag:ciphertext), the same treatment as apps.claude_credentials_encrypted
-- and env_vars.value_encrypted. Never plaintext, never logged.
--
-- ON DELETE CASCADE, like 087's log_permissions and 095's app_env_files: this
-- row is a live credential, and deleting the user must take it with them
-- rather than leave a decryptable token behind under an id that may later be
-- reused. routes/users.js deletes with foreign_keys = ON (server/db.js sets
-- the pragma on every connection), so the cascade actually fires.
--
-- A FOREIGN KEY here is safe where 091/092 declined one: those referenced
-- `apps`, which is rebuilt by DROP + RENAME in 086/088/090. `users` has been
-- rebuilt exactly once (046) -- long before this migration -- and a rebuild of
-- it would have to preserve ids anyway, since sessions, audit rows and app
-- grants are all keyed to them.
--
-- No `-- migration:no-transaction`: this file is plain DDL. That marker exists
-- for connection-level state SQLite refuses to change inside a transaction
-- (PRAGMA writable_schema, PRAGMA foreign_keys); nothing here touches either,
-- so the default transactional apply is correct and gives the file
-- all-or-nothing semantics.

CREATE TABLE IF NOT EXISTS user_claude_tokens (
  user_id          INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_encrypted  TEXT NOT NULL,
  expires_at       TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
