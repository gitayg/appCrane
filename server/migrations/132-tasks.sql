-- Tasks: a platform service hosted apps use to assign work to people.
--
-- An app (authenticated by its APPCRANE_SERVICE_TOKEN, never by a header)
-- creates a task on behalf of a requester and assigns it to an assignee; both
-- must be active users with access to that app. Each person sees the tasks
-- they are a party to, across every app, in one inbox.
--
-- tasks.id is opaque (random base64url), never sequential. A deleted task is
-- soft-deleted (deleted_at) and hidden from everyone, app included.
-- task_events is the history and the app's poll cursor (its id is monotonic).
CREATE TABLE IF NOT EXISTS tasks (
  id                 TEXT PRIMARY KEY,
  app_id             INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  subject            TEXT NOT NULL,
  body               TEXT NOT NULL DEFAULT '',
  status             TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'done', 'declined')),
  requester_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assignee_user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  due_date           TEXT,
  external_ref       TEXT,
  url                TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  last_activity_at   TEXT NOT NULL,
  last_actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  deleted_at         TEXT,
  deleted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  deleted_via        TEXT CHECK(deleted_via IS NULL OR deleted_via IN ('app', 'dashboard'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_user_id, deleted_at, last_activity_at);
CREATE INDEX IF NOT EXISTS idx_tasks_requester ON tasks(requester_user_id, deleted_at, last_activity_at);
CREATE INDEX IF NOT EXISTS idx_tasks_app ON tasks(app_id, deleted_at, created_at);

CREATE TABLE IF NOT EXISTS task_comments (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id         TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  author_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  body            TEXT NOT NULL,
  via             TEXT NOT NULL CHECK(via IN ('app', 'dashboard')),
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_comments_task ON task_comments(task_id, id);

CREATE TABLE IF NOT EXISTS task_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id         TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL CHECK(kind IN ('created', 'comment', 'status', 'deleted')),
  actor_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  via             TEXT NOT NULL CHECK(via IN ('app', 'dashboard')),
  from_status     TEXT,
  to_status       TEXT,
  comment_id      INTEGER REFERENCES task_comments(id) ON DELETE CASCADE,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_events_app ON task_events(app_id, id);
CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id, id);

CREATE TABLE IF NOT EXISTS task_reads (
  task_id  TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  seen_at  TEXT NOT NULL,
  PRIMARY KEY (task_id, user_id)
);

-- Per-app Tasks settings, written by the app itself: the webhook it wants
-- assignee replies and status changes pushed to.
CREATE TABLE IF NOT EXISTS task_app_settings (
  app_id               INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  webhook_url          TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_status          TEXT,
  last_attempt_at      TEXT,
  updated_at           TEXT NOT NULL
);
