-- Bugs / notes / reviews thread attached to an enhancement request.
--
-- Until now there were two append-only text columns on the request row
-- (user_comments, admin_comments) used by the plan-feedback flow. They
-- can't carry status (open/resolved), can't be filtered by type, and
-- can't be authored by the right user when multiple people interact
-- with the same request. This table replaces that pattern for any
-- structured back-and-forth — bugs, notes, peer reviews — that the
-- planner and coder should treat as additional context on every run.
--
-- Agent prompt assembly (services/appstudio/planner.js + generator.js)
-- queries open rows for the active enhancement and appends them as an
-- '## Open feedback to address' section, so re-runs naturally pick up
-- whatever the operator added since the last attempt.
--
-- ON DELETE CASCADE keeps the table tidy when a request is deleted.

CREATE TABLE IF NOT EXISTS enhancement_comments (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  enhancement_id  INTEGER NOT NULL REFERENCES enhancement_requests(id) ON DELETE CASCADE,
  type            TEXT NOT NULL DEFAULT 'note',  -- bug | note | review
  body            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'open',  -- open | resolved
  author_user_id  INTEGER REFERENCES users(id),
  author_name     TEXT,                          -- denormalized so deleted users still display
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at     TEXT,
  resolved_by     INTEGER REFERENCES users(id),
  CHECK (type IN ('bug', 'note', 'review')),
  CHECK (status IN ('open', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_enhancement_comments_enh
  ON enhancement_comments(enhancement_id);
CREATE INDEX IF NOT EXISTS idx_enhancement_comments_open
  ON enhancement_comments(enhancement_id, status) WHERE status = 'open';
