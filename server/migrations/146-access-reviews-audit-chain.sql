-- Periodic access reviews (services/accessReviews/) and the tamper-evident
-- audit chain (services/auditChain.js).

-- ── Access reviews ─────────────────────────────────────────────────────────
-- A campaign is one review round. scope 'default' covers every app whose data
-- classification has no cadence of its own, plus the platform-admin review;
-- a classification level ('restricted', ...) covers only apps at that level.
CREATE TABLE IF NOT EXISTS access_review_campaigns (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT    NOT NULL,
  scope                TEXT    NOT NULL DEFAULT 'default',
  status               TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  started_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  due_at               TEXT    NOT NULL,
  grace_until          TEXT    NOT NULL,
  closed_at            TEXT,
  created_by           INTEGER,
  overdue_action       TEXT    NOT NULL DEFAULT 'none' CHECK (overdue_action IN ('none', 'report')),
  escalated_at         TEXT,
  grace_processed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_scope ON access_review_campaigns(scope, started_at);

-- One review per app (reviewed by its owners) and one platform review
-- (reviewed by platform admins). App name and slug are copied so the evidence
-- survives the app being deleted.
CREATE TABLE IF NOT EXISTS access_reviews (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id         INTEGER NOT NULL REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
  kind                TEXT    NOT NULL CHECK (kind IN ('app', 'platform')),
  app_id              INTEGER,
  app_slug            TEXT,
  app_name            TEXT,
  data_classification TEXT,
  status              TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed')),
  completed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_reviews_campaign ON access_reviews(campaign_id);

CREATE TABLE IF NOT EXISTS access_review_reviewers (
  review_id INTEGER NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  user_id   INTEGER NOT NULL,
  PRIMARY KEY (review_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_access_review_reviewers_user ON access_review_reviewers(user_id);

-- One row per person with a role, as it stood when the campaign started.
-- granted_via: 'direct' | 'scim' (scim_group_access holds a ledger row, so
-- the identity provider owns the grant and it cannot be changed here).
CREATE TABLE IF NOT EXISTS access_review_items (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id      INTEGER NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  user_id        INTEGER NOT NULL,
  user_name      TEXT,
  user_email     TEXT,
  role           TEXT    NOT NULL,
  granted_via    TEXT    NOT NULL DEFAULT 'direct' CHECK (granted_via IN ('direct', 'scim')),
  last_access_at TEXT,
  decision       TEXT    CHECK (decision IN ('keep', 'remove', 'change')),
  new_role       TEXT,
  note           TEXT,
  decided_by     INTEGER,
  decided_at     TEXT,
  UNIQUE (review_id, user_id)
);

-- ── Audit chain ────────────────────────────────────────────────────────────
-- One hash chain per source table, in row id order:
--   row_hash   = SHA-256 of the row's canonical serialisation
--   alt_hash   = audit_log only: the row hashed with user_id and/or app_id
--                cleared, so deleting a user or an app (which clears them) is
--                told apart from an edit
--   meta       = events only: [ts, severity], so a row removed by retention
--                can be told apart from a row deleted by hand
--   chain_hash = SHA-256(prev chain_hash | row_hash | alt_hash | meta)
-- Rows are never updated; entries are deleted only by compaction, below a
-- signed 'compaction' checkpoint whose chain_hash becomes the new start.
CREATE TABLE IF NOT EXISTS audit_chain (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  src        TEXT    NOT NULL CHECK (src IN ('audit_log', 'events')),
  row_id     INTEGER NOT NULL,
  row_hash   TEXT    NOT NULL,
  alt_hash   TEXT,
  meta       TEXT,
  chain_hash TEXT    NOT NULL,
  sealed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (src, row_id)
);

-- HMAC-signed anchors (key derived from ENCRYPTION_KEY). kind:
--   seal        the chain of src ended at upto_row_id with chain_hash
--   retention   the event retention windows in force (data), for telling a
--               pruned event from a deleted one
--   compaction  chain entries of src up to upto_row_id were removed; chain_hash
--               is where verification resumes
-- prev_signature links each checkpoint to the one before it.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  kind           TEXT    NOT NULL CHECK (kind IN ('seal', 'retention', 'compaction')),
  src            TEXT,
  upto_row_id    INTEGER,
  chain_hash     TEXT,
  data           TEXT,
  created_at     TEXT    NOT NULL,
  prev_signature TEXT,
  signature      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_chain_verifications (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ran_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  ok          INTEGER NOT NULL,
  checked     INTEGER NOT NULL DEFAULT 0,
  problems    TEXT,
  trigger_by  TEXT
);

CREATE TRIGGER IF NOT EXISTS audit_chain_append_only
BEFORE UPDATE ON audit_chain
BEGIN
  SELECT RAISE(ABORT, 'audit_chain is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_chain_checkpoints_append_only
BEFORE UPDATE ON audit_chain_checkpoints
BEGIN
  SELECT RAISE(ABORT, 'audit_chain_checkpoints are append-only');
END;

-- No append-only trigger on audit_log yet: apps.js deletes an app's audit rows
-- with the app and several tests delete or back-date audit rows, so a trigger
-- here breaks them. The chain still detects every such change.

-- Platform mail (app_id NULL) is not deduped by idx_email_queue_idem; these
-- keys name the review or failure, so each notice goes out once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_access_review_chain
  ON email_queue(idempotency_key)
  WHERE source IN ('access-review', 'audit-chain') AND idempotency_key IS NOT NULL;
