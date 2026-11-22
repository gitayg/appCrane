-- EU AI Act deployer records (services/aiAct/*).
--
-- app_ai_profile: one row per app that answered the intake "AI use" question
-- or set a transparency notice. Kept out of app_intake so the intake upsert
-- and a later app_intake rebuild never touch it. No row reads as "not answered".
CREATE TABLE IF NOT EXISTS app_ai_profile (
  app_id              INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  ai_use              TEXT CHECK (ai_use IS NULL OR ai_use IN ('none', 'assistive', 'decisions_about_people', 'annex_iii')),
  annex_iii_category  TEXT,
  ai_use_set_by       INTEGER,
  ai_use_set_at       TEXT,
  -- Set when a platform admin chose the answer: owners cannot change it then.
  ai_use_locked       INTEGER NOT NULL DEFAULT 0 CHECK (ai_use_locked IN (0, 1)),
  -- Set when an owner lowered the answer: production waits for a platform
  -- admin's intake approval, which clears it.
  ai_review_required  INTEGER NOT NULL DEFAULT 0 CHECK (ai_review_required IN (0, 1)),
  notice_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (notice_enabled IN (0, 1)),
  notice_text         TEXT,
  notice_updated_by   INTEGER,
  notice_updated_at   TEXT,
  CHECK (ai_use = 'annex_iii' OR annex_iii_category IS NULL),
  CHECK (ai_use IS NOT 'annex_iii' OR annex_iii_category IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_app_ai_profile_use ON app_ai_profile (ai_use);

-- One row per user and statement version: the AI-literacy acknowledgement a
-- builder gives before classifying an app as using AI.
CREATE TABLE IF NOT EXISTS ai_literacy_acks (
  user_id            INTEGER NOT NULL,
  statement_version  TEXT NOT NULL,
  statement_sha256   TEXT NOT NULL,
  acknowledged_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, statement_version)
);
