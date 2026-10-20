-- In-app surveys (NPS and friends). A platform admin defines a survey: its
-- questions, the apps it runs on and how often one person is asked. The
-- signed-in user sees a small card in the app's AppCrane top bar when one is
-- due; every answer is stored here and mailed to the app's owners and the
-- platform admins (services/surveyMail.js).
--
-- Frequency (services/surveys.js isDue):
--   min_visits       the person has opened the app at least this many times
--   min_days         ... and first opened it at least this many days ago
--   frequency_days   after an answer, ask again after this many days (0 = once)
--   snooze_days      "Not now" hides the card for this many days
CREATE TABLE IF NOT EXISTS surveys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
  all_apps INTEGER NOT NULL DEFAULT 1 CHECK(all_apps IN (0, 1)),
  frequency_days INTEGER NOT NULL DEFAULT 90 CHECK(frequency_days >= 0),
  min_visits INTEGER NOT NULL DEFAULT 3 CHECK(min_visits >= 0),
  min_days INTEGER NOT NULL DEFAULT 0 CHECK(min_days >= 0),
  snooze_days INTEGER NOT NULL DEFAULT 7 CHECK(snooze_days >= 0),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS survey_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  survey_id INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
  position INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL CHECK(kind IN ('nps', 'scale', 'choice', 'text')),
  prompt TEXT NOT NULL,
  required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0, 1)),
  scale_min INTEGER,
  scale_max INTEGER,
  low_label TEXT,
  high_label TEXT,
  options TEXT,
  max_length INTEGER
);
CREATE INDEX IF NOT EXISTS idx_survey_questions_survey ON survey_questions(survey_id, position);

CREATE TABLE IF NOT EXISTS survey_apps (
  survey_id INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  PRIMARY KEY (survey_id, app_id)
);

-- answers: JSON array of { question_id, kind, prompt, value } -- the prompt is
-- copied so a later edit of the survey does not rewrite what was answered.
CREATE TABLE IF NOT EXISTS survey_responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  survey_id INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  answers TEXT NOT NULL,
  nps_score INTEGER CHECK(nps_score IS NULL OR (nps_score BETWEEN 0 AND 10)),
  submitted_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_survey_responses_app ON survey_responses(app_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_survey_responses_user ON survey_responses(survey_id, app_id, user_id, submitted_at);

-- One row per person per app: how often they have opened it (counted by the
-- top bar's pending check, at most once per 30 minutes).
CREATE TABLE IF NOT EXISTS survey_app_visits (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_counted_at TEXT NOT NULL DEFAULT (datetime('now')),
  visit_count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, app_id)
);

CREATE TABLE IF NOT EXISTS survey_snoozes (
  survey_id INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  snoozed_until TEXT NOT NULL,
  PRIMARY KEY (survey_id, user_id, app_id)
);
