-- What verify-before-run found when an image was NOT verified (services/imageTrust/events.js),
-- one row per app, env, image and outcome:
--   kind 'warn'    warn mode started it anyway (the census lists these while the image is unsigned)
--   kind 'refused' enforce mode refused a start or restart (audited, mailed, shown on the app)
-- count/first_at/last_at say how often; last_logged_at and last_notified_at
-- throttle the server log line and the mail to one per image per day.
-- image_id is '' when the image could not even be inspected.
CREATE TABLE IF NOT EXISTS image_trust_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL,
  image_id TEXT NOT NULL DEFAULT '',
  image_ref TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('warn', 'refused')),
  what TEXT,
  reason TEXT,
  count INTEGER NOT NULL DEFAULT 0,
  first_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_logged_at TEXT,
  last_notified_at TEXT,
  UNIQUE (app_id, env, image_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_image_trust_events_app ON image_trust_events(app_id, env, last_at);
