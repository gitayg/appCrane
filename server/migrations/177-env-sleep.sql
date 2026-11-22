-- Environment sleep (services/envSleep*.js, envSleeper.js, sleepPolicy.js).
--
-- sleep_platform: one row, the platform-wide defaults and the token Caddy adds
-- to the crash-page rewrite so AppCrane can tell a request that came through an
-- app route from one sent straight to /api/_crashed.
-- app_sleep_policy: per-app overrides. NULL inherits the platform value, 0 is
-- off. sandbox_schedule is JSON {days,start,end,tz}, 'off', or NULL (inherit).
CREATE TABLE IF NOT EXISTS sleep_platform (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sandbox_idle_minutes INTEGER NOT NULL DEFAULT 0,
  sandbox_schedule TEXT,
  inactive_days INTEGER NOT NULL DEFAULT 0,
  wake_token TEXT,
  updated_at TEXT,
  updated_by INTEGER
);
INSERT OR IGNORE INTO sleep_platform (id) VALUES (1);

CREATE TABLE IF NOT EXISTS app_sleep_policy (
  app_id INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  sandbox_idle_minutes INTEGER,
  sandbox_schedule TEXT,
  inactive_days INTEGER,
  updated_at TEXT,
  updated_by INTEGER
);

-- state: 'awake' | 'sleeping' | 'waking'. reason: 'idle' | 'schedule' | 'inactive'.
CREATE TABLE IF NOT EXISTS env_sleep (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK (env IN ('sandbox', 'production')),
  state TEXT NOT NULL DEFAULT 'awake' CHECK (state IN ('awake', 'sleeping', 'waking')),
  reason TEXT,
  slept_at TEXT,
  woke_at TEXT,
  wake_reason TEXT,
  last_error TEXT,
  PRIMARY KEY (app_id, env)
);

-- Request activity per app and environment, counted at forward_auth
-- (/api/identity/verify with X-Forwarded-Uri). AppCrane's own probes go to the
-- container's loopback port and never pass through it. tracking_since is when
-- AppCrane first looked at this environment, so an environment with no request
-- on record is idle from then, not from the epoch.
CREATE TABLE IF NOT EXISTS env_activity_last (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL,
  last_request_at TEXT,
  tracking_since TEXT NOT NULL,
  PRIMARY KEY (app_id, env)
);

CREATE TABLE IF NOT EXISTS env_activity_daily (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL,
  day TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, env, day)
);

CREATE TABLE IF NOT EXISTS env_activity_users (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL,
  day TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (app_id, env, day, user_id)
);
CREATE INDEX IF NOT EXISTS idx_env_activity_users_day ON env_activity_users (day);
