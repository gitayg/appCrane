-- Path role rules enforced at the gate (services/accessRules.js).
--
-- One row per app, environment and source. 'manifest' rows are written by a
-- deploy from deployhub.json `access` and replaced by the next deploy;
-- 'dashboard' rows are edited by the app's owners and admins without a
-- redeploy and never touched by a deploy. Both apply at once and the strictest
-- matching rule wins, so neither source can loosen the other.
CREATE TABLE IF NOT EXISTS app_access_rules (
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env        TEXT NOT NULL CHECK (env IN ('production', 'sandbox')),
  source     TEXT NOT NULL CHECK (source IN ('manifest', 'dashboard')),
  rules_json TEXT NOT NULL,
  updated_by INTEGER,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env, source)
);
