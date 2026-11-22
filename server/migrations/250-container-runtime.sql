-- Container runtime per app (services/containerRuntime.js). The platform
-- default is the settings key container_runtime_default ('runc' unless a
-- platform admin sets 'runsc', gVisor). A row here overrides it for one app:
-- 'runsc' raises isolation (an owner or app admin may set it), 'runc' is an
-- exception below gVisor that only a platform admin may set, with a reason.
-- No row = the platform default. Takes effect at the next container start; a
-- start that needs runsc on a host without it is refused, never run on runc.
CREATE TABLE IF NOT EXISTS app_container_runtime (
  app_id     INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  runtime    TEXT    NOT NULL CHECK (runtime IN ('runc', 'runsc')),
  reason     TEXT,
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
