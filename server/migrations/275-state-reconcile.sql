-- State reconciliation (services/reconcileState.js, routes/stateReconcile.js):
-- what the database says against what Docker and the disk hold.
--
-- reconcile_findings: one row per distinct problem, keyed by a fingerprint
-- (kind + app + env + subject), so a problem seen on every sweep is one row
-- whose last_seen_at moves. A finding not seen on a sweep is 'resolved'.
-- status: open | auto_fixed | fixed | resolved | dismissed.
CREATE TABLE IF NOT EXISTS reconcile_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
  app_id INTEGER,
  slug TEXT,
  env TEXT,
  subject TEXT,
  detail_json TEXT,
  fix TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'auto_fixed', 'fixed', 'resolved', 'dismissed')),
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT,
  fixed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  fix_result TEXT
);
CREATE INDEX IF NOT EXISTS idx_reconcile_findings_status ON reconcile_findings (status, last_seen_at);

CREATE TABLE IF NOT EXISTS reconcile_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trigger_by TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  docker_ok INTEGER,
  counts_json TEXT,
  error TEXT
);

-- A health probe the reconciler paused because the env has no container.
-- Only rows here are resumed automatically: a probe a person disabled
-- (health_configs.enabled = 0 with no row here) is never turned back on.
CREATE TABLE IF NOT EXISTS health_probe_pauses (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK (env IN ('production', 'sandbox')),
  reason TEXT NOT NULL,
  paused_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);

-- Directories moved aside instead of removed: an app's data directory and its
-- Crane-hosted repository on delete, an orphan directory on a one-click fix.
-- Nothing purges a row automatically; after expires_at a platform admin can.
CREATE TABLE IF NOT EXISTS app_trash (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  slug TEXT,
  app_id INTEGER,
  original_path TEXT NOT NULL,
  trash_path TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  moved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  moved_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  restored_at TEXT,
  purged_at TEXT
);
