-- v2.21.8: per-app resource time-series. metricsCollector already reads live
-- CPU/mem from Docker, but nothing persisted it — so the dashboard could only
-- show a current snapshot. This table stores periodic samples (written by the
-- metrics sampler) so Manage can chart CPU/memory trends per app + env.
-- Pruned to a rolling window by the sampler.

CREATE TABLE IF NOT EXISTS metrics_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env         TEXT    NOT NULL,
  cpu_percent REAL    NOT NULL DEFAULT 0,
  mem_mb      REAL    NOT NULL DEFAULT 0,
  recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_metrics_history_app ON metrics_history (app_id, recorded_at);
