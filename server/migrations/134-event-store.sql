-- One append-only event store that the audit log, deployments, dependency
-- scans, client errors, Job Health, host alerts and memory admission all write
-- to (services/eventStore.js), so one query answers "what happened to this app"
-- or "what did this person do" across all of them. Each row links back to its
-- source row through ref_table + ref_id. No foreign keys: an event about an app
-- or a person outlives them, and app_slug keeps the deleted app's name.
-- Rows are never updated; services/eventStore.js deletes them by severity once
-- past the retention window (settings event_retention_*_days).
CREATE TABLE IF NOT EXISTS events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              TEXT    NOT NULL DEFAULT (datetime('now')),
  kind            TEXT    NOT NULL,
  severity        TEXT    NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  app_id          INTEGER,
  app_slug        TEXT,
  user_id         INTEGER,
  subject_user_id INTEGER,
  summary         TEXT    NOT NULL,
  ref_table       TEXT,
  ref_id          INTEGER,
  data            TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_app_ts      ON events(app_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_user_ts     ON events(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_subject_ts  ON events(subject_user_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts     ON events(kind, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity_ts ON events(severity, ts);

CREATE TRIGGER IF NOT EXISTS events_append_only
BEFORE UPDATE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;

-- One-time backfill of the last 30 days, at most 20,000 rows per source, in
-- timestamp order so ids follow time. Only the action / status is copied, never
-- an audit detail body.
INSERT INTO events (ts, kind, severity, app_id, app_slug, user_id, subject_user_id, summary, ref_table, ref_id, data)
SELECT ts, kind, severity, app_id, app_slug, user_id, subject_user_id, summary, ref_table, ref_id, data FROM (
  SELECT * FROM (
    SELECT al.created_at AS ts,
           CASE al.action
             WHEN 'login' THEN 'login'
             WHEN 'login-failed' THEN 'login.failed'
             WHEN 'env-reveal' THEN 'secret.reveal'
             WHEN 'secret-reveal' THEN 'secret.reveal'
             WHEN 'env_file.reveal' THEN 'secret.reveal'
             ELSE 'audit'
           END AS kind,
           CASE WHEN al.action IN ('login-failed', 'env-reveal', 'secret-reveal', 'env_file.reveal') THEN 'warning' ELSE 'info' END AS severity,
           al.app_id, a.slug AS app_slug,
           CASE WHEN al.action = 'login-failed' THEN NULL ELSE al.user_id END AS user_id,
           CASE WHEN al.action = 'login-failed' THEN al.user_id ELSE NULL END AS subject_user_id,
           CASE al.action
             WHEN 'login' THEN 'Signed in'
             WHEN 'login-failed' THEN 'Sign-in failed'
             ELSE 'Audit: ' || replace(replace(replace(al.action, '-', ' '), '_', ' '), '.', ' ')
           END AS summary,
           'audit_log' AS ref_table, al.id AS ref_id,
           json_object('action', al.action, 'backfilled', 1) AS data
      FROM audit_log al LEFT JOIN apps a ON a.id = al.app_id
     WHERE al.created_at >= datetime('now', '-30 days')
     ORDER BY al.id DESC LIMIT 20000
  )
  UNION ALL
  SELECT * FROM (
    SELECT COALESCE(d.finished_at, d.started_at) AS ts,
           CASE d.status WHEN 'failed' THEN 'deploy.failed' ELSE 'deploy.succeeded' END AS kind,
           CASE d.status WHEN 'failed' THEN 'warning' ELSE 'info' END AS severity,
           d.app_id, a.slug AS app_slug, d.deployed_by AS user_id, NULL AS subject_user_id,
           CASE d.status WHEN 'failed' THEN 'Deploy to ' || d.env || ' failed'
                ELSE 'Deployed ' || COALESCE('v' || d.version, 'a new version') || ' to ' || d.env END AS summary,
           'deployments' AS ref_table, d.id AS ref_id,
           json_object('env', d.env, 'version', d.version, 'backfilled', 1) AS data
      FROM deployments d LEFT JOIN apps a ON a.id = d.app_id
     WHERE d.status IN ('live', 'rolled_back', 'failed')
       AND COALESCE(d.finished_at, d.started_at) >= datetime('now', '-30 days')
     ORDER BY d.id DESC LIMIT 20000
  )
  UNION ALL
  SELECT * FROM (
    SELECT s.scanned_at AS ts, 'scan.finding' AS kind, 'warning' AS severity,
           s.app_id, a.slug AS app_slug, NULL AS user_id, NULL AS subject_user_id,
           'Dependency scan of ' || s.env || ' found ' || COALESCE(json_array_length(s.findings_json), 0) || ' vulnerable package(s)' AS summary,
           'app_vuln_scans' AS ref_table, s.id AS ref_id,
           json_object('env', s.env, 'source', s.source, 'backfilled', 1) AS data
      FROM app_vuln_scans s LEFT JOIN apps a ON a.id = s.app_id
     WHERE s.status = 'findings' AND s.scanned_at >= datetime('now', '-30 days')
     ORDER BY s.id DESC LIMIT 20000
  )
) ORDER BY ts ASC;
