-- SIEM and log streaming (services/siem/*). Each row is one destination a
-- platform admin configured: syslog (TCP+TLS or UDP), HTTPS JSON (generic,
-- Splunk HEC, Datadog, Elastic _bulk, Sumo Logic, Microsoft Sentinel) or a
-- daily-partitioned JSONL export to S3/R2.
--
-- cursor_event_id is the durable delivery cursor: the last events.id this sink
-- has handled (delivered, or skipped by its filters). Delivery always resumes
-- from it, so a restart or an outage loses nothing and replays in id order.
-- secrets_enc holds the sink's credentials as encrypted JSON (encryption.js);
-- config holds everything that is not a secret.
CREATE TABLE IF NOT EXISTS siem_sinks (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT    NOT NULL,
  type                 TEXT    NOT NULL CHECK (type IN ('syslog', 'https', 's3')),
  preset               TEXT    NOT NULL DEFAULT 'generic',
  format               TEXT    NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'cef')),
  enabled              INTEGER NOT NULL DEFAULT 1,
  config               TEXT    NOT NULL DEFAULT '{}',
  secrets_enc          TEXT,
  ca_pem               TEXT,
  tls_skip_verify      INTEGER NOT NULL DEFAULT 0,
  filter_kinds         TEXT,
  min_severity         TEXT    NOT NULL DEFAULT 'info' CHECK (min_severity IN ('info', 'warning', 'critical')),
  filter_apps          TEXT,
  cursor_event_id      INTEGER NOT NULL DEFAULT 0,
  delivered_count      INTEGER NOT NULL DEFAULT 0,
  last_success_at      TEXT,
  last_attempt_at      TEXT,
  last_error           TEXT,
  last_error_at        TEXT,
  failing_since        TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_by           INTEGER,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);
