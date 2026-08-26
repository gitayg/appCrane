-- v2.52.0: dependency scan results for the apps AppCrane HOSTS.
--
-- v2.49.1 made AppCrane's own dependency scan blocking, which covers the
-- platform's tree and says nothing about the ~57 apps the platform runs.
-- Their lockfiles have been sitting on disk in <appDir>/current the whole
-- time, at deploy time, unread. This table is where reading them lands.
--
-- ONE ROW PER SCAN, NOT ONE ROW PER APP.
-- The obvious shape is a column or two on `apps` holding "current vuln count",
-- overwritten each scan. That loses the thing the daily scan exists to find.
-- The failure mode that actually bites is an advisory published against code
-- that was deployed weeks ago and has not changed since: no deploy, no diff,
-- nothing in any log, and the app goes from clean to vulnerable without anyone
-- touching it. Distinguishing "this app has always been like this" from "this
-- app became vulnerable on Tuesday" needs the history, and an overwritten
-- column cannot answer it. Rows are cheap here — one per app per env per day
-- is a few tens of thousands of rows a year on a 57-app box.
--
-- `source` records which of the two triggers produced the row ('deploy' or
-- 'scheduled') because they answer different questions and get read
-- differently: a 'deploy' row is attributable to a change someone just made,
-- a 'scheduled' row that flipped to findings is attributable to the advisory
-- feed moving underneath an unchanged app.
--
-- STATUS IS FOUR-VALUED ON PURPOSE, AND 'error' IS NOT 'ok'.
--   'ok'       — scanned, nothing found.
--   'findings' — scanned, something found.
--   'skipped'  — nothing to scan (no lockfile AppCrane knows how to read).
--   'error'    — the scan did not complete (OSV unreachable, unparseable
--                lockfile).
-- Collapsing the last two into 'ok' is the tempting simplification and it is
-- the one that makes this whole feature lie: a reporting control that renders
-- "could not check" as "nothing found" reports a clean fleet loudest at
-- exactly the moment it has stopped working. `error` carries the message so
-- the reason is visible without a log dive.
--
-- No CHECK constraints on env / source / status / ecosystem, following the
-- precedent 072 set for ingress_type and 076/077 kept for env and state:
-- SQLite cannot ALTER a CHECK, so one here would force a full table rebuild
-- the next time an ecosystem is added — and adding ecosystems is the explicit
-- plan (findLockfile returns the ecosystem so pip/go can land without touching
-- a caller). Validated in code instead.
--
-- ON DELETE CASCADE: scan history for a deleted app is not evidence of
-- anything, and leaving orphans behind would have the fleet view reporting
-- vulnerabilities in apps that no longer exist.

CREATE TABLE IF NOT EXISTS app_vuln_scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env           TEXT    NOT NULL,
  scanned_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  source        TEXT    NOT NULL,
  ecosystem     TEXT,
  status        TEXT    NOT NULL,
  package_count INTEGER NOT NULL DEFAULT 0,
  findings_json TEXT,
  error         TEXT
);

-- Both reads this table has are "the newest row for an app+env": latestScan
-- for one app, fleetScanSummary for every app. Leading with (app_id, env) and
-- trailing scanned_at lets SQLite seek the group and walk it backwards rather
-- than sorting the app's whole history on every dashboard load.
CREATE INDEX IF NOT EXISTS idx_app_vuln_scans_app_env_time
  ON app_vuln_scans(app_id, env, scanned_at);
