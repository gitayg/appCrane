-- Immediate vulnerability alerts (services/vulnAlerts.js): one row per
-- (app, ecosystem, package, advisory) that owners and platform admins have
-- already been told about, so a finding is mailed once, not on every scan.
--
-- scan_id: the scan that first reported it (NULL for the backfill below). A
-- retry of the same scan re-reads its own rows and re-queues the same mail,
-- which the e-mail queue's idempotency key then drops.
--
-- A row is deleted when no environment's latest successful scan still reports
-- the advisory (the same rule that closes its request), so a vulnerable version
-- that is fixed and later comes back is mailed again.
CREATE TABLE IF NOT EXISTS vuln_alerts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  ecosystem   TEXT NOT NULL,
  package     TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  scan_id     INTEGER,
  alerted_at  TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (app_id, ecosystem, package, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_alerts_scan ON vuln_alerts(scan_id);

-- Backfill: everything the latest successful scan of each app/env already
-- reports counts as alerted. Those findings are in the daily digest and have
-- requests open; without this the first scan after the upgrade would mail every
-- existing finding to every owner and admin at once.
INSERT OR IGNORE INTO vuln_alerts (app_id, ecosystem, package, advisory_id, scan_id)
SELECT s.app_id, json_extract(f.value, '$.ecosystem'), json_extract(f.value, '$.name'), i.value, NULL
FROM app_vuln_scans s,
     json_each(s.findings_json) f,
     json_each(json_extract(f.value, '$.ids')) i
WHERE s.findings_json IS NOT NULL AND json_valid(s.findings_json)
  AND s.id = (
    SELECT id FROM app_vuln_scans
    WHERE app_id = s.app_id AND env = s.env AND status IN ('ok', 'findings')
    ORDER BY scanned_at DESC, id DESC LIMIT 1
  );
