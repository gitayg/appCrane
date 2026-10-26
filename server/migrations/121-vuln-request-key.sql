-- One request per dependency-scan finding: (app, ecosystem, package, advisory).
--
-- vuln_key is NULL on every request a person filed and on every row that
-- existed before this migration. A request the scanner opens carries the key,
-- and the partial UNIQUE index is what makes "opened once" hold: the scanner
-- inserts with ON CONFLICT DO NOTHING, so a second scan, a second environment,
-- a restart or two scans racing each other cannot add a second row for the
-- same key. The key is never cleared, so a request that was closed stays the
-- one request for that key and is not opened again.
ALTER TABLE enhancement_requests ADD COLUMN vuln_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_enhancement_requests_vuln_key
  ON enhancement_requests(vuln_key) WHERE vuln_key IS NOT NULL;
