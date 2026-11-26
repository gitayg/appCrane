-- Managed databases: the "TLS required" login level, for an app whose image
-- can verify the server over TLS but cannot send a client certificate
-- (BookStack reads only MYSQL_ATTR_SSL_CA).
--
-- tls_required: 1 once a platform admin converted the login with Require TLS
--   postgres  member of appcrane_tls_required: pg_hba lets it in over
--             hostssl with its password and rejects it on plain TCP
--   mariadb   REQUIRE SSL (no SUBJECT/ISSUER)
-- Sticky like client_cert_required (migration 108): deploys never clear it.
-- Only the platform admin's "Revert to password" (managedDb.revertTls) sets
-- it back to 0. client_cert_required = 1 is the stronger level and wins
-- wherever both are 1. No CHECK constraint, for the reason migration 108 gives.
ALTER TABLE managed_databases ADD COLUMN tls_required INTEGER NOT NULL DEFAULT 0;

-- tls_probe_base: the MariaDB TLS check's baseline (JSON: when it started,
-- the server's start time, the id of the session that read it, and each
-- login's TOTAL_CONNECTIONS / TOTAL_SSL_CONNECTIONS then), so the check
-- counts the connections opened since. NULL: never started. Postgres reads
-- its current connections instead and does not use it.
ALTER TABLE managed_databases ADD COLUMN tls_probe_base TEXT;
