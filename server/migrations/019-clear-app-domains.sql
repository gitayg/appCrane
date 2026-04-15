-- Clear stale domain fields now that all routing is path-based via CRANE_DOMAIN.
-- The domain column is no longer used by Caddy; leaving it set causes incorrect
-- public URLs in health/monitoring API responses.
UPDATE apps SET domain = NULL WHERE domain IS NOT NULL;
