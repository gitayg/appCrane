-- v2.104.0: a failed-login row carries a COUNT instead of standing for one failure.
--
-- dbAuthAlerts inserted one row per failure. Redis groups repeated failures into
-- one ACL LOG entry whose count keeps growing, so an app hammering AUTH turned a
-- few log entries into millions of rows per scan (security review: amplification).
-- Rows now store a count; the alert query sums it. Existing rows are one failure
-- each, which is exactly what DEFAULT 1 says.
ALTER TABLE managed_db_auth_failures ADD COLUMN count INTEGER NOT NULL DEFAULT 1;
