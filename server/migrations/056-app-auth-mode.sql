-- v2.7.22: per-app auth mode. Headless apps bypass forward_auth entirely
-- (no identity, no role headers, no per-app verify round-trip). Right tool
-- for single-purpose unauthenticated services: telemetry ingest, public
-- webhooks, status pages.
--
-- Defaults to 'authenticated' — only an explicit flip exposes an app to
-- unauth traffic, and the UI requires a confirmation step on toggle.

ALTER TABLE apps ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'authenticated';
