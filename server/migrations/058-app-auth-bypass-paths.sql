-- v2.7.27: per-path auth bypass — companion to auth_mode='headless' (056).
-- A bypass entry is a path PREFIX (e.g. "/ws/local-runner"). Requests under
-- that prefix on this app skip forward_auth and reach the container with NO
-- X-AppCrane-* identity headers. The app authenticates them itself (typically
-- a query-string or body token validated by the app).
--
-- Motivating case: a CLI client (e.g. aghook → AgentClub) can't carry the
-- browser SSO cookie. The runner connects with ?token=<secret> over WS and
-- the app's WS handler validates that token. The whole rest of the app keeps
-- SSO. Caddy logs are configured to redact the token query param for these
-- paths so the credential doesn't sit in log storage.
--
-- Stored as a JSON array of strings or NULL. Validation lives in the API
-- write path AND is re-asserted when the Caddy generator reads back, so a
-- direct DB write (or an older record from a future migration) can't smuggle
-- a malformed prefix into the live Caddyfile.

ALTER TABLE apps ADD COLUMN auth_bypass_paths TEXT;
