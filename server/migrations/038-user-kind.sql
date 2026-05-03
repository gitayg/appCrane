-- Distinguish agent / API-key users from real human portal users.
--
-- Until now the only way to tell them apart on the dashboard was the
-- agent-{ts}@appcrane email convention used by the "+ New App Agent"
-- button on /applications. The "Unused Keys" section therefore showed
-- every human user not assigned to an app — confusing and noisy.
--
-- The new column has values:
--   'human' (default — portal users, OIDC/SAML/SSO sign-ins, manually
--           created via /settings#users)
--   'agent' (created by the "+ New App Agent" flow, or any future
--           server-to-server API-key-only identity)
--
-- Backfill rule: any pre-existing user whose email matches the
-- 'agent-...@appcrane' shape (the historical pattern) is reclassified
-- as an agent. Everyone else stays 'human'.

ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human';

UPDATE users
   SET kind = 'agent'
 WHERE email LIKE 'agent-%@appcrane';
