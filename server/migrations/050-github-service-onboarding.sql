-- v2.2.15: hidden GitHub onboarding via a single platform service account.
--
-- AppCrane optionally fronts a GitHub org/user that owns every per-app
-- repository. The end user never authenticates with GitHub directly — they
-- talk to AppCrane, AppCrane talks to GitHub on their behalf using a single
-- PAT stored encrypted in this row set.
--
-- Phase 1 (this migration): seed the keys empty so the Settings UI can render
-- inputs against a known shape. Population happens via PUT /api/settings/:key
-- (admin only). The token is encrypted at rest using the same AES-256-GCM
-- envelope as oidc_client_secret_enc / saml_idp_cert_enc.
--
-- Keys:
--   github_service_owner            — github username or org name owning the repos
--   github_service_token_enc        — encrypted PAT (server-side decrypted only)
--   github_service_visibility       — 'private' | 'internal' | 'public' (repo default)
--   github_service_enabled          — '0' | '1' kill switch the UI flips
--
-- The _enc suffix matches existing convention so settings.js SENSITIVE_KEYS
-- gating naturally extends to the token.

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('github_service_owner',      ''),
  ('github_service_token_enc',  ''),
  ('github_service_visibility', 'private'),
  ('github_service_enabled',    '0');
