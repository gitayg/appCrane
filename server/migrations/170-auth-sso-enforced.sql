-- "Require SSO sign-in" is on by default.
--
-- auth_sso_only now means: enforced unless a platform admin stored 'false',
-- and only while an SSO provider (oidc_enabled or saml_enabled = '1') is on
-- (services/authPolicy.js ssoRequired). A missing row already counts as on.
--
-- Until now the setting defaulted to off and the toggle stored 'false' when it
-- was cleared, so an instance with SSO enabled could hold an explicit 'false'
-- nobody chose as policy. This turns the stored value to 'true' on every
-- instance where a provider is enabled at upgrade, once. An instance with no
-- provider is left as it is: there the setting has no effect, and its stored
-- value keeps meaning what the admin set. After this, a platform admin who
-- turns it off again (Settings, or `crane sso enforce off` on the host) is
-- respected; no later migration flips it back.
--
-- The row is written as 'true' rather than deleted so GET
-- /api/settings/auth_sso_only answers 'true' to a login page built before this
-- release, which only hides the password form on that exact value.

INSERT INTO settings (key, value, updated_at)
SELECT 'auth_sso_only', 'true', datetime('now')
WHERE EXISTS (SELECT 1 FROM settings WHERE key IN ('oidc_enabled', 'saml_enabled') AND value = '1')
ON CONFLICT(key) DO UPDATE SET value = 'true', updated_at = datetime('now');
