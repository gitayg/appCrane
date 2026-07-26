-- Domain aliases (v2.24.4): extra domains that 301-redirect to an app's
-- primary custom domain. AppCrane serves one custom domain per app; when an
-- app migrates its domain, the old one used to go dark (no Caddy block →
-- cert error), breaking already-sent login links and bookmarks. An alias row
-- keeps the old domain alive as a permanent redirect to the current primary,
-- with TLS auto-provisioned by Caddy — no hand-edited Caddyfile.
--
-- source: 'auto'   — seeded automatically when an app's domain changed X→Y
--         'manual' — added by an owner/admin via the API/UI
CREATE TABLE IF NOT EXISTS app_domain_aliases (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  domain     TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT 'manual',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One app owns a given alias domain globally (mirrors the primary-domain
-- uniqueness enforced in app logic). Case-insensitive.
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_domain_aliases_domain
  ON app_domain_aliases (lower(domain));
CREATE INDEX IF NOT EXISTS idx_app_domain_aliases_app
  ON app_domain_aliases (app_id);
