-- Per-instance GitHub App authentication for CONNECTED (source_type='github')
-- apps. Each self-hosted AppCrane registers its OWN GitHub App through GitHub's
-- App-manifest flow; app builders install that App on the repositories they
-- choose; AppCrane then authenticates git and REST with short-lived (1 hour)
-- installation access tokens instead of a long-lived PAT.
--
-- SEPARATE TABLES, no new columns on `apps`:
--   - `apps` is rebuilt by DROP + RENAME in several migrations, and its newest
--     rebuild is guarded by tests that require every live column to be restated
--     there. Bookkeeping for an optional integration does not belong in that
--     blast radius.
--   - the routing input stays exactly one lookup: an app has an installation
--     row, or it does not.
--
-- No FOREIGN KEY to apps, for the same reason 091 gives: apps is recreated by
-- those rebuilds and a reference that survives them only by accident is worse
-- than none. An orphan row cannot grant anything: resolution re-checks that the
-- app's github_url still names the repository the installation was attached to.
--
-- Secrets: private_key_enc and webhook_secret_enc / client_secret_enc hold
-- services/encryption.js envelopes (AES-256-GCM), never plaintext. Installation
-- ACCESS tokens are never stored here at all -- they live in process memory for
-- at most an hour, which is the point of the whole feature.

CREATE TABLE IF NOT EXISTS github_app_config (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),  -- one App per instance
  github_app_id      INTEGER NOT NULL,
  slug               TEXT    NOT NULL,
  name               TEXT,
  owner_login        TEXT,
  html_url           TEXT,
  client_id          TEXT,
  client_secret_enc  TEXT,
  webhook_secret_enc TEXT,
  private_key_enc    TEXT    NOT NULL,
  created_by         INTEGER,
  created_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_github_installations (
  app_id          INTEGER PRIMARY KEY,
  slug            TEXT    NOT NULL,
  installation_id INTEGER NOT NULL,
  repo_full_name  TEXT    NOT NULL,   -- 'owner/repo', as GitHub spells it
  attached_by     INTEGER,
  attached_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_app_github_installations_slug
  ON app_github_installations (slug);
