-- IT setup links (services/itSetup/*, routes/itSetup.js): a platform admin
-- hands a customer's IT contact, who has no AppCrane account, a scoped and
-- expiring link to a setup page for SSO, SCIM, domains and SIEM.
--
-- token_hash / session token_hash: sha256 of the opaque value; the value itself
-- is shown once (link) or lives only in an HttpOnly cookie (session).
-- scopes: JSON array, a subset of oidc, saml, scim, domains, siem.
CREATE TABLE IF NOT EXISTS it_setup_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  first_opened_at TEXT,
  last_used_at TEXT,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS it_setup_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL REFERENCES it_setup_links(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_it_setup_sessions_link ON it_setup_sessions (link_id);

-- One change per section edit. staged -> applied (the IT contact confirmed) ->
-- rolled_back (a platform admin undid it), or staged -> discarded.
-- after_enc / before_enc: encrypted JSON. after holds what was entered (a
-- client secret included); before holds the settings rows it replaced.
-- test_ok: 1 once the connection test passed for exactly these values.
CREATE TABLE IF NOT EXISTS it_setup_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL REFERENCES it_setup_links(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'staged' CHECK (status IN ('staged', 'applied', 'discarded', 'rolled_back')),
  after_enc TEXT NOT NULL,
  before_enc TEXT,
  test_ok INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  applied_at TEXT,
  rolled_back_at TEXT,
  rolled_back_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_it_setup_changes_link ON it_setup_changes (link_id, id);
