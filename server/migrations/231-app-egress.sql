-- Egress allow-list (services/egress). Off unless a platform admin turns it on:
-- settings key egress_mode ('open' default, 'enforced' for every app), or
-- app_egress.enforced = 1 for one app while the platform stays open.
--
-- An enforced app's container has no default route (its network namespace is
-- held by an anchor container that removes it), so the internet is reachable
-- only through AppCrane's egress proxy, which admits the hosts of the app's
-- active 'egress' capability grants. The proxy authenticates the container by
-- the per-app, per-environment token below (hashed for lookup, encrypted for
-- re-injection at every start). Takes effect at the next container start.
CREATE TABLE IF NOT EXISTS app_egress (
  app_id     INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  enforced   INTEGER NOT NULL DEFAULT 0 CHECK (enforced IN (0, 1)),
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_egress_tokens (
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env             TEXT    NOT NULL CHECK (env IN ('production', 'sandbox')),
  token_hash      TEXT    NOT NULL UNIQUE,
  token_encrypted TEXT    NOT NULL,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);
