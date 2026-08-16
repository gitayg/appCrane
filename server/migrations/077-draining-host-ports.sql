-- migration:no-transaction
--
-- v2.47.0: a host port can be PINNED or DRAINING.
--
-- Changing an app's published port while a container is bound to it was refused
-- outright, and the operator was told to do it in three steps: flip to http,
-- redeploy, then pin the new number. The reason recorded in tcpIngress.js was
-- honest about being a workaround:
--
--     Refused rather than tracked: recording "still bound to X while pinned to
--     Y" needs a second column, and the two-step below reuses the release path
--     that is already audited and tested.
--
-- The hazard it avoided is real. The pin is the ONLY thing reserving a number:
-- overwrite it and the old port returns to the pool while a live container is
-- still bound to it, so the allocator can hand it to another app, whose
-- `docker run` then dies with "port is already allocated" while traffic to that
-- port keeps reaching the ORIGINAL app. Silent cross-app redirection.
--
-- v2.46.0 built the second store the comment was missing — app_host_ports —
-- so the refusal is no longer necessary. A re-pin can mark the old row DRAINING
-- and claim the new one in the same transaction: the old number stays owned (so
-- nothing else can be given it) while no longer being the app's pinned port, and
-- the existing release-on-recreate hook drops it the moment the container that
-- was binding it is gone.
--
-- WHAT CHANGES, AND WHAT MUST NOT.
--   host_port stays the PRIMARY KEY. That is the invariant — one owner per port
--   across every app and environment — and a draining port is still an owner.
--   Weakening it here would reintroduce exactly the double-booking this whole
--   mechanism exists to prevent.
--
--   UNIQUE (app_id, env) has to go, because an app in mid-move legitimately
--   holds two ports for one environment: the one it is moving to, and the one
--   its running container is still bound to. It is replaced by a PARTIAL unique
--   index over state='pinned', so "one pinned port per app per environment"
--   remains enforced by the schema while draining rows are unconstrained.
--
-- A table rebuild rather than PRAGMA writable_schema: this is dropping a table
-- constraint, not editing a CHECK string, and the table is days old and holds
-- one row per published port (single digits on every deployment). The
-- writable_schema trick is the right tool when a rebuild would be expensive or
-- would have to re-copy a large table; here the rebuild is a few rows and is
-- far easier to verify.
--
-- no-transaction because the rebuild toggles PRAGMA foreign_keys, which is a
-- no-op inside a transaction (server/db.js turns foreign_keys ON at connect,
-- and app_host_ports.app_id references apps(id) ON DELETE CASCADE — dropping
-- the old table with enforcement live would fire that cascade logic against a
-- table mid-swap).

PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS app_host_ports_v2 (
  host_port INTEGER PRIMARY KEY,
  app_id    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env       TEXT    NOT NULL,
  -- 'pinned'   — the port this app publishes in this environment.
  -- 'draining' — a port a running container is still bound to, kept reserved so
  --              it cannot be reissued, and released when that container goes.
  -- Validated in code, like ingress_type and env: SQLite cannot ALTER a CHECK,
  -- and a constraint here would force another rebuild the next time the set of
  -- states grows.
  state     TEXT    NOT NULL DEFAULT 'pinned'
);

-- Everything that exists today is a pinned port; draining is a state only the
-- new re-pin path can produce.
INSERT OR IGNORE INTO app_host_ports_v2 (host_port, app_id, env, state)
  SELECT host_port, app_id, env, 'pinned' FROM app_host_ports;

DROP TABLE app_host_ports;
ALTER TABLE app_host_ports_v2 RENAME TO app_host_ports;

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_host_ports_pinned
  ON app_host_ports(app_id, env) WHERE state = 'pinned';
CREATE INDEX IF NOT EXISTS idx_app_host_ports_app ON app_host_ports(app_id);

PRAGMA foreign_keys = ON;
