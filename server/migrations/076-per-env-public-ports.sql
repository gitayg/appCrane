-- v2.46.0: a published host port PER ENVIRONMENT.
--
-- Until now `apps.public_port` was one number per app, and docker.js refused to
-- publish anything for a non-production container:
--
--     if (env !== 'production') return null;   // publicPublishTargets
--
-- The reason recorded for that was "one public_port per app but two containers,
-- so publishing it for both would make the second `docker run` fail with 'port
-- is already allocated' — and the loser could be production". That argues
-- against ONE port on TWO containers. It never argued against two DIFFERENT
-- ports; sandbox was excluded because there was only one number to go around,
-- and the safe way to allocate one number between two containers is to give it
-- to the one with real clients.
--
-- The cost was that a raw data plane could not be exercised before promoting:
-- the sandbox container's HTTP control plane was reachable through Caddy at
-- /<slug>-sandbox, but the raw port existed only in production, so the first
-- time anyone spoke the actual protocol to it was after it went live.
--
-- WHY A TABLE AND NOT A SECOND COLUMN.
-- Today the database itself guarantees no two apps share a host port, via a
-- UNIQUE index on apps(public_port). A second column would quietly weaken that:
-- SQLite cannot enforce uniqueness ACROSS two columns as one value space, so
-- app A's sandbox port could equal app B's production port with every
-- constraint still satisfied — and the collision would surface as a failed
-- `docker run` partway through a deploy, naming a port that looks unclaimed in
-- the dashboard. A registry keyed BY the port keeps that invariant where it is
-- now: in the schema.
--
--   host_port INTEGER PRIMARY KEY  — one owner per port, across every app and
--                                    every environment. This is the invariant.
--   UNIQUE (app_id, env)           — and one port per app per environment.
--
-- `env` is validated in CODE rather than with a CHECK constraint, following the
-- precedent set by ingress_type in 072: SQLite cannot ALTER a CHECK, so one here
-- would force a full table rebuild the next time the set of environments changes.
--
-- ROLLOUT IS OPT-IN. This migration backfills production only. No app gains a
-- sandbox port here, and none is allocated on deploy — a sandbox port appears
-- only when an admin sets one. A published port has no forward_auth, no TLS from
-- AppCrane, no identity headers and no audit, so handing a second one to 57
-- running apps because their schema changed would open doors nobody asked for,
-- at deploy time, when nobody is watching.

CREATE TABLE IF NOT EXISTS app_host_ports (
  host_port INTEGER PRIMARY KEY,
  app_id    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env       TEXT    NOT NULL,
  UNIQUE (app_id, env)
);

CREATE INDEX IF NOT EXISTS idx_app_host_ports_app ON app_host_ports(app_id);

-- Backfill: every port currently published is a production port. INSERT OR
-- IGNORE rather than a plain INSERT so re-running against a partly-migrated
-- database cannot fail on the primary key.
INSERT OR IGNORE INTO app_host_ports (host_port, app_id, env)
  SELECT public_port, id, 'production' FROM apps WHERE public_port IS NOT NULL;

-- The per-environment mirror of the registry, kept so the hot read path stays a
-- column read on a row the caller already has. /api/apps builds a payload for
-- every app on the platform, and making publicPortForApp() query per app would
-- put one lookup per app on the catalog endpoint. Written in the SAME
-- transaction as the registry by a single writer in tcpIngress.js; the registry
-- is the invariant, these are the fast path.
ALTER TABLE apps ADD COLUMN sandbox_public_port INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_sandbox_public_port
  ON apps(sandbox_public_port) WHERE sandbox_public_port IS NOT NULL;
