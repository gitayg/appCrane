-- Managed Redis: a container PER SCOPE, so a managed_databases row needs to
-- carry the two facts a shared-server row never did — which container, and
-- which host port.
--
-- WHY REDIS DOES NOT FIT THE SHARED-SERVER SHAPE 085 BUILT.
-- Postgres and MariaDB get ONE container each for the whole platform because
-- both enforce isolation INSIDE the engine: a login role reaches exactly one
-- database and the engine refuses everything else. Redis has no equivalent.
-- Measured against redis:8.10-alpine (see server/services/managedRedis.js for
-- the full transcript):
--
--   * ACL key patterns do NOT scope to a numbered database. A user created with
--     `~*` read another user's key out of db 2 while "living in" db 1.
--   * Denying SELECT is not enough either: `COPY <key> <dst> DB 2` and
--     `MOVE <key> 2` both returned 1 — a write into a sibling's keyspace — for
--     a user restricted to `+select|1`.
--   * `FT.CREATE` answers "Cannot create index on db != 0", so every app parked
--     on a numbered database silently loses RediSearch, and with it the JSON
--     and vector indexes Redis 8 ships as core.
--
-- So the numbered-database model would have been a deny-list of cross-database
-- commands, maintained by hand, against a command set that grows every release
-- — and a feature-crippled one. The boundary is a PROCESS instead: one small
-- Redis per scope, its own password, its own volume, its own port. Measured at
-- ~6 MiB resident at rest, which is what makes this affordable where 57 idle
-- Postgres servers were not.
--
-- host_port is NULL for postgres and mariadb, whose port lives on the ENGINE
-- (managed_db_servers.host_port) because they share one server. It is NOT NULL
-- for redis. Same reasoning as 085's host_port: the value is stored rather than
-- recomputed because it is what an already-deployed container was handed in its
-- connection string, and a code change to the range must not silently repoint a
-- running fleet.
--
-- container_name is stored for the same reason 085 stores it on the server row:
-- it is what actually exists on the host and is what `docker inspect` has to be
-- pointed at. A change to the naming scheme must not make a running instance
-- read as absent.

ALTER TABLE managed_databases ADD COLUMN host_port INTEGER;
ALTER TABLE managed_databases ADD COLUMN container_name TEXT;

-- One owner per host port. A port handed to two scopes means the second
-- container fails to bind — recoverable — but a port REUSED after a partial
-- deprovision means an app connects to a stranger's Redis with a password that
-- happens to still work, which is not.
--
-- The WHERE clause is NOT what makes the postgres and mariadb rows safe here,
-- and it would be easy to write that down as though it were: SQLite treats
-- every NULL in a UNIQUE index as distinct, so an unqualified index would
-- already tolerate a hundred NULL host_ports. Measured — removing the WHERE and
-- inserting two NULL-port rows still succeeds. It is here to keep the index to
-- the rows that have a port at all, and to say in the schema which rows the
-- constraint is about.
CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_databases_host_port
  ON managed_databases(host_port) WHERE host_port IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_databases_container
  ON managed_databases(container_name) WHERE container_name IS NOT NULL;
