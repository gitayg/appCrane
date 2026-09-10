-- migration:no-transaction
--
-- The container runtime contract gains the two facts a pulled image needs and
-- AppCrane had no way to express: what COMMAND it is started with, and WHICH
-- paths inside it hold state.
--
-- apps.container_command
-- ----------------------
-- JSON array of argv strings, or NULL for "run the image's own ENTRYPOINT/CMD",
-- which is what every app does today and what every app keeps doing until this
-- column is filled in.
--
-- Measured, not assumed. `docker run -d quay.io/keycloak/keycloak:26.0` with no
-- argv prints its CLI usage banner and inspects as state=exited exit=0 — a
-- container that starts, reports success and never serves. With `start-dev`
-- appended it reaches state=running and answers on 8080. Zitadel, MinIO, ntfy
-- and Vault are the same shape, which is why none of them could be catalogued.
--
-- ARRAY, NEVER A SHELL STRING, and the column comment is the place to say why
-- rather than only the code. A string could only be turned back into argv by
-- splitting it, and the step after "split a stored string into a command" is
-- `sh -c <that string>` — command injection with an app row as the injection
-- point, against this repo's standing rule that DB and user strings are never
-- inlined into a shell. services/containerRuntimeSpec.js enforces the shape at
-- the write boundary AND again where the argv is built, so a caller that
-- bypassed this column cannot get a shell string onto a `docker run` line
-- either.
--
-- apps.volume_paths
-- -----------------
-- JSON array of absolute container paths, or NULL/'[]' for "just /data".
--
-- AppCrane mounts exactly one path: /data, from <app>/<env>/shared/data. That is
-- a contract an image AppCrane BUILT keeps and a pulled image never agreed to.
-- Every redeploy does `docker rm -f` + recreate (services/docker.js stopApp), so
-- anything an image wrote outside /data lives in the container's writable layer
-- and is destroyed on every deploy.
--
-- Measured against the shipped catalogue on 2026-09-09 by reading each entry's
-- image config from its registry: of the 63 entries whose config could be read,
-- 25 declare a VOLUME and 22 declare at least one that is NOT /data —
-- mattermost (/mattermost/{config,data,logs,plugins}), paperless-ngx
-- (/usr/src/paperless/{data,media,export,consume}), bookstack (/config), odoo
-- (/var/lib/odoo), openproject (/var/openproject/{assets,pgdata}), snipe-it
-- (/var/lib/snipeit), appsmith (/appsmith-stacks) and more. That is a FLOOR: an
-- app that persists without declaring VOLUME (any Laravel app writing to
-- /var/www/html/storage) is invisible to the count.
--
-- Each declared path is bind-mounted from <app>/<env>/shared/volumes/<path>, a
-- sibling of the existing data/ rather than a child of it, so the /data mount
-- does not expose every other mount to the app. Bind mounts live on the host, so
-- they survive `docker rm -f` for free — that is the whole point, and
-- test/container-volumes.test.js proves it by writing a file inside a container,
-- destroying the container, recreating it and reading the file back, with a
-- negative control on an unmounted path so the pass cannot come from the
-- writable layer having survived.
--
-- NO CHECK on either column, following 072/075/076/077/078/085/086: SQLite
-- cannot ALTER a CHECK, so one here would force a rebuild the first time the
-- rules move — and the rules these need (element types, control characters,
-- colons in paths, length caps) are not expressible in a CHECK anyway. They are
-- enforced in services/containerRuntimeSpec.js at both boundaries instead.
--
-- ================================================================
-- WHY THIS IS A TABLE REBUILD AND NOT `ALTER TABLE apps ADD COLUMN`
-- ================================================================
-- Same reason 086 gives, and it was re-measured here rather than taken on
-- faith: the ADD COLUMN version of this file was written first, and the full
-- suite reported test/app-catalog-slug.test.js failing with "the live table and
-- 086 disagree on the column count — 38 !== 36".
--
-- That guard is not incidental. Every rebuild restates the whole column list by
-- hand, and a column missing from that list is not an error — the rebuild
-- succeeds and the data is gone. A column added by ALTER after the newest
-- rebuild is invisible to whoever writes the next one, so container_command and
-- volume_paths would be silently dropped by some future widening of
-- source_type, and the symptom would be catalogue apps losing their command and
-- every declared mount on a schema change that had nothing to do with them —
-- an app that boots, exits 0, and has forgotten where its data lives.
--
-- BACKFILL: none, deliberately. This migration adds the CAPABILITY and changes
-- no app's behaviour — every existing row keeps NULL in both columns and gets
-- exactly the argv it gets today. Populating the catalogue's entries with their
-- real volume paths is a SEPARATE data change to server/services/appCatalog.json,
-- because it is not a no-op: the first deploy after such a change starts an app
-- with an EMPTY directory bound over a path that previously held whatever the
-- image shipped there (bookstack's /config, orangehrm's /var/www/html), which
-- for several of these images means a first-run re-initialisation. That needs
-- per-entry review and a migration note per app, not a blanket UPDATE from a
-- schema migration. Half-migrating — some entries backfilled here, the rest
-- later — is the one outcome to avoid, so this migration backfills nothing.
--
-- The column list below is the live schema as of 087, verified against
-- PRAGMA table_info(apps) on a freshly migrated database: the 36 columns 086
-- restated, unchanged, plus container_command and volume_paths.

PRAGMA foreign_keys = OFF;

CREATE TABLE apps_new (
  id                          INTEGER PRIMARY KEY AUTOINCREMENT,
  name                        TEXT NOT NULL,
  slug                        TEXT UNIQUE NOT NULL,
  slot                        INTEGER UNIQUE NOT NULL,
  domain                      TEXT,
  source_type                 TEXT NOT NULL DEFAULT 'github'
                                CHECK(source_type IN ('github', 'managed', 'managed_legacy', 'upload', 'image')),
  github_url                  TEXT,
  branch                      TEXT DEFAULT 'main',
  github_token_encrypted      TEXT,
  resource_limits             TEXT DEFAULT '{"max_ram_mb":512,"max_cpu_percent":50}',
  created_by                  INTEGER REFERENCES users(id),
  created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
  description                 TEXT,
  public_access               INTEGER NOT NULL DEFAULT 0,
  runtime                     TEXT NOT NULL DEFAULT 'docker',
  category                    TEXT,
  slug_aliases                TEXT,
  visibility                  TEXT NOT NULL DEFAULT 'private',
  image_retention             INTEGER NOT NULL DEFAULT 0,
  frame_ancestors             TEXT,
  claude_credentials_encrypted TEXT,
  auth_mode                   TEXT NOT NULL DEFAULT 'authenticated',
  auth_bypass_paths           TEXT,
  service_token_hash          TEXT,
  service_token_encrypted     TEXT,
  email_from_name             TEXT,
  last_managed_push_sha       TEXT,
  multitenant                 INTEGER NOT NULL DEFAULT 0,
  ingress_type                TEXT NOT NULL DEFAULT 'http',
  public_port                 INTEGER,
  data_plane_port             INTEGER,
  sandbox_public_port         INTEGER,
  image_ref                   TEXT,
  container_port              INTEGER,
  health_path                 TEXT,
  catalog_slug                TEXT,
  container_command           TEXT,
  volume_paths                TEXT
);

-- container_command and volume_paths are absent from both lists on purpose: no
-- existing row has a value for either, so naming them would mean a NULL literal
-- for no gain. Same treatment 086 gave catalog_slug.
INSERT INTO apps_new (
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port,
  image_ref, container_port, health_path, catalog_slug
)
SELECT
  id, name, slug, slot, domain, source_type, github_url, branch,
  github_token_encrypted, resource_limits, created_by, created_at,
  description, public_access, runtime, category, slug_aliases,
  visibility, image_retention, frame_ancestors, claude_credentials_encrypted,
  auth_mode, auth_bypass_paths, service_token_hash, service_token_encrypted,
  email_from_name, last_managed_push_sha, multitenant, ingress_type,
  public_port, data_plane_port, sandbox_public_port,
  image_ref, container_port, health_path, catalog_slug
FROM apps;

DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;

-- Dropping the table dropped its indexes with it. These three are the explicit
-- ones; the UNIQUE constraints on slug and slot rebuild themselves from the
-- column definitions above. The two partial unique indexes are what stop two
-- apps claiming one host port (076), so losing them here would silently undo
-- per-env port safety.
CREATE INDEX IF NOT EXISTS idx_apps_service_token ON apps(service_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_public_port
  ON apps(public_port) WHERE public_port IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_sandbox_public_port
  ON apps(sandbox_public_port) WHERE sandbox_public_port IS NOT NULL;

PRAGMA foreign_keys = ON;
