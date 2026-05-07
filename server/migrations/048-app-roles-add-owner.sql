-- migration:no-transaction
--
-- v2.2.11: Fix latent bug from migration 042-owner-role.sql.
--
-- Migration 042 introduced the 'owner' per-app role tier and tried to
-- auto-promote existing app creators to it. But it never relaxed the
-- CHECK constraint on app_user_roles.app_role (set by 004-role-update
-- to IN ('none', 'user', 'admin')). Result: 042's INSERT OR IGNORE
-- silently discarded every owner row (CHECK violation, OR IGNORE
-- swallowed it), and 042's UPDATE matched nothing for the same reason.
-- Migration was recorded as applied; database had zero owner rows.
--
-- Symptom that surfaced: PUT /api/apps/:slug/roles {app_role: 'owner'}
-- on the dashboard returned
--   "CHECK constraint failed: app_role IN ('none', 'user', 'admin')"
--
-- This migration:
--   1. Rebuilds app_user_roles with the relaxed CHECK
--   2. Re-runs 042's auto-promote logic now that owner is allowed
--
-- Pattern matches 046's no-transaction + foreign_keys=OFF approach.

PRAGMA foreign_keys = OFF;

CREATE TABLE app_user_roles_new (
  app_id   INTEGER NOT NULL REFERENCES apps(id)  ON DELETE CASCADE,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_role TEXT    NOT NULL DEFAULT 'none' CHECK(app_role IN ('none', 'user', 'admin', 'owner')),
  PRIMARY KEY (app_id, user_id)
);

INSERT INTO app_user_roles_new (app_id, user_id, app_role)
SELECT app_id, user_id, app_role FROM app_user_roles;

DROP TABLE app_user_roles;
ALTER TABLE app_user_roles_new RENAME TO app_user_roles;

CREATE INDEX IF NOT EXISTS idx_app_user_roles_app ON app_user_roles(app_id);

PRAGMA foreign_keys = ON;

-- Re-run 042's promote logic now that the CHECK accepts 'owner'.
-- INSERT OR IGNORE so we skip rows where (app_id, user_id) already exists
-- (e.g. operator already manually inserted them).
INSERT OR IGNORE INTO app_user_roles (app_id, user_id, app_role)
  SELECT id, created_by, 'owner'
  FROM apps
  WHERE created_by IS NOT NULL;

UPDATE app_user_roles
  SET app_role = 'owner'
  WHERE app_role = 'admin'
    AND (app_id, user_id) IN (
      SELECT id, created_by FROM apps WHERE created_by IS NOT NULL
    );
