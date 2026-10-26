-- App owners may rename their own apps (no longer platform-admin only), so the
-- two things a rename must never do are enforced here, not only in the route.
--
-- 1. A slug an app was renamed away from stays that app's while it redirects
--    (apps.slug_aliases). If another app could take it, that app would receive
--    every bookmark and link still pointing at the old URL. apps.slug is
--    UNIQUE already; these triggers extend the same guarantee to the old
--    slugs, on every write path (create, rename, reconcile), so two writers
--    racing for one slug cannot both win.
--
-- 2. Renames are throttled per app; app_slug_renames is the record they are
--    counted from, written in the same transaction as the rename itself.
--
-- A migration that rebuilds the apps table drops these triggers with it;
-- test/app-rename-owner.test.js fails when they are missing.

CREATE TRIGGER IF NOT EXISTS apps_slug_not_alias_insert
BEFORE INSERT ON apps
WHEN EXISTS (
  SELECT 1 FROM apps a,
    json_each(CASE WHEN json_valid(a.slug_aliases) THEN a.slug_aliases ELSE '[]' END) j
  WHERE j.value = NEW.slug
)
BEGIN
  SELECT RAISE(ABORT, 'SLUG_TAKEN');
END;

CREATE TRIGGER IF NOT EXISTS apps_slug_not_alias_update
BEFORE UPDATE OF slug ON apps
WHEN NEW.slug <> OLD.slug AND EXISTS (
  SELECT 1 FROM apps a,
    json_each(CASE WHEN json_valid(a.slug_aliases) THEN a.slug_aliases ELSE '[]' END) j
  WHERE j.value = NEW.slug AND a.id <> NEW.id
)
BEGIN
  SELECT RAISE(ABORT, 'SLUG_TAKEN');
END;

CREATE TABLE IF NOT EXISTS app_slug_renames (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  old_slug    TEXT NOT NULL,
  new_slug    TEXT NOT NULL,
  renamed_by  INTEGER,
  renamed_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_slug_renames_app ON app_slug_renames (app_id, renamed_at);
