-- Per-app "What's new e-mail": when the app ships a new production version, its
-- owners and app admins get one mail with that version's What's New text.
--
-- On app_settings (104) like separate_sandbox_db (107), so no apps rebuild.
-- Default 1 and "no row" both mean on.
ALTER TABLE app_settings ADD COLUMN whats_new_email INTEGER NOT NULL DEFAULT 1 CHECK(whats_new_email IN (0, 1));
