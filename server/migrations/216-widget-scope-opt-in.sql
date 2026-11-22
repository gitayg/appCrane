-- Per-app opt-in for the two widget scopes that act with an owner's power:
-- 'members' (change roles, add members) and 'app-keys' (issue sign-in keys).
-- A widget token lives in the app page's JavaScript, so with these on, a bug
-- or an XSS in the app can use them while an owner has the page open. Off by
-- default: POST /__appcrane/widgets/token never grants them, and the widget
-- endpoints refuse them, until an owner or platform admin turns each on
-- (PUT /api/apps/:slug/widget-scopes, audited).
--
-- On app_settings (104) like whats_new_email (125). Default 0 and "no row"
-- both mean off.
ALTER TABLE app_settings ADD COLUMN widget_members INTEGER NOT NULL DEFAULT 0 CHECK(widget_members IN (0, 1));
ALTER TABLE app_settings ADD COLUMN widget_app_keys INTEGER NOT NULL DEFAULT 0 CHECK(widget_app_keys IN (0, 1));
