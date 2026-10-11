-- Retire the global 'admin' role (users.role = 'admin').
--
-- That tier made a person admin on EVERY app without anyone assigning them —
-- the opposite of the rule that app access is granted per app. Platform admin
-- stays; per-app roles in app_user_roles (owner / admin / user / viewer) are a
-- different thing and are not touched here, so "app admin" still exists.
--
-- Former holders become plain 'user'. They keep exactly the apps they have
-- explicit app_user_roles rows for, at that app role, and lose the implicit
-- access to every other app. Nobody is promoted.
-- Lockout guard, the same rule as 066: a box whose only privileged accounts
-- are global admins would be left with nobody able to manage it (no platform
-- admin, and `crane init` refuses once users exist). Only then is the oldest
-- admin made platform admin. A no-op on every box 066 already covered.
UPDATE users
SET role = 'platform_admin'
WHERE id = (SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1)
AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'platform_admin');

UPDATE users SET role = 'user' WHERE role = 'admin';

-- Nobody may hold 'admin' again. The CHECK from 046 still lists it, but
-- relaxing a CHECK means rebuilding users (see the history in 046 for why that
-- is painful here); triggers do the same job with no rebuild. The API refuses
-- 'admin' with a 400 first — these are the backstop for any write path that
-- was missed.
CREATE TRIGGER IF NOT EXISTS users_no_global_admin_insert
BEFORE INSERT ON users
WHEN NEW.role = 'admin'
BEGIN
  SELECT RAISE(ABORT, 'The global admin role was retired: use role user with per-app admin, or platform_admin');
END;

CREATE TRIGGER IF NOT EXISTS users_no_global_admin_update
BEFORE UPDATE OF role ON users
WHEN NEW.role = 'admin'
BEGIN
  SELECT RAISE(ABORT, 'The global admin role was retired: use role user with per-app admin, or platform_admin');
END;
