-- Managed databases: a second, DML-only login per scope, and per-database
-- extensions AppCrane wires up on request (deployhub.json `database` block).
--
-- app_user / app_password_enc: the `<login>_app` login (`"app_login": true`).
-- It can connect to its scope's database and SELECT/INSERT/UPDATE/DELETE, and
-- cannot create, alter or drop anything; the owner login stays the one
-- migrations use. NULL when the app never asked for one. The password is only
-- ever stored through encryption.js, like password_enc. Turning the option off
-- later disables the login (NOLOGIN / ACCOUNT LOCK) but keeps the role, because
-- a dump taken while it existed carries GRANTs naming it and would no longer
-- restore if the role were gone.
--
-- extensions: JSON array of the extensions AppCrane installed in the
-- database as the superuser because the app login cannot (today only
-- pg_stat_statements, which is not a trusted extension). Re-applied after a
-- restore, which is why it is on the row and not only in the manifest.
--
-- No CHECK constraints, same reason as migrations 085 and 108.
ALTER TABLE managed_databases ADD COLUMN app_user TEXT;
ALTER TABLE managed_databases ADD COLUMN app_password_enc TEXT;
ALTER TABLE managed_databases ADD COLUMN extensions TEXT;
