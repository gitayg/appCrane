-- GitHub's numeric repository id for an attached installation row
-- (services/githubAppWebhook.js).
--
-- A `repository` webhook with action renamed or transferred is matched on
-- this id, never on the name: after a rename the name in the payload is the
-- NEW one, which no row holds. NULL until a verified delivery names the
-- repository (push, installation_repositories added) while it still matches
-- the row by installation and name; every later such delivery refreshes it,
-- so a repository deleted and recreated under the same name takes over the id.
ALTER TABLE app_github_installations ADD COLUMN repo_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_app_github_installations_repo_id ON app_github_installations (repo_id);
