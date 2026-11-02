-- The latest deploys of an app in one environment (the app list, monitoring,
-- metrics, the deployer's rollback and promote lookups) are read as
-- `WHERE app_id = ? AND env = ? ... ORDER BY started_at DESC LIMIT n`.
-- idx_deployments_app_env found the rows but every lookup sorted them in a temp
-- B-tree; with started_at in the index they come out in order. It serves plain
-- (app_id, env) and app_id lookups too, so it replaces that index.
CREATE INDEX IF NOT EXISTS idx_deployments_app_env_started ON deployments(app_id, env, started_at DESC);
DROP INDEX IF EXISTS idx_deployments_app_env;
