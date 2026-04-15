-- DeployHub Schema v1

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
  api_key_hash TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  slot INTEGER UNIQUE NOT NULL,
  domain TEXT,
  source_type TEXT NOT NULL DEFAULT 'github' CHECK(source_type IN ('github', 'upload')),
  github_url TEXT,
  branch TEXT DEFAULT 'main',
  github_token_encrypted TEXT,
  resource_limits TEXT DEFAULT '{"max_ram_mb":512,"max_cpu_percent":50}',
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_users (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (app_id, user_id)
);

CREATE TABLE IF NOT EXISTS deployments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  version TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'building', 'deploying', 'live', 'failed', 'rolled_back')),
  commit_hash TEXT,
  commit_message TEXT,
  log TEXT,
  deployed_by INTEGER REFERENCES users(id),
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS env_vars (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  key TEXT NOT NULL,
  value_encrypted TEXT NOT NULL,
  updated_by INTEGER REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, env, key)
);

CREATE TABLE IF NOT EXISTS health_configs (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  endpoint TEXT NOT NULL DEFAULT '/api/health',
  interval_sec INTEGER NOT NULL DEFAULT 30,
  fail_threshold INTEGER NOT NULL DEFAULT 3,
  down_threshold INTEGER NOT NULL DEFAULT 5,
  enabled INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (app_id, env)
);

CREATE TABLE IF NOT EXISTS health_state (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  consecutive_fails INTEGER NOT NULL DEFAULT 0,
  last_check_at TEXT,
  last_status INTEGER,
  last_response_ms INTEGER,
  is_down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, env)
);

CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  size_bytes INTEGER DEFAULT 0,
  file_path TEXT NOT NULL,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  app_id INTEGER REFERENCES apps(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_configs (
  app_id INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  secret TEXT NOT NULL,
  auto_deploy_sandbox INTEGER NOT NULL DEFAULT 1,
  auto_deploy_prod INTEGER NOT NULL DEFAULT 0,
  branch_filter TEXT DEFAULT 'main'
);

CREATE TABLE IF NOT EXISTS notification_configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  on_deploy_success INTEGER NOT NULL DEFAULT 1,
  on_deploy_fail INTEGER NOT NULL DEFAULT 1,
  on_app_down INTEGER NOT NULL DEFAULT 1,
  on_app_recovered INTEGER NOT NULL DEFAULT 1,
  UNIQUE(user_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_deployments_app_env ON deployments(app_id, env);
CREATE INDEX IF NOT EXISTS idx_audit_log_app ON audit_log(app_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_env_vars_app_env ON env_vars(app_id, env);
