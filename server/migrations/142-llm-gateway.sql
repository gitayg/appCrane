-- LLM gateway for hosted apps (services/llmGateway/*).
--
-- An app that opts in reaches Anthropic / OpenAI through AppCrane at
-- /api/service/llm/*: the deploy injects the provider SDK's base URL and a
-- gateway token in place of a provider key, and AppCrane adds its own key on
-- the way out. The platform-wide config (provider keys, allowlists, prices,
-- default limits) lives in settings under the key 'llm_gateway'.

-- Per-app opt-in plus the platform admin's per-app overrides (models, limits).
CREATE TABLE IF NOT EXISTS llm_gateway_apps (
  app_id         INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  enabled        INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  overrides_json TEXT NOT NULL DEFAULT '{}',
  updated_by     INTEGER,
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One gateway token per app and environment. It opens /api/service/llm/* and
-- nothing else: requireAuth and the service API never look in this table.
CREATE TABLE IF NOT EXISTS llm_gateway_tokens (
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env             TEXT NOT NULL CHECK (env IN ('production', 'sandbox')),
  token_hash      TEXT NOT NULL UNIQUE,
  token_encrypted TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);

-- One row per gateway request. Metadata only: never a prompt, a response or a key.
CREATE TABLE IF NOT EXISTS llm_gateway_usage (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env           TEXT NOT NULL,
  provider      TEXT NOT NULL,
  endpoint      TEXT NOT NULL,
  model         TEXT,
  status        INTEGER,
  outcome       TEXT NOT NULL,
  stream        INTEGER NOT NULL DEFAULT 0,
  input_tokens  INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd      REAL,
  latency_ms    INTEGER,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_llm_gateway_usage_app ON llm_gateway_usage (app_id, env, created_at);
CREATE INDEX IF NOT EXISTS idx_llm_gateway_usage_created ON llm_gateway_usage (created_at);
