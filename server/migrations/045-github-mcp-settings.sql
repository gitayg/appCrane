-- v1.31: GitHub MCP per-user container settings.
--
-- AppCrane orchestrates a per-user github-mcp-server Docker container so the
-- end user only configures one MCP (AppCrane) in their client; AppCrane
-- proxies github_* tool calls to that user's container, holding a PAT they
-- supplied via X-Github-Token header in their MCP client config.
--
-- Idle timeout (seconds): containers with no github_* activity for this long
-- are stopped by the reaper.
-- Max concurrent: hard cap on simultaneously-running containers across all
-- users. The 11th user gets a capacity error suggesting retry in ~half the
-- idle timeout.
-- Image: pinnable container image tag for security/reproducibility.

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('github_mcp_idle_timeout',   '600'),
  ('github_mcp_max_concurrent', '10'),
  ('github_mcp_image',          'ghcr.io/github/github-mcp-server:latest');
