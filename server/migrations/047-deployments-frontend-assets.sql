-- v2.2.6: track frontend asset reachability per deployment.
--
-- After a deploy goes "live" (container up, /api/health green), AppCrane
-- runs a HEAD probe through Caddy against every script/link/img reference
-- in the served index.html. If any 404, we record that on the deployment
-- record so MCP agents (and the dashboard) can distinguish "container is
-- healthy" from "users can actually load the app."
--
-- Values:
--   'ok'           — every asset reference returned 2xx
--   'missing'      — at least one returned 404
--   'inconclusive' — index page redirected (auth wall) or unreachable; we
--                    couldn't verify
--   NULL           — pre-v2.2.6 deployments, or probe didn't run
--
-- ALTER TABLE ADD COLUMN works inside the migration runner's transaction
-- wrapper; no need for the no-transaction directive.

ALTER TABLE deployments ADD COLUMN frontend_assets TEXT;
