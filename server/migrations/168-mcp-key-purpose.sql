-- user_mcp_keys.purpose: why a personal MCP key exists. NULL is an ordinary
-- key a person created on the MCP page. 'onboarding' is the key the
-- Applications page puts into an app-onboarding agent brief.
--
-- Every onboarding click used to create a new write-capable key that was never
-- revoked, so keys piled up unused. Issuing an onboarding key now revokes the
-- caller's earlier onboarding keys that were never used (routes/userMcpKeys.js),
-- which needs to tell those keys apart from the ones a person made on purpose.
-- Keys from before this column carry the label 'onboarding-<epoch ms>' and are
-- matched by that label instead.

ALTER TABLE user_mcp_keys ADD COLUMN purpose TEXT;
