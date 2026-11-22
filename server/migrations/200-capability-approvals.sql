-- Platform-admin approval for sensitive app capabilities
-- (services/capabilities/registry.js lists them).
--
-- One row is one request AND, once approved, the grant it became. Three origins:
--   request       an owner or app admin asked, with a reason and a scope;
--   implicit      a platform admin set the capability directly, so the
--                 setting carries an audited grant like any other;
--   grandfathered the capability was already in use when this table arrived.
--                 It stays in force (status 'approved') but reviewed_at is NULL
--                 until a platform admin confirms or revokes it.
--
-- scope is what was granted, requested_scope what was asked for; an approver
-- may narrow one to the other but never widen it. A grant stops authorizing at
-- expires_at; the capability-grants sweep then revokes or only flags it,
-- depending on the capability, and stamps expiry_action.
CREATE TABLE IF NOT EXISTS capability_requests (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id           INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  capability       TEXT    NOT NULL,
  origin           TEXT    NOT NULL DEFAULT 'request' CHECK (origin IN ('request', 'implicit', 'grandfathered')),
  status           TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired', 'revoked')),
  requested_scope  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(requested_scope)),
  scope            TEXT    CHECK (scope IS NULL OR json_valid(scope)),
  reason           TEXT,
  requested_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  requested_by_kind TEXT,
  requested_via    TEXT,
  decided_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  decided_at       TEXT,
  decision_note    TEXT,
  expires_at       TEXT,
  reviewed_at      TEXT,
  expiry_action    TEXT CHECK (expiry_action IS NULL OR expiry_action IN ('revoked', 'flagged')),
  ended_by         INTEGER REFERENCES users(id) ON DELETE SET NULL,
  ended_at         TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_capability_requests_app ON capability_requests (app_id, capability, status);
CREATE INDEX IF NOT EXISTS idx_capability_requests_status ON capability_requests (status, created_at);

-- One open request per app and capability: a second click, or an agent
-- retrying, gets the existing request back instead of a duplicate e-mail.
CREATE UNIQUE INDEX IF NOT EXISTS idx_capability_requests_one_pending
  ON capability_requests (app_id, capability) WHERE status = 'pending';

-- Grandfather what is already in use. Nothing about these apps changes; they
-- appear on the platform admins' review list as unreviewed.
INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT id, 'auth_bypass_paths', 'grandfathered', 'approved',
       json_object('paths', json(auth_bypass_paths)), json_object('paths', json(auth_bypass_paths)),
       'In use before capability approvals existed'
FROM apps
WHERE auth_bypass_paths IS NOT NULL AND json_valid(auth_bypass_paths)
  AND json_type(auth_bypass_paths) = 'array' AND json_array_length(auth_bypass_paths) > 0;

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT id, 'headless', 'grandfathered', 'approved', '{}', '{}', 'In use before capability approvals existed'
FROM apps WHERE auth_mode = 'headless';

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT id, 'public_visibility', 'grandfathered', 'approved', '{}', '{}', 'In use before capability approvals existed'
FROM apps WHERE visibility = 'public';

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT id, 'tcp_ports', 'grandfathered', 'approved', s, s, 'In use before capability approvals existed'
FROM (
  SELECT id, json_object(
    'ingress_type', ingress_type,
    'public_port', public_port,
    'sandbox_public_port', sandbox_public_port,
    'data_plane_port', CASE WHEN ingress_type = 'dual' THEN data_plane_port END,
    'data_plane_protocol', COALESCE(data_plane_protocol, 'tcp')
  ) AS s
  FROM apps WHERE ingress_type IN ('tcp', 'dual')
);

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT DISTINCT app_id, 'outbound_email', 'grandfathered', 'approved',
       '{"recipient_domains":["*"]}', '{"recipient_domains":["*"]}',
       'Sent e-mail through the app e-mail API before capability approvals existed'
FROM email_queue WHERE source = 'app' AND app_id IS NOT NULL AND app_id IN (SELECT id FROM apps);

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT app_id, 'external_secret_connections', 'grandfathered', 'approved',
       json_object('providers', json_group_array(DISTINCT provider)), json_object('providers', json_group_array(DISTINCT provider)),
       'In use before capability approvals existed'
FROM secret_connections WHERE app_id IS NOT NULL AND app_id IN (SELECT id FROM apps) GROUP BY app_id;

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT app_id, 'managed_database', 'grandfathered', 'approved',
       json_object('engines', json_group_array(DISTINCT engine)), json_object('engines', json_group_array(DISTINCT engine)),
       'In use before capability approvals existed'
FROM managed_databases WHERE app_id IN (SELECT id FROM apps) GROUP BY app_id;

INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT app_id, 'llm_gateway', 'grandfathered', 'approved', '{}', '{}', 'In use before capability approvals existed'
FROM llm_gateway_apps WHERE enabled = 1 AND app_id IN (SELECT id FROM apps);
