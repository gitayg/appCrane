// Settings keys that a dedicated route owns: it validates the value, applies
// step-up and audits the change. PUT /api/settings/:key refuses them so the
// generic writer cannot change sign-in, SSO, SCIM, MFA, OAuth, approval,
// egress, audit or other security policy around those gates.

const OWNED = [
  { prefix: 'oidc_', route: 'PUT /api/auth/oidc/config' },
  { prefix: 'saml_', route: 'PUT /api/auth/saml/config' },
  { prefix: 'scim_', route: 'PUT /api/auth/scim/config or POST /api/auth/scim/token' },
  { prefix: 'auth_mfa_', route: 'PUT /api/identity/mfa/policy' },
  { prefix: 'mfa_', route: 'PUT /api/identity/mfa/policy' },
  { prefix: 'session_admin_', route: 'PUT /api/identity/mfa/policy' },
  { prefix: 'session_user_', route: 'PUT /api/identity/mfa/policy' },
  { prefix: 'step_up_', route: 'PUT /api/identity/step-up/policy' },
  { prefix: 'oauth_', route: 'PUT /api/oauth/admin/policy' },
  { prefix: 'capability_approval_required:', route: 'PUT /api/capability-approvals/policy' },
  { prefix: 'egress_', route: 'PUT /api/egress/settings' },
  { prefix: 'app_audit_', route: 'PUT /api/app-audit/settings' },
  { prefix: 'siem_', route: 'PUT /api/settings/siem/network' },
  { prefix: 'signin_risk_', route: 'PUT /api/signin-security/policy' },
  { prefix: 'policy_', route: 'PUT /api/apps/platform-policy' },
  { prefix: 'github_service_', route: 'PUT /api/github-service/config' },
  { key: 'llm_gateway', route: 'PUT /api/llm-gateway/config' },
  { key: 'api_key_max_age_days', route: 'PUT /api/api-key-policy' },
  { key: 'classification_policy', route: 'PUT /api/data-classification/policy' },
  { key: 'access_review_policy', route: 'PUT /api/access-reviews/policy' },
  { key: 'graph_client_secret_encrypted', route: 'PUT /api/settings/mail/config' },
];

export function ownedSettingRoute(key) {
  const k = String(key);
  const hit = OWNED.find((o) => (o.key ? k === o.key : k.startsWith(o.prefix)));
  return hit ? hit.route : null;
}

// Settings whose value is a protection, a limit or the state behind one
// (v2.147.0). PUT /api/settings/:key answers 409 for these: a route that
// validates, audits and asks for a step-up when the change weakens the
// protection owns them, or AppCrane alone records them (readOnly).
export const PROTECTED_ROUTE = 'PUT /api/settings/protected/';

// Served by routes/protectedSettings.js, which has no other writer.
export const PROTECTED_ROUTE_KEYS = Object.freeze([
  'host_gateway_auto_repair',
  'restart_loop_short_count',
  'restart_loop_short_minutes',
  'restart_loop_long_count',
  'restart_loop_long_minutes',
  'restart_loop_quiet_minutes',
  'restart_backoff_base_minutes',
  'restart_backoff_max_minutes',
  'restart_incident_retention_days',
  'supply_chain_verify_enabled',
  'vuln_alerts_immediate',
  'app_access_mail_enabled',
  'max_dev_containers',
  'app_disk_quota_mb',
  'db_allowlist_mode',
]);

// Recorded by AppCrane only. Readable through GET /api/settings/protected/:key.
export const READ_ONLY_KEYS = Object.freeze([
  'host_gateway_repairs',
  'host_hardening_last_run',
  'host_hardening_auto_last',
  'credcheck_state',
  'host_vulns_last_result',
  'host_vulns_last_run',
  'host_vulns_mailed',
  'crew_retention_last_run',
]);

const PROTECTED_ELSEWHERE = [
  { key: 'managed_db_conn_limit', route: 'PUT /api/managed-db/settings' },
  { key: 'managed_db_pg_max_connections', route: 'PUT /api/managed-db/settings' },
  { key: 'managed_db_statement_timeout_s', route: 'PUT /api/managed-db/settings' },
  { key: 'managed_db_auth_alert_threshold', route: 'PUT /api/managed-db/settings' },
  { key: 'managed_db_pg_stat_statements', route: 'PUT /api/managed-db/settings' },
  { key: 'memory_admission_mode', route: 'PUT /api/settings/server-capacity' },
  { key: 'memory_reserve_mb', route: 'PUT /api/settings/server-capacity' },
  { key: 'cpu_admission_mode', route: 'PUT /api/settings/server-capacity' },
  { key: 'cpu_reserve_cores', route: 'PUT /api/settings/server-capacity' },
  { key: 'cpu_overcommit_ratio', route: 'PUT /api/settings/server-capacity' },
  { key: 'mcp_oauth_only', route: 'PUT /api/api-key-policy' },
  { key: 'mcp_oauth_only_exempt_user_ids', route: 'PUT /api/api-key-policy' },
  { key: 'llm_gateway_retention_days', route: 'PUT /api/ai-act/retention' },
  { prefix: 'event_retention_', route: 'PUT /api/events/retention' },
  { key: 'edge_refuse_brotli_bodies', route: 'PUT /api/settings/edge/brotli' },
  { key: 'container_runtime_default', route: 'PUT /api/container-runtime/settings' },
  { key: 'pull_base_images_app_dockerfiles', route: 'PUT /api/runtime-patch/policy' },
  { key: 'host_hardening_auto_apply', route: 'PUT /api/settings/host-hardening/auto' },
];

/** { route } or { readOnly: true } for a protected key, else null. */
export function protectedSetting(key) {
  const k = String(key);
  if (READ_ONLY_KEYS.includes(k)) return { readOnly: true };
  if (PROTECTED_ROUTE_KEYS.includes(k)) return { route: PROTECTED_ROUTE + k };
  const hit = PROTECTED_ELSEWHERE.find((o) => (o.key ? k === o.key : k.startsWith(o.prefix)));
  return hit ? { route: hit.route } : null;
}

// Refused by PUT /api/settings/:key in its own checks (routes/settings.js).
const REFUSED_INLINE = [
  { prefix: 'managed_db_mariadb_encryption', route: 'PUT /api/managed-db/encryption' },
  { prefix: 'image_signing_', route: 'PUT /api/image-trust/policy' },
  { prefix: 'image_trust_', route: 'PUT /api/image-trust/policy' },
  { prefix: 'app_isolation_', route: 'PUT /api/settings/isolation' },
  { key: 'platform_anthropic_key_encrypted', route: 'PUT /api/appstudio/anthropic-key' },
  { key: 'auto_approve_rce_fixes', route: 'PUT /api/auto-patch/policy' },
  { key: 'auto_patch_cooldown_hours', route: 'PUT /api/auto-patch/policy' },
  { key: 'auth_sso_only', route: 'PUT /api/settings/auth_sso_only (step-up)' },
];

/**
 * Every key the settings snapshot import (POST /api/config/import) must not
 * write without include_protected: owned, protected or refused by the generic
 * writer. { route } or { readOnly: true }, else null.
 */
export function guardedSettingKey(key) {
  const owner = ownedSettingRoute(key);
  if (owner) return { route: owner };
  const p = protectedSetting(key);
  if (p) return p;
  const k = String(key);
  const hit = REFUSED_INLINE.find((o) => (o.key ? k === o.key : k.startsWith(o.prefix)));
  return hit ? { route: hit.route } : null;
}
