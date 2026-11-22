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
