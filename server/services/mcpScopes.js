// Fine-grained MCP scopes: which scope each appcrane_* tool needs.
//
// A credential with no scopes (a legacy OAuth grant for `mcp` / `mcp:read`, a
// dhk_mcp_* key with no blueprint) is not checked here at all: it keeps the
// role-based behaviour it always had. A scoped credential (fine-grained scopes
// asked for at /oauth/authorize, or a blueprint on the grant or key) may call a
// tool only when its effective scope set holds the tool's scope. The role gate
// (canUseTool, per-slug checks in each handler) still runs after this one, so
// the result is always role AND scope.
//
// The table below is the one place a tool is given a scope. A tool missing from
// it is refused to every scoped credential (fails closed), and
// test/mcp-scopes.test.js fails until it is added.

export const SCOPE = Object.freeze({
  FULL: 'mcp',
  READ: 'mcp:read',
  FEEDBACK: 'mcp:feedback',
  SECRETS: 'mcp:secrets:read',
  DEPLOY_SANDBOX: 'mcp:deploy:sandbox',
  DEPLOY: 'mcp:deploy',
  APP_WRITE: 'mcp:app:write',
  APP_ACCESS: 'mcp:app:access',
  APP_CREATE: 'mcp:app:create',
  APP_DELETE: 'mcp:app:delete',
  PLATFORM: 'mcp:platform',
  CREW: 'mcp:crew',
  GITHUB: 'mcp:github',
});

// Plain-language names for the admin screens (served by the API, so the UI
// never keeps its own copy of the scope list).
export const SCOPE_INFO = Object.freeze({
  [SCOPE.FULL]: { label: 'Everything', description: 'Every scope below. The same as a connection without scopes, within the person\'s role.' },
  [SCOPE.READ]: { label: 'Read', description: 'See apps, deploys, logs, members, audit and masked settings.' },
  [SCOPE.FEEDBACK]: { label: 'Send feedback', description: 'Report a bug or idea about an app or AppCrane.' },
  [SCOPE.SECRETS]: { label: 'Read secret values', description: 'Reveal secrets in plain text and read raw files from containers.' },
  [SCOPE.DEPLOY_SANDBOX]: { label: 'Deploy sandbox', description: 'Deploy, roll back and upload builds to sandbox only.' },
  [SCOPE.DEPLOY]: { label: 'Deploy any env', description: 'Deploy, roll back and promote sandbox and production.' },
  [SCOPE.APP_WRITE]: { label: 'Change apps', description: 'Push code, edit settings, secrets, cron runs, databases and app context.' },
  [SCOPE.APP_ACCESS]: { label: 'Manage members', description: 'Grant and revoke access, app roles and access requests.' },
  [SCOPE.APP_CREATE]: { label: 'Create apps', description: 'Create, adopt and scaffold new apps.' },
  [SCOPE.APP_DELETE]: { label: 'Delete apps', description: 'Delete an app.' },
  [SCOPE.PLATFORM]: { label: 'Platform settings', description: 'Ingress, backups, scans, platform policy and app updates reserved for platform admins.' },
  [SCOPE.CREW]: { label: 'Crew messages', description: 'Register agents and send or answer Crew messages.' },
  [SCOPE.GITHUB]: { label: 'GitHub passthrough', description: 'Call GitHub tools through AppCrane with the person\'s GitHub token.' },
});

export const FINE_SCOPES = Object.freeze(Object.values(SCOPE).filter((s) => s !== SCOPE.FULL));
export const ALL_SCOPES = Object.freeze([SCOPE.FULL, ...FINE_SCOPES]);

// A broader scope implies narrower ones (MCP authorization: servers MUST
// account for scope hierarchies).
const IMPLIES = {
  [SCOPE.FULL]: FINE_SCOPES,
  [SCOPE.DEPLOY]: [SCOPE.DEPLOY_SANDBOX],
};

const ENV_DEPLOY = 'env-deploy';

const GROUPS = {
  [SCOPE.READ]: [
    'appcrane_list_apps', 'appcrane_get_app', 'appcrane_top_apps', 'appcrane_top_users', 'appcrane_get_health',
    'appcrane_get_secret', 'appcrane_list_releases', 'appcrane_list_requests', 'appcrane_ls', 'appcrane_wait_deploy',
    'appcrane_get_deploy_log', 'appcrane_get_logs', 'appcrane_get_app_context', 'appcrane_get_app_ingress',
    'appcrane_list_app_members', 'appcrane_list_app_roles', 'appcrane_list_access_requests', 'appcrane_get_guide',
    'appcrane_get_audit', 'appcrane_list_cron', 'appcrane_check_resource_limits', 'appcrane_get_backup_status',
    'appcrane_memory_budget', 'appcrane_get_app_scan', 'appcrane_scan_report', 'appcrane_list_databases',
    'appcrane_crew_roster', 'appcrane_crew_who_is_on', 'appcrane_crew_inbox', 'appcrane_crew_rules',
    'appcrane_list_capability_requests',
  ],
  [SCOPE.SECRETS]: ['appcrane_reveal_secret', 'appcrane_cat'],
  [ENV_DEPLOY]: ['appcrane_deploy', 'appcrane_rollback', 'appcrane_deploy_artifact'],
  [SCOPE.DEPLOY]: ['appcrane_promote'],
  [`${SCOPE.DEPLOY_SANDBOX}|${SCOPE.APP_WRITE}`]: ['appcrane_stage_from_url', 'appcrane_stage_chunk', 'appcrane_stage_assemble'],
  [SCOPE.APP_WRITE]: [
    'appcrane_set_request_status', 'appcrane_rename_app', 'appcrane_append_app_context', 'appcrane_set_app_context',
    'appcrane_set_app_meta', 'appcrane_set_app_icon', 'appcrane_push_to_managed_app', 'appcrane_managed_push_chunk',
    'appcrane_managed_assemble', 'appcrane_managed_patch', 'appcrane_set_secret', 'appcrane_cp', 'appcrane_run_cron_now',
    'appcrane_provision_database', 'appcrane_push_staged_file', 'appcrane_request_capability',
  ],
  [SCOPE.APP_ACCESS]: [
    'appcrane_grant_app_access', 'appcrane_revoke_app_access', 'appcrane_create_app_role', 'appcrane_set_user_app_roles',
    'appcrane_approve_access_request', 'appcrane_deny_access_request',
  ],
  [SCOPE.APP_CREATE]: ['appcrane_create_app', 'appcrane_adopt_app', 'appcrane_create_managed_app'],
  [SCOPE.APP_DELETE]: ['appcrane_delete_app'],
  [SCOPE.PLATFORM]: [
    'appcrane_update_app', 'appcrane_set_app_ingress', 'appcrane_set_backup_config', 'appcrane_run_backup_now',
    'appcrane_scan_app', 'appcrane_platform_policy',
  ],
  [SCOPE.CREW]: ['appcrane_crew_register', 'appcrane_crew_send', 'appcrane_crew_reply'],
  [SCOPE.FEEDBACK]: ['appcrane_submit_feedback'],
};

export const TOOL_SCOPES = Object.freeze(Object.fromEntries(
  Object.entries(GROUPS).flatMap(([group, names]) => names.map((n) => [n, group])),
));

/** Expand a list of scope strings through the hierarchy; unknown ones are dropped. */
export function expandScopes(list) {
  const out = new Set();
  for (const s of list || []) {
    if (!ALL_SCOPES.includes(s)) continue;
    out.add(s);
    for (const i of IMPLIES[s] || []) out.add(i);
  }
  out.delete(SCOPE.FULL);
  return out;
}

export function parseScopeString(raw) {
  return typeof raw === 'string' ? [...new Set(raw.split(/\s+/).filter(Boolean))] : [];
}

const envOf = (args) => ((args?.env ?? args?.stage) === 'production' ? 'production' : 'sandbox');

/** The scopes that would each satisfy a call to this tool with these args (any one is enough). */
export function requiredScopes(toolName, args) {
  const group = TOOL_SCOPES[toolName];
  if (!group) return [];
  if (group === ENV_DEPLOY) return [envOf(args) === 'production' ? SCOPE.DEPLOY : SCOPE.DEPLOY_SANDBOX];
  return group.split('|');
}

/** Is the tool advertised in tools/list to this scope set (callable with some arguments)? */
export function toolListed(scopes, toolName) {
  if (!scopes) return true;
  const group = TOOL_SCOPES[toolName];
  if (!group) return false;
  if (group === ENV_DEPLOY) return scopes.has(SCOPE.DEPLOY_SANDBOX);
  return group.split('|').some((s) => scopes.has(s));
}

export class ScopeError extends Error {
  constructor(message, required) {
    super(message);
    this.insufficientScope = true;
    this.requiredScope = required.join(' ');
  }
}

/** Throws ScopeError unless this scope set may make this call. `scopes` null = legacy credential. */
export function assertToolScope(scopes, toolName, args) {
  if (!scopes) return;
  const need = requiredScopes(toolName, args);
  if (!need.length) {
    throw new ScopeError(`Forbidden: ${toolName} has no scope assigned, so a scoped credential cannot call it`, [SCOPE.FULL]);
  }
  if (need.some((s) => scopes.has(s))) return;
  throw new ScopeError(`Forbidden: ${toolName} needs scope ${need.join(' or ')}, which this credential was not granted`, need);
}

/** The effective scope set carried by a request, or null for a legacy (unscoped) credential. */
export function scopesOf(user, userMcpKey) {
  const list = userMcpKey?.scopes ?? user?.mcp_scopes ?? null;
  return Array.isArray(list) ? new Set(list) : null;
}

/** Each fine-grained scope with its name, description and the tools it opens, for the admin UI. */
export function scopeGroups() {
  return FINE_SCOPES.map((scope) => ({
    scope, ...SCOPE_INFO[scope],
    tools: Object.keys(TOOL_SCOPES).filter((t) => toolListed(expandScopes([scope]), t)).sort(),
  }));
}
