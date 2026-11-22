// Shapes served by /api/oauth/admin/blueprints, /api/oauth/blueprints and
// /api/oauth/admin/policy (server/routes/oauthAdminBlueprints.js, oauthAdmin.js).

export interface Blueprint {
  id: number
  name: string
  description: string
  scopes: string[]
  apps: string[] | null
  builtin?: boolean
}

export interface ScopeGroup {
  scope: string
  label: string
  description: string
  tools: string[]
}

export interface BlueprintAdminList {
  blueprints: Blueprint[]
  scope_groups: ScopeGroup[]
}

export interface ClientSourcesPolicy {
  cimd_enabled: boolean
  id_jag_enabled: boolean
  crane_domain_set: boolean
  oidc_configured: boolean
}
