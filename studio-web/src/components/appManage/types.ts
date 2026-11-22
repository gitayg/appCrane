export type EnvName = 'production' | 'sandbox'
export const ENVS: EnvName[] = ['production', 'sandbox']
export const ENV_LABEL: Record<EnvName, string> = { production: 'Production', sandbox: 'Sandbox' }

export type TabId = 'overview' | 'releases' | 'env' | 'access' | 'network' | 'security' | 'resources' | 'usage' | 'logs'
export const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'releases', label: 'Releases' },
  { id: 'env', label: 'Env vars' },
  { id: 'access', label: 'Access' },
  { id: 'network', label: 'Network' },
  { id: 'security', label: 'Security' },
  { id: 'resources', label: 'Resources' },
  { id: 'usage', label: 'Usage' },
  { id: 'logs', label: 'Logs' },
]

export interface Person { id: number; name: string; email?: string }

/** One row of GET /api/apps (the list carries the caller's role and owners). */
export interface ManagedApp {
  slug: string
  name: string
  description?: string
  category?: string
  visibility?: string
  github_url?: string
  source_type?: string
  repo_backend?: string | null
  has_icon?: boolean
  code_source?: string | null
  resource_limits?: { max_ram_mb?: number; max_cpu_percent?: number }
  image_retention?: number
  frame_ancestors?: string | null
  auth_bypass_paths?: string[] | null
  ingress_type?: 'http' | 'tcp' | 'dual'
  public_port?: number | null
  sandbox_public_port?: number | null
  data_plane_port?: number | null
  publish_applied?: boolean | null
  publish_drift?: { state: string; message: string } | null
  pending_port_release?: number | null
  domain?: string | null
  custom_domain_auth?: number
  domain_aliases?: { id: number; domain: string; source: string; created_at: string }[]
  url?: string
  sandbox_url?: string
  owner?: Person | null
  owners?: Person[]
  app_role?: 'owner' | 'admin' | 'user' | 'viewer' | 'none'
  production?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
  sandbox?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
  show_sandbox?: boolean
  sandbox_visible?: boolean
}

/** GET /api/apps/:slug (health and webhook live here, not on the list). */
export interface AppDetail {
  app: { can_change_show_sandbox?: boolean; can_rename?: boolean }
  health?: Record<EnvName, { config?: { endpoint?: string } | null; state?: { is_down?: number | boolean; last_status?: number; last_response_ms?: number; last_check_at?: string } | null }>
  webhook?: { auto_deploy_sandbox?: number; auto_deploy_prod?: number; branch_filter?: string } | null
}

export interface Msg { text: string; ok: boolean }

export interface ManageCtx {
  slug: string
  app: ManagedApp
  detail: AppDetail | null
  isPlatformAdmin: boolean
  /** owner, app admin or platform admin: who may read the release log and usage. */
  canAdmin: boolean
  isOwner: boolean
  reload: number
  refresh: () => void
  onMsg: (m: Msg) => void
  setTab: (t: TabId, extra?: Record<string, string>) => void
  patchApp: (p: Partial<ManagedApp>) => void
}
