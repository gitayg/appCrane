export interface AppAuditEntity { type: string; id: string; name?: string | null }
export interface AppAuditEvent {
  id: number
  source: 'app'
  app: { id: number; slug: string }
  action: string
  occurred_at: string
  received_at: string
  actor: AppAuditEntity & { verified: boolean; identity_env?: string }
  targets: AppAuditEntity[]
  context: { location?: string; user_agent?: string }
  metadata: Record<string, unknown> | null
  unregistered: boolean
}
export interface AppAuditPage { events: AppAuditEvent[]; limit: number; next_before: number | null }
export interface AppAuditConfig {
  types: { id: number; action: string; description: string | null; created_at: string }[]
  settings: { allow_unregistered: boolean }
  retention_days: number
  can_manage_types: boolean
  can_manage_streams: boolean
}
export interface AppAuditStream {
  id: number
  name: string
  type: 'syslog' | 'https' | 's3'
  preset: string
  format: string
  enabled: boolean
  config: Record<string, unknown>
  secrets: Record<string, { set: boolean; preview?: string }>
  filters: { actions: string[] }
  delivered_count: number
  last_success_at: string | null
  last_error: string | null
}
