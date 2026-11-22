export interface Person { id: number; name?: string | null; email?: string | null; kind?: string | null }

export interface CapabilityRequest {
  id: number
  app: { slug: string; name: string | null } | null
  capability: string
  label: string
  origin: 'request' | 'implicit' | 'grandfathered'
  status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired' | 'revoked'
  active: boolean
  unreviewed: boolean
  requested_scope: Record<string, unknown>
  scope: Record<string, unknown> | null
  reason: string | null
  requested_by: Person | null
  requested_by_kind: string | null
  requested_via: string | null
  decided_by: Person | null
  decided_at: string | null
  decision_note: string | null
  expires_at: string | null
  reviewed_at: string | null
  expiry_action: 'revoked' | 'flagged' | null
  created_at: string
}

export interface CapabilityPolicy {
  label: string
  description: string
  approval_required: boolean
  default_approval_required: boolean
  always_required?: boolean
  when_off: string
  on_expiry: 'revoke' | 'flag'
  on_revoke: 'revoke' | 'flag'
}

export interface AppCapability extends CapabilityPolicy {
  example_scope: Record<string, unknown>
  grants: CapabilityRequest[]
  pending: CapabilityRequest | null
  history: CapabilityRequest[]
}

export interface AppCapabilities {
  app: string
  can_request: boolean
  capabilities: Record<string, AppCapability>
  external: Record<string, { label: string; description: string; in_use: boolean | null; category?: string | null; review_required?: boolean }>
}

export const personLabel = (p: Person | null) => (p ? p.name || p.email || `#${p.id}` : 'AppCrane')
export const scopeText = (s: Record<string, unknown> | null) => (s && Object.keys(s).length ? JSON.stringify(s) : 'whole capability')
