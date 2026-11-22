export interface PersonRef { id: number; name: string | null; email: string | null }

export interface OwnerTransfer {
  id: number
  app_id: number
  app_slug: string | null
  app_name: string | null
  kind: 'orphan' | 'handover'
  step_down: boolean
  note: string | null
  status: 'pending' | 'accepted' | 'declined' | 'cancelled' | 'superseded' | 'expired'
  created_at: string
  expires_at: string
  decided_at: string | null
  nominee: PersonRef | null
  nominated_by: PersonRef | null
}

export interface OrphanDetail { reason: string; former_owner_ids: number[] }

export interface Ownership {
  app: string
  owners: PersonRef[]
  orphaned: boolean
  orphan: { orphaned_at: string; cause: string; detail: OrphanDetail | null } | null
  pending_transfer: OwnerTransfer | null
  can_nominate: boolean
  can_assign: boolean
  viewer_role: 'platform_admin' | 'owner' | 'admin' | 'user' | null
}

export interface OrphanedApp {
  orphan_id: number
  app_id: number
  slug: string
  name: string
  orphaned_at: string
  cause: string
  detail: OrphanDetail | null
  notified_at: string | null
  notify_note: string | null
  age_days: number
  age_seconds: number
  transfer_id: number | null
  nominee_user_id: number | null
  nominee_name: string | null
  nominee_email: string | null
  transfer_created_at: string | null
  transfer_expires_at: string | null
}

export const REASON_LABEL: Record<string, string> = {
  'owner-deactivated': 'Owner deactivated',
  'owner-deleted': 'Owner deleted',
  'owner-removed': 'Owner role removed',
  'no-owner': 'Never had an owner',
}

export function ageText(seconds: number): string {
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`
  return `${Math.floor(seconds / 86400)} d`
}

export const personLabel = (p: PersonRef | null) => (p ? p.name || p.email || `#${p.id}` : 'someone')
