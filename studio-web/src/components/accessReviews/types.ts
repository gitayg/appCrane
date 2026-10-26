import { authHeaders } from '../../adminApi'

export type Decision = 'keep' | 'remove' | 'change'

export interface ReviewItem {
  id: number
  user_id: number
  user_name: string | null
  user_email: string | null
  role: string
  granted_via: 'direct' | 'scim'
  last_access_at: string | null
  decision: Decision | null
  new_role: string | null
  note: string | null
  decided_by: number | null
  decided_by_name: string | null
  decided_at: string | null
  scim_managed: boolean
  scim_message: string | null
}

export interface Review {
  id: number
  kind: 'app' | 'platform'
  app_id: number | null
  app_slug: string | null
  app_name: string | null
  data_classification: string | null
  status: 'pending' | 'completed'
  completed_at: string | null
  campaign: { id: number; name: string; status: 'open' | 'closed'; started_at: string; due_at: string }
  can_decide: boolean
  reviewers: { user_id: number; name: string | null }[]
  items: ReviewItem[]
}

export interface Campaign {
  id: number
  name: string
  scope: string
  status: 'open' | 'closed'
  started_at: string
  due_at: string
  grace_until: string
  closed_at: string | null
  overdue_action: 'none' | 'report'
  escalated_at: string | null
  reviews: number
  reviews_completed: number
  items: number
  decided: number
  removed: number
  changed: number
}

export interface Policy {
  enabled: boolean
  cadence_days: number
  due_days: number
  reminder_days: number
  grace_days: number
  overdue_action: 'none' | 'report'
  by_classification: Record<string, number>
}

/** Download an authenticated export as a file. */
export async function downloadExport(path: string, fallbackName: string) {
  const r = await fetch(path, { headers: authHeaders() })
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(body?.error?.message || `HTTP ${r.status}`)
  }
  const name = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '')?.[1] || fallbackName
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
