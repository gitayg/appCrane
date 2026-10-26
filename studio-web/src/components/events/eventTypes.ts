import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

export type Severity = 'info' | 'warning' | 'critical'

export interface AppEvent {
  id: number
  ts: string
  kind: string
  severity: Severity
  app_id: number | null
  app_slug: string | null
  user_id: number | null
  user_name: string | null
  subject_user_id: number | null
  subject_user_name: string | null
  summary: string
  ref_table: string | null
  ref_id: number | null
  data: Record<string, unknown> | null
}

export interface EventPage {
  events: AppEvent[]
  next_cursor: number | null
}

export interface EventFilters {
  kind?: string
  severity?: string
  app?: string
  user?: string
  from?: string
  to?: string
  q?: string
}

export const SEVERITIES: Severity[] = ['info', 'warning', 'critical']

export const KIND_GROUPS = [
  'audit', 'deploy', 'scan', 'client_error', 'job', 'host', 'memory', 'secret', 'login', 'request', 'task', 'survey', 'coder',
]

export function eventQuery(filters: EventFilters, before?: number | null, limit = 50): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (!v) continue
    if (k === 'from' || k === 'to') {
      const d = new Date(v)
      if (!Number.isNaN(d.getTime())) p.set(k, d.toISOString())
    } else {
      p.set(k, v)
    }
  }
  if (before) p.set('before', String(before))
  p.set('limit', String(limit))
  return p.toString()
}

export function fetchEvents(base: string, filters: EventFilters, before?: number | null, limit = 50) {
  return adminApi.get<EventPage>(`${base}?${eventQuery(filters, before, limit)}`)
}

export function fetchRelated(id: number) {
  return adminApi.get<{ event: AppEvent; related: AppEvent[] }>(`/api/events/${id}/related`)
}

export function eventTime(e: AppEvent): string {
  return serverDate(e.ts).toLocaleString()
}

export function actorLabel(e: AppEvent): string {
  if (e.user_name) return e.user_name
  if (e.user_id) return `user #${e.user_id}`
  return 'AppCrane'
}
