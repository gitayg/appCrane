export type TaskStatus = 'open' | 'in_progress' | 'done' | 'declined'

export interface TaskUser { id: number; name: string; email: string | null }

export interface TaskSummary {
  id: string
  app: { slug: string; name: string } | null
  subject: string
  status: TaskStatus
  requester: TaskUser | null
  assignee: TaskUser | null
  due_date: string | null
  external_ref: string | null
  url: string | null
  created_at: string
  updated_at: string
  last_activity_at: string
  my_roles?: { requester: boolean; assignee: boolean }
  unread?: boolean
}

export interface TaskComment {
  id: number
  author: TaskUser | null
  via: 'app' | 'dashboard'
  body: string
  created_at: string
}

export interface TaskHistoryEntry {
  kind: 'created' | 'status'
  from_status: TaskStatus | null
  to_status: TaskStatus | null
  actor: TaskUser | null
  via: 'app' | 'dashboard'
  created_at: string
}

export interface TaskDetail extends TaskSummary {
  body: string
  comments: TaskComment[]
  history: TaskHistoryEntry[]
  allowed_statuses: TaskStatus[]
  can_delete: boolean
}

export const STATUS_LABEL: Record<TaskStatus, string> = {
  open: 'Open', in_progress: 'In progress', done: 'Done', declined: 'Declined',
}

export const STATUS_STYLE: Record<TaskStatus, { fg: string; bg: string; border: string }> = {
  open: { fg: '#f97316', bg: 'rgba(249,115,22,.15)', border: 'rgba(249,115,22,.4)' },
  in_progress: { fg: '#3b82f6', bg: 'rgba(59,130,246,.15)', border: 'rgba(59,130,246,.4)' },
  done: { fg: '#22c55e', bg: 'rgba(34,197,94,.15)', border: 'rgba(34,197,94,.4)' },
  declined: { fg: '#a1a1aa', bg: 'var(--surface2)', border: 'var(--border)' },
}

export function fmtWhen(s: string | null | undefined, withTime = false): string {
  if (!s) return '-'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  return withTime
    ? d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function userLabel(u: TaskUser | null, appName?: string): string {
  if (!u) return appName || 'The app'
  return u.name
}

/** Only http(s) links are rendered as links; anything else shows as text. */
export function safeHref(url: string | null): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null
  } catch {
    return null
  }
}
