import { adminApi } from '../../adminApi'
import type { EnvName } from './types'

export interface ReleaseMetrics {
  requests: number
  active_users: number
  restarts: number
  requests_per_day: number | null
  active_users_per_day: number | null
  restarts_per_day: number | null
  error_rate: number | null
  p95_ms: number | null
  coverage: 'full' | 'partial' | 'none'
}

export interface Release {
  id: number
  env: EnvName
  version: string | null
  label: string | null
  status: 'live' | 'replaced' | 'rolled back' | 'auto-reverted' | 'failed' | 'in progress'
  raw_status: string
  kind: 'deploy' | 'rollback' | 'promote'
  rollback_of: number | null
  promoted_from: number | null
  promoted_to: number[]
  whats_new: string | null
  commit: string | null
  deployed_by: { id: number; name: string; kind: 'person' | 'agent' } | null
  approver: null
  started_at: string
  finished_at: string | null
  failure_reason: string | null
  live_from: string | null
  live_until: string | null
  live_ms: number | null
  metrics: ReleaseMetrics | null
}

export interface ReleaseLog {
  releases: Release[]
  labels: string[]
  unavailable: { error_rate: string; p95_ms: string }
}

export const LABEL_RE = /^[A-Za-z0-9._=-]{1,40}$/

function query(env?: EnvName | '', label?: string, extra?: Record<string, string>) {
  const q = new URLSearchParams()
  if (env) q.set('env', env)
  if (label) q.set('label', label)
  for (const [k, v] of Object.entries(extra || {})) q.set(k, v)
  const s = q.toString()
  return s ? `?${s}` : ''
}

export const loadReleases = (slug: string, label?: string) =>
  adminApi.get<ReleaseLog>(`/api/apps/${encodeURIComponent(slug)}/releases${query('', label)}`)

export const setReleaseLabel = (slug: string, id: number, label: string | null) =>
  adminApi.put<{ id: number; label: string | null }>(`/api/apps/${encodeURIComponent(slug)}/releases/${id}/label`, { label })

export async function downloadReleasesCsv(slug: string, label?: string) {
  const r = await fetch(`/api/apps/${encodeURIComponent(slug)}/releases${query('', label, { format: 'csv' })}`, { headers: adminApi.authHeaders() })
  if (!r.ok) throw new Error(`CSV export failed (HTTP ${r.status})`)
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `${slug}-releases${label ? `-${label}` : ''}.csv`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
