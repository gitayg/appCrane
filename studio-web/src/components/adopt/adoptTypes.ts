import { ApiError, authHeaders } from '../../adminApi'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ReportItem {
  id: string
  level: 'ok' | 'change' | 'decision' | 'risk'
  title: string
  detail: string
  request: boolean
  blocking: boolean
  severity?: Severity
  preview?: string
  side?: string
}

export interface EnvVar {
  key: string
  scope: 'client' | 'server'
  build_time: boolean
  sources: string[]
  in_template: boolean
  value_in_upload: boolean
  hint: string | null
}

export interface AdoptReport {
  verdict: 'ready' | 'works_with_changes' | 'needs_changes' | 'critical_risks'
  project: {
    framework: string
    label: string
    kind: string | null
    build: string | null
    start: string | null
    package_manager: string | null
    origin: { tool: string; label: string; confidence: string; evidence: string[] }
  }
  works: ReportItem[]
  changes: ReportItem[]
  risks: ReportItem[]
  risk_counts: Record<Severity, number>
  env: EnvVar[]
  supabase_edge_env: string[]
  scaffold: { path: string; why: string }[]
  skipped: { path: string; reason: string }[]
  file_count: number
}

export interface Analysis {
  id: string
  source: { kind: 'github' | 'zip'; label: string }
  suggested: { name: string; slug: string }
  report: AdoptReport
}

export interface AdoptResult {
  app: { id: number; slug: string; name: string }
  sandbox_url: string
  commit: string | null
  files_committed: number
  env_files_left_out: string[]
  scaffold: string[]
  env_keys_set: string[]
  deployments: { env: string; deployment_id: number }[]
  intake: { submitted: boolean; skipped?: boolean; reason?: string }
  requests: { id: number; title: string }[]
}

export interface SourceGuide { tool: string; label: string; steps: string }

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#94a3b8', info: '#60a5fa',
}

export const VERDICT_TEXT: Record<AdoptReport['verdict'], string> = {
  ready: 'Ready to adopt as is',
  works_with_changes: 'Works, with changes recommended',
  needs_changes: 'Needs changes before the sandbox deploy can pass',
  critical_risks: 'Critical risks found',
}

/** Multipart upload; adminApi's helpers send JSON only. */
export async function uploadZip(file: File): Promise<Analysis> {
  const form = new FormData()
  form.append('file', file, file.name)
  const r = await fetch('/api/adopt/analyze', { method: 'POST', headers: authHeaders(), body: form })
  const body = await r.json().catch(() => ({}))
  if (!r.ok) {
    const err = (body as { error?: { message?: string; code?: string } }).error
    throw new ApiError(err?.message || `HTTP ${r.status}`, r.status, err?.code || 'HTTP_ERROR', err || {})
  }
  return body as Analysis
}
