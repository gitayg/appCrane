import { useEffect, useRef, useState, useCallback } from 'react'
import { adminApi } from '../adminApi'

const POLL_MS = 8000

export interface JobsActiveJob {
  id: number
  app_slug?: string
  phase?: string
  status: 'queued' | 'running' | string
  enhancement_message?: string
}

export interface JobsMyRequest {
  id: number
  app_slug?: string
  message: string
  status: string
  job_id?: number | null
  job_status?: string | null
  phase?: string
}

export interface JobsAppRequest {
  id: number
  app_slug: string
  user_name?: string
  message: string
  status: string
  phase?: string
  latest_job_id?: number | null
}

interface JobsResponse {
  active_jobs?: JobsActiveJob[]
  my_requests?: JobsMyRequest[]
  app_requests?: JobsAppRequest[]
}

export interface JobsList {
  active_jobs:  JobsActiveJob[]
  my_requests:  JobsMyRequest[]
  app_requests: JobsAppRequest[]
  activeCount:  number
  refresh:      () => void
}

/**
 * Mirror of the portal's refreshJobsList/refreshJobsBadge: polls
 * /api/ask/jobs, optionally scoped by app slug, and returns active jobs
 * + the user's own requests + (admin only) app-specific request triage.
 *
 * `polling=false` only fetches the badge count; pass `true` while the
 * panel is open so the in-panel list stays fresh.
 */
export function useJobsList(slug: string | null | undefined, polling: boolean): JobsList {
  const [data, setData] = useState<JobsResponse>({})
  const tickRef = useRef(0)

  const fetchOnce = useCallback(async () => {
    try {
      const url = slug
        ? `/api/ask/jobs?app_slug=${encodeURIComponent(slug)}`
        : '/api/ask/jobs'
      const d = await adminApi.get<JobsResponse>(url)
      setData(d || {})
    } catch {
      // keep last good state
    }
  }, [slug])

  useEffect(() => {
    let alive = true
    fetchOnce()
    const interval = polling ? POLL_MS : 30000 // background trickle for badge
    const t = setInterval(() => { if (alive) { tickRef.current++; fetchOnce() } }, interval)
    return () => { alive = false; clearInterval(t) }
  }, [fetchOnce, polling])

  const activeJobs = data.active_jobs ?? []
  const myReqs    = data.my_requests ?? []
  const myActive  = myReqs.filter(r => r.job_status === 'queued' || r.job_status === 'running').length
  const activeCount = activeJobs.length + myActive

  return {
    active_jobs:  activeJobs,
    my_requests:  myReqs,
    app_requests: data.app_requests ?? [],
    activeCount,
    refresh: fetchOnce,
  }
}
