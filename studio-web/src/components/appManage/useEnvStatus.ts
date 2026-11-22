import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { EnvName } from './types'

export interface Deployment {
  id: number
  status: string
  version?: string
  commit_hash?: string
  commit_message?: string
  started_at?: string
  finished_at?: string
  deployed_by_name?: string
  release_label?: string | null
  log?: string
}
export interface SleepEnv { state: string; reason?: string | null; slept_at?: string | null; last_request_at?: string | null; not_eligible?: string[] }
export interface RuntimeEnv { desired: string; source?: string; applied: string | null; drift?: boolean; notice?: string }
export interface Updates { latest_sha?: string; latest_message?: string; production?: { update_available?: boolean }; sandbox?: { update_available?: boolean }; error?: { message?: string } }

export interface EnvStatus {
  latest: Partial<Record<EnvName, Deployment | null>>
  sleep: Partial<Record<EnvName, SleepEnv>> | null
  runtime: { runtime?: string; envs?: Partial<Record<EnvName, RuntimeEnv>> } | null
  storage: Record<EnvName, number> | null | 'error'
  updates: Updates | null
}

/** Per-environment facts the Overview and other tabs show side by side. */
export function useEnvStatus(slug: string, reload: number): EnvStatus {
  const [s, set] = useState<EnvStatus>({ latest: {}, sleep: null, runtime: null, storage: null, updates: null })
  useEffect(() => {
    let off = false
    const merge = (p: Partial<EnvStatus>) => { if (!off) set(prev => ({ ...prev, ...p, latest: { ...prev.latest, ...(p.latest || {}) } })) }
    for (const env of ['production', 'sandbox'] as EnvName[]) {
      adminApi.get<{ deployments?: Deployment[] }>(`/api/apps/${slug}/deployments/${env}`)
        .then(d => merge({ latest: { [env]: d.deployments?.[0] ?? null } }))
        .catch(() => merge({ latest: { [env]: null } }))
    }
    adminApi.get<{ envs: Record<EnvName, SleepEnv> }>(`/api/apps/${slug}/sleep`).then(r => merge({ sleep: r.envs })).catch(() => {})
    adminApi.get<EnvStatus['runtime']>(`/api/apps/${slug}/runtime`).then(r => merge({ runtime: r })).catch(() => {})
    adminApi.get<{ storage: Record<EnvName, number> }>(`/api/apps/${slug}/storage`).then(r => merge({ storage: r.storage })).catch(() => merge({ storage: 'error' }))
    adminApi.get<Updates>(`/api/apps/${slug}/updates`).then(r => merge({ updates: r })).catch(() => {})
    return () => { off = true }
  }, [slug, reload])
  return s
}
