import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { deriveEnvStatus, type EnvHealthResponse, type EnvStatus } from './envStatus'

const POLL_BLOCKED_MS = 5_000
const POLL_UP_MS = 30_000

/**
 * The env's health, read before the viewer mounts the app and polled while it
 * shows it: every 5 s while the env is down, every 30 s while it is up, and
 * not at all while the tab is hidden. A health read that fails (no access, a
 * network blip) never hides the app: it reports 'unknown'.
 */
export function useEnvHealth(slug: string | undefined, env: string | undefined, enabled: boolean, nonce = 0): EnvStatus {
  const [status, setStatus] = useState<EnvStatus>({ phase: 'checking', block: false, reason: null, nextCheckSec: null })

  useEffect(() => {
    setStatus({ phase: 'checking', block: false, reason: null, nextCheckSec: null })
  }, [slug, env])

  useEffect(() => {
    if (!slug || !env || !enabled) return
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const tick = () => {
      adminApi.get<EnvHealthResponse>(`/api/apps/${encodeURIComponent(slug)}/health/${encodeURIComponent(env)}`)
        .then(h => deriveEnvStatus(h))
        .catch(() => deriveEnvStatus(null))
        .then(s => {
          if (!alive) return
          setStatus(s)
          timer = setTimeout(tick, s.block ? POLL_BLOCKED_MS : POLL_UP_MS)
        })
    }
    tick()
    return () => { alive = false; if (timer) clearTimeout(timer) }
  }, [slug, env, enabled, nonce])

  return status
}
