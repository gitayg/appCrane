import { ApiError } from '../adminApi'

export interface InflightDeploy {
  id: number
  app_id: number
  app_slug: string | null
  app_name: string | null
  env: string
  status: string
  started_at: string | null
  age_seconds: number | null
  stale: boolean
}

export interface BuildsInFlight {
  inFlight: InflightDeploy[]
  stale: InflightDeploy[]
  staleAfterMinutes: number | null
}

/** The deployments a BUILDS_IN_FLIGHT refusal is waiting on, or null for any other error. */
export function buildsInFlightOf(err: unknown): BuildsInFlight | null {
  if (!(err instanceof ApiError) || err.code !== 'BUILDS_IN_FLIGHT') return null
  const d = err.details as { in_flight?: InflightDeploy[]; stale?: InflightDeploy[]; stale_after_minutes?: number }
  return {
    inFlight: Array.isArray(d.in_flight) ? d.in_flight : [],
    stale: Array.isArray(d.stale) ? d.stale : [],
    staleAfterMinutes: typeof d.stale_after_minutes === 'number' ? d.stale_after_minutes : null,
  }
}

/**
 * True when the update request died in transit rather than being refused.
 *
 * The request runs git fetch, npm install and a SPA rebuild before answering,
 * then the process exits. A dropped socket (fetch TypeError) or the proxy's
 * 502/503/504 while the upstream is gone are what a working update looks like
 * from the browser — not a failure to alert about.
 */
export function isConnectionDrop(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 502 || err.status === 503 || err.status === 504
  return err instanceof TypeError
}

export function formatAge(seconds: number | null): string {
  if (seconds == null || seconds < 0) return 'unknown'
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  return `${h} h ${m % 60} min`
}

/**
 * Poll /api/info until it reports a version other than `fromVersion`.
 * Resolves with the new version, or null after `timeoutMs`. Errors while the
 * server is down are the expected state, so they only mean "try again".
 */
export async function waitForNewVersion(fromVersion: string, timeoutMs = 15 * 60_000, intervalMs = 3000): Promise<string | null> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, intervalMs))
    try {
      const r = await fetch('/api/info', { cache: 'no-store' })
      if (r.ok) {
        const d = await r.json() as { version?: string }
        if (d?.version && d.version !== fromVersion) return d.version
      }
    } catch { /* server restarting */ }
  }
  return null
}
