import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

const PING_MS = 15000

export interface Viewer {
  user_id?: number
  name: string
}

/**
 * Mirrors the portal's startPresence/pingPresence: POSTs the slug to
 * /api/presence/ping every 15s and returns the OTHER viewers currently
 * watching the same app. The server uses the caller's auth to identify
 * "self" and excludes them from `viewers`.
 */
export function usePresence(slug: string | null | undefined): Viewer[] {
  const [viewers, setViewers] = useState<Viewer[]>([])

  useEffect(() => {
    if (!slug) { setViewers([]); return }
    let alive = true

    async function ping() {
      try {
        const data = await adminApi.post<{ viewers?: Viewer[] }>(
          '/api/presence/ping',
          { slug },
        )
        if (alive) setViewers(data?.viewers || [])
      } catch {
        // network blip — keep last known viewers, don't blank
      }
    }

    ping()
    const t = setInterval(ping, PING_MS)
    return () => { alive = false; clearInterval(t); setViewers([]) }
  }, [slug])

  return viewers
}
