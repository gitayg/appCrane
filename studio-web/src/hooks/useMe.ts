import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

export interface Me {
  user: { role: string; name?: string; id?: number }
  apps?: Array<{ slug: string; name: string }>
}

let cached: Me | null = null
let inflight: Promise<Me> | null = null

function hasAnyAuthToken(): boolean {
  if (typeof localStorage === 'undefined') return false
  return !!(localStorage.getItem('cc_api_key') || localStorage.getItem('cc_identity_token'))
}

/**
 * Lightweight wrapper around GET /api/auth/me with module-level cache so
 * multiple components that need the current user's role don't refetch.
 *
 * Skips the fetch entirely when no auth token is present (admin key OR
 * portal Bearer) — avoids the harmless-but-noisy 401 the React panels
 * used to log when mounted in /portal before the user signed in. The
 * panels degrade gracefully to "not admin" defaults.
 */
export function useMe(): Me | null {
  const [me, setMe] = useState<Me | null>(cached)

  useEffect(() => {
    if (cached) { setMe(cached); return }
    if (!hasAnyAuthToken()) return
    if (!inflight) {
      inflight = adminApi.get<Me>('/api/auth/me')
        .then(m => { cached = m; return m })
        .catch(() => { inflight = null; throw new Error('me fetch failed') })
    }
    let alive = true
    inflight.then(m => { if (alive) setMe(m) }).catch(() => {})
    return () => { alive = false }
  }, [])

  return me
}

export function isAdmin(me: Me | null): boolean {
  return me?.user?.role === 'admin'
}
