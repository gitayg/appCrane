import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

const POLL_MS = 5000

/**
 * Mirrors the portal's startAskContainerPoll: hits /api/ask/active/:slug
 * every 5s and reports whether ANY container (Ask or AppStudio code job)
 * is live for this app. Drives the green "Builder Working" badge.
 */
export function useBuilderActive(slug: string | null | undefined): boolean {
  const [active, setActive] = useState(false)

  useEffect(() => {
    if (!slug) { setActive(false); return }
    let alive = true

    async function poll() {
      try {
        const data = await adminApi.get<{ active?: boolean }>(`/api/ask/active/${encodeURIComponent(slug!)}`)
        if (alive) setActive(!!data?.active)
      } catch {
        if (alive) setActive(false)
      }
    }

    poll()
    const t = setInterval(poll, POLL_MS)
    return () => { alive = false; clearInterval(t) }
  }, [slug])

  return active
}
