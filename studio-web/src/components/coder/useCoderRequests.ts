import { useCallback, useEffect, useState } from 'react'
import { coderApi, type CoderRequest } from './api'
import { MAX_CODER_BATCH } from './SendToCoderBar'

export function isOpenRequest(r: CoderRequest) {
  return r.bucket === 'triage' || r.bucket === 'in_progress'
}

/**
 * The open requests a message names as `#id`, in the order they first appear,
 * at most MAX_CODER_BATCH. Only ids in `openIds` count, so "step #2" in a
 * message is plain text unless this app has an open request #2 — and the
 * composer shows which ones will go along before the user sends.
 */
export function referencedRequestIds(text: string, openIds: Set<number>): number[] {
  const out: number[] = []
  for (const m of text.matchAll(/(?:^|[^\w#])#(\d{1,9})\b/g)) {
    const id = Number(m[1])
    if (openIds.has(id) && !out.includes(id)) out.push(id)
  }
  return out.slice(0, MAX_CODER_BATCH)
}

/** This app's requests for the coder panel, loaded while the panel is open. */
export function useCoderRequests(slug: string, enabled: boolean) {
  const [requests, setRequests] = useState<CoderRequest[] | null>(null)
  const [showClosed, setShowClosed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    setError(null)
    coderApi.requests(slug, showClosed)
      .then(r => { if (!cancelled) setRequests(r.requests) })
      .catch(e => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)) })
    return () => { cancelled = true }
  }, [slug, enabled, showClosed, tick])

  const reload = useCallback(() => setTick(t => t + 1), [])
  const openIds = new Set((requests || []).filter(isOpenRequest).map(r => r.id))

  return { requests, openIds, showClosed, setShowClosed, error, reload }
}
