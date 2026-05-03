import { useCallback, useEffect, useRef, useState } from 'react'
import { adminApi, authTokenForSSE } from '../adminApi'

/**
 * Plan-then-Build flow used by the React RequestPanel — mirrors the
 * portal's sendPlanRequest + _streamPlan + buildFromPlan.
 *
 *   submit(message)
 *     → POST /api/enhancements (server creates the request + queues a
 *       'plan' job; for admins it auto-flips mode='auto' so the worker
 *       proceeds to code after plan, but the Build button still works
 *       as a manual confirmation).
 *     → opens an EventSource on /api/plan/:id/stream?token=...
 *     → status / progress / plan / error events drive the working text
 *       and the final plan summary.
 *
 *   build()
 *     → POST /api/plan/:id/build (after the plan event arrives).
 *
 *   reset()  — clears local state (does NOT delete the server-side
 *              enhancement; pick from the Requests list to revisit).
 */
export interface PlanState {
  busy:        boolean
  enhId:       number | null
  working:     { active: boolean; text: string; elapsedSec: number; tokens: number }
  planText:    string
  planReady:   boolean
  error:       string | null
  built:       boolean
  activity:    string[]   // tool-use breadcrumbs streamed during exploration
}

const IDLE: PlanState['working'] = { active: false, text: '', elapsedSec: 0, tokens: 0 }

export function usePlanFlow(slug: string | null | undefined) {
  const [state, setState] = useState<PlanState>({
    busy: false, enhId: null, working: IDLE,
    planText: '', planReady: false, error: null, built: false, activity: [],
  })
  const esRef     = useRef<EventSource | null>(null)
  const tickRef   = useRef<ReturnType<typeof setInterval> | null>(null)
  const startedRef = useRef(0)

  const stopTicker = () => {
    if (tickRef.current) { clearInterval(tickRef.current); tickRef.current = null }
  }
  const closeStream = () => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
  }

  const reset = useCallback(() => {
    closeStream()
    stopTicker()
    setState({ busy: false, enhId: null, working: IDLE, planText: '', planReady: false, error: null, built: false, activity: [] })
  }, [])

  // Reset when slug changes.
  useEffect(() => { reset() }, [slug, reset])

  // Cleanup on unmount.
  useEffect(() => () => { closeStream(); stopTicker() }, [])

  function streamPlan(enhId: number) {
    const token = authTokenForSSE()
    const qs = token ? `?token=${encodeURIComponent(token)}` : ''
    const es = new EventSource(`/api/plan/${enhId}/stream${qs}`)
    esRef.current = es
    es.onmessage = (ev) => {
      let data: any
      try { data = JSON.parse(ev.data) } catch { return }
      if (data.type === 'status' || data.type === 'tokens') {
        setState(s => ({
          ...s,
          working: {
            ...s.working, active: true,
            text: data.text ?? s.working.text,
            tokens: data.count ?? data.tokens ?? s.working.tokens,
          },
        }))
      } else if (data.type === 'progress') {
        setState(s => ({ ...s, planText: String(data.text || ''), working: { ...s.working, active: true } }))
      } else if (data.type === 'activity') {
        const fresh: string[] = Array.isArray(data.lines) ? data.lines : []
        if (fresh.length) {
          setState(s => ({ ...s, activity: [...s.activity, ...fresh].slice(-30) }))
        }
      } else if (data.type === 'plan') {
        const txt = formatPlan(data.plan) || state.planText || '(plan returned no text)'
        es.close(); esRef.current = null
        stopTicker()
        setState(s => ({ ...s, busy: false, planReady: true, planText: txt, working: IDLE }))
      } else if (data.type === 'error') {
        es.close(); esRef.current = null
        stopTicker()
        setState(s => ({ ...s, busy: false, error: String(data.message || 'Plan failed'), working: IDLE }))
      }
    }
    es.onerror = () => {
      // EventSource auto-reconnects on transient errors; only treat as
      // fatal if we never reached planReady. The server's poll closes
      // the stream cleanly on terminal states which also fires onerror —
      // that's why we don't treat onerror itself as failure.
    }
  }

  const submit = useCallback(async (message: string) => {
    if (!slug || !message.trim() || state.busy) return
    closeStream(); stopTicker()
    startedRef.current = Date.now()
    setState({
      busy: true, enhId: null,
      working: { active: true, text: 'Submitting request…', elapsedSec: 0, tokens: 0 },
      planText: '', planReady: false, error: null, built: false, activity: [],
    })
    tickRef.current = setInterval(() => {
      const sec = Math.round((Date.now() - startedRef.current) / 1000)
      setState(s => s.working.active ? { ...s, working: { ...s.working, elapsedSec: sec } } : s)
    }, 1000)
    try {
      const r = await adminApi.post<{ enhancement_id?: number; error?: { message?: string } }>(
        '/api/enhancements', { message: message.trim(), app_slug: slug },
      )
      if (r.error) throw new Error(r.error.message || 'Submission failed')
      const enhId = r.enhancement_id
      if (!enhId) throw new Error('Server did not return an enhancement_id')
      setState(s => ({ ...s, enhId, working: { ...s.working, text: 'Generating plan…' } }))
      streamPlan(enhId)
    } catch (err) {
      stopTicker()
      setState(s => ({ ...s, busy: false, error: err instanceof Error ? err.message : String(err), working: IDLE }))
    }
  }, [slug, state.busy])

  const build = useCallback(async () => {
    if (!state.enhId || state.built) return
    setState(s => ({ ...s, built: true, working: { active: true, text: 'Queuing build…', elapsedSec: 0, tokens: 0 } }))
    try {
      const r = await adminApi.post<{ error?: { message?: string } }>(`/api/plan/${state.enhId}/build`, {})
      if (r.error) throw new Error(r.error.message || 'Build failed')
      setState(s => ({ ...s, working: IDLE }))
    } catch (err) {
      setState(s => ({ ...s, built: false, error: err instanceof Error ? err.message : String(err), working: IDLE }))
    }
  }, [state.enhId, state.built])

  // Send refinement feedback against the current enhId — server queues a
  // 'revise_plan' job; we re-open the SSE so the new plan streams in
  // place of the old one. Mirrors portal's sendPlanRequest refine branch.
  const refine = useCallback(async (comment: string) => {
    if (!state.enhId || !comment.trim() || state.busy) return
    closeStream(); stopTicker()
    startedRef.current = Date.now()
    setState(s => ({
      ...s,
      busy: true,
      planReady: false,
      built: false,
      planText: '',
      activity: [],
      error: null,
      working: { active: true, text: 'Re-planning…', elapsedSec: 0, tokens: 0 },
    }))
    tickRef.current = setInterval(() => {
      const sec = Math.round((Date.now() - startedRef.current) / 1000)
      setState(s => s.working.active ? { ...s, working: { ...s.working, elapsedSec: sec } } : s)
    }, 1000)
    try {
      const r = await adminApi.post<{ error?: { message?: string } }>(
        `/api/plan/${state.enhId}/feedback`, { comment: comment.trim() },
      )
      if (r.error) throw new Error(r.error.message || 'Feedback failed')
      streamPlan(state.enhId)
    } catch (err) {
      stopTicker()
      setState(s => ({ ...s, busy: false, error: err instanceof Error ? err.message : String(err), working: IDLE }))
    }
  }, [state.enhId, state.busy])

  return { state, submit, build, refine, reset }
}

function formatPlan(plan: any): string {
  if (!plan) return ''
  if (typeof plan === 'string') return plan
  if (typeof plan === 'object') {
    if (typeof plan.text === 'string') return plan.text
    if (typeof plan.plan === 'string') return plan.plan
    return JSON.stringify(plan, null, 2)
  }
  return String(plan)
}
