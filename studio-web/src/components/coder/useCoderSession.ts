import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../../adminApi'
import { sessionStillValid } from '../../sessionExpiry'
import {
  coderApi, isLiveStatus,
  type CoderEvent, type CoderFollowup, type CoderModel, type CoderSession,
  type CoderStatus, type StreamEvent,
} from './api'

export interface Entry {
  key:   string
  kind:  'user' | 'assistant' | 'tool' | 'note' | 'error'
  text:  string
  tool?: string
  /** Which model answered. Shown on assistant bubbles; a transcript where you
   *  cannot tell which model produced a turn is worse than no picker. */
  model?: string | null
}

let seq = 0
const key = () => `e${++seq}`

/**
 * Pull one parsed agent event out of whatever the SSE channel handed us.
 * Replayed rows arrive bare, live ones arrive wrapped in `{type:'stream'}`.
 * Returns null for the control events (status / queue / cost / error).
 */
function asStreamEvent(ev: CoderEvent): StreamEvent | null {
  if (ev.type === 'stream') return ev.event
  if (ev.type === 'text' || ev.type === 'tool' || ev.type === 'result' || ev.type === 'system') {
    return ev as StreamEvent
  }
  return null
}

/** A one-line "what is it doing" label for a tool_use block. */
function toolSummary(name: string, input: unknown): string {
  const i = (input ?? {}) as Record<string, unknown>
  const first = ['file_path', 'path', 'pattern', 'command', 'url', 'prompt']
    .map(k => i[k])
    .find(v => typeof v === 'string' && v) as string | undefined
  if (!first) return name
  return first.length > 120 ? `${first.slice(0, 120)}…` : first
}

/**
 * One coder session for one app: lifecycle, transcript, and the SSE stream.
 *
 * Transcript is kept in two halves on purpose. `history` is what the DB has
 * persisted as user/assistant turns; `live` is everything the event stream
 * produced since this connection opened. A reconnect re-reads history and
 * throws `live` away rather than appending to it — the route replays buffered
 * events on every connect, so appending would duplicate the whole transcript
 * each time the stream blipped. Re-reading also recovers the user turns, which
 * the replay (system rows only) does not carry.
 */
export function useCoderSession(slug: string, open: boolean) {
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [session,   setSession]   = useState<CoderSession | null>(null)
  const [phase,     setPhase]     = useState<'loading' | 'absent' | 'ready' | 'failed'>('loading')
  const [history,   setHistory]   = useState<Entry[]>([])
  const [live,      setLive]      = useState<Entry[]>([])
  const [status,    setStatus]    = useState<CoderStatus>('idle')
  const [queueAhead, setQueueAhead] = useState<number | null>(null)
  const [costCents, setCostCents] = useState(0)
  const [starting,  setStarting]  = useState(false)
  // Set while POST .../resume is in flight. Resume recreates the container and,
  // after an upgrade, REBUILDS the agent image first -- a minute or more -- and
  // with no state for it the Resume button looked exactly like a dead button.
  const [resumingSince, setResumingSince] = useState<number | null>(null)
  const [error,     setError]     = useState<ApiError | Error | null>(null)
  const [startLog,  setStartLog]  = useState<string[]>([])
  const [models,    setModels]    = useState<CoderModel[]>([])
  const [model,     setModel]     = useState<string>('')
  const [followups, setFollowups] = useState<CoderFollowup[]>([])

  const esRef      = useRef<EventSource | null>(null)
  const stoppedRef = useRef(false)
  /** Model of the turn currently streaming, stamped onto its assistant bubble. */
  const turnModel  = useRef<string | null>(null)

  // ── the allowlist the server enforces ─────────────────────────────────
  // Fetched, never hardcoded: a hardcoded list drifts from the validator and
  // the drift shows up as a 400 on send (or as a configured model nobody can
  // pick), not as a build failure.
  useEffect(() => {
    if (!open) return
    let cancelled = false
    coderApi.models()
      .then(r => {
        if (cancelled) return
        setModels(r.models)
        setModel(m => m || r.default)
      })
      .catch(() => { /* picker stays empty; the server still applies its default */ })
    return () => { cancelled = true }
  }, [open])

  // ── discover the app's current session ────────────────────────────────
  useEffect(() => {
    if (!open) return
    let cancelled = false
    setPhase('loading')
    setError(null)
    coderApi.latestSession(slug)
      .then(r => {
        if (cancelled) return
        if (r.session && isLiveStatus(r.session.status)) {
          setSession(r.session)
          setSessionId(r.session.id)
          setStatus(r.session.status)
          setCostCents(r.session.cost_usd_cents || 0)
          setPhase('ready')
        } else {
          setSessionId(null)
          setSession(null)
          setPhase('absent')
        }
      })
      .catch(e => { if (!cancelled) { setError(e as Error); setPhase('failed') } })
    return () => { cancelled = true }
  }, [slug, open])

  // ── stream ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!open || !sessionId) return
    stoppedRef.current = false
    let attempt = 0
    let timer: ReturnType<typeof setTimeout> | null = null

    const apply = (ev: CoderEvent) => {
      if (ev.type === 'status') {
        setStatus(ev.status)
        if (ev.status !== 'queued') setQueueAhead(null)
        if (ev.reason) setLive(p => [...p, { key: key(), kind: 'note', text: ev.reason! }])
        return
      }
      // `ahead: 0` means "at the front", i.e. running — NOT waiting. The queue
      // event fires on every enqueue, including this session's own, and it
      // arrives AFTER the `status: active` that precedes it (builderSession
      // publishes active at dispatch, then subscribeQueue fires). Storing a 0
      // here and letting it outrank the status is why a running turn showed
      // "queued · 0 ahead" for its whole duration. Only a positive number is
      // a queue position worth showing.
      if (ev.type === 'queue') { setQueueAhead(ev.ahead > 0 ? ev.ahead : null); return }
      if (ev.type === 'followups') { setFollowups(ev.items); return }
      if (ev.type === 'turn') { turnModel.current = ev.model; return }
      if (ev.type === 'note') {
        setLive(p => [...p, { key: key(), kind: 'note', text: ev.message }])
        return
      }
      if (ev.type === 'cost')  { setCostCents(c => c + (ev.costUsdCents || 0)); return }
      if (ev.type === 'error') {
        setLive(p => [...p, { key: key(), kind: 'error', text: ev.message }])
        return
      }
      const se = asStreamEvent(ev)
      if (!se) return
      if (se.type === 'result') { setCostCents(c => c + (se.costUsdCents || 0)); return }
      if (se.type === 'system') return          // message_start &c — too noisy to show
      if (se.type === 'tool') {
        setLive(p => [...p, { key: key(), kind: 'tool', tool: se.name, text: toolSummary(se.name, se.input) }])
        return
      }
      // text — append to the assistant bubble in progress, or open a new one.
      setLive(p => {
        const last = p[p.length - 1]
        if (last && last.kind === 'assistant') {
          return [...p.slice(0, -1), { ...last, text: last.text + se.text }]
        }
        return [...p, { key: key(), kind: 'assistant', text: se.text, model: turnModel.current }]
      })
    }

    const connect = async () => {
      if (stoppedRef.current) return
      let watermark = 0
      try {
        const d = await coderApi.session(slug, sessionId)
        if (stoppedRef.current) return
        setSession(d.session)
        setStatus(d.session.status)
        setCostCents(d.session.cost_usd_cents || 0)
        watermark = d.messages.reduce((m, r) => Math.max(m, r.id), 0)
        setHistory(d.messages.map(m => ({
          key: `h${m.id}`,
          kind: m.role === 'user' ? 'user' : 'assistant',
          text: m.content,
          model: m.model,
        })))
        // Survives F5: the pending queue comes back with the transcript, from
        // the DB, on every connect.
        setFollowups(d.followups || [])
      } catch (e) {
        if (!stoppedRef.current) setError(e as Error)
        return
      }
      setLive([])
      const es = new EventSource(coderApi.eventsUrl(slug, sessionId, watermark))
      esRef.current = es
      es.onmessage = (m) => {
        attempt = 0
        let data: CoderEvent
        try { data = JSON.parse(m.data) } catch { return }
        apply(data)
      }
      // An EventSource error carries no status code, so an expired session and
      // a dropped connection look identical. Probe a channel that CAN report
      // one before spending a reconnect on it (salvage/ChatPanel.tsx, v2.73.0).
      es.onerror = () => {
        es.close()
        esRef.current = null
        if (stoppedRef.current) return
        void sessionStillValid().then(ok => {
          if (!ok || stoppedRef.current) { stoppedRef.current = true; return }
          const delay = Math.min(1000 * 2 ** attempt++, 30000)
          timer = setTimeout(() => { void connect() }, delay)
        })
      }
    }

    void connect()
    return () => {
      stoppedRef.current = true
      if (timer) clearTimeout(timer)
      esRef.current?.close()
      esRef.current = null
    }
  }, [slug, sessionId, open])

  // ── actions ───────────────────────────────────────────────────────────

  const start = useCallback(async () => {
    setStarting(true)
    setError(null)
    setStartLog([])
    try {
      const r = await coderApi.startSession(slug)
      setStartLog(r.log || [])
      setHistory([])
      setLive([])
      setSessionId(r.session_id)
      setStatus('idle')
      setPhase('ready')
    } catch (e) {
      setError(e as Error)
    } finally {
      setStarting(false)
    }
  }, [slug])

  /**
   * Send, or queue behind the turn in flight. The BROWSER does not decide
   * which: it posts, and the route answers `queued` when a turn is running.
   * A client-side "am I busy" check would be wrong the moment a second viewer
   * is watching the same session.
   */
  const send = useCallback(async (text: string, chosen?: string) => {
    if (!sessionId || !text.trim()) return
    const wasStreaming = status === 'active' || status === 'queued'
    if (!wasStreaming) {
      setLive(p => [...p, { key: key(), kind: 'user', text }])
      setStatus('active')
    }
    try {
      const r = await coderApi.dispatch(slug, sessionId, text, chosen || model || undefined)
      // The same row arrives TWICE: once as this response, once on the SSE
      // `followups` event the enqueue publishes. The SSE copy is the whole
      // list and usually wins the race, so a blind append renders the newest
      // follow-up twice (observed in the browser — no test that skips React
      // can see it). Merge by id: the chip still appears immediately if the
      // stream is momentarily disconnected, and never doubles when it is not.
      if (r.queued && r.followup) {
        const added = r.followup
        setFollowups(p => (p.some(f => f.id === added.id) ? p : [...p, added]))
      }
    } catch (e) {
      setLive(p => [...p, { key: key(), kind: 'error', text: (e as Error).message }])
      if (!wasStreaming) setStatus('idle')
    }
  }, [slug, sessionId, model, status])

  const cancelFollowup = useCallback(async (id: number) => {
    if (!sessionId) return
    try {
      const r = await coderApi.cancelFollowup(slug, sessionId, id)
      setFollowups(r.followups || [])
    } catch (e) {
      setLive(p => [...p, { key: key(), kind: 'error', text: (e as Error).message }])
    }
  }, [slug, sessionId])

  const stop = useCallback(async () => {
    if (!sessionId) return
    try { await coderApi.stop(slug, sessionId) } catch (e) {
      setLive(p => [...p, { key: key(), kind: 'error', text: (e as Error).message }])
    }
  }, [slug, sessionId])

  const resume = useCallback(async () => {
    if (!sessionId || resumingSince) return
    setError(null)
    setResumingSince(Date.now())
    try {
      // Bounded: the request has no timeout of its own, so a server that
      // stalls would leave the counter running forever. Ten minutes is well
      // past the slowest image rebuild; past it, say so rather than wait on.
      const r = await Promise.race([
        coderApi.resume(slug, sessionId),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error(
          'Resume did not finish within 10 minutes. The container may still be starting on the server — '
          + 'reload in a minute, and if the session is still paused, this is worth reporting.',
        )), 10 * 60 * 1000)),
      ])
      setStartLog(r.log || [])
      setStatus('idle')
    } catch (e) {
      setError(e as Error)
    } finally {
      setResumingSince(null)
    }
  }, [slug, sessionId, resumingSince])

  const streaming = status === 'active' || status === 'queued' || status === 'starting'

  return {
    phase, session, sessionId, status, streaming, queueAhead, costCents,
    entries: [...history, ...live],
    starting, error, startLog, resumingSince,
    models, model, setModel,
    followups, cancelFollowup,
    start, send, stop, resume,
  }
}
