import { useCallback, useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'

export interface AskMessage {
  role: 'user' | 'assistant'
  content: string
}

export interface AskWorkingState {
  active: boolean
  text: string
  elapsedSec: number
  tokens: number
}

export interface AskSession {
  messages: AskMessage[]
  working: AskWorkingState
  busy: boolean
  send: (question: string) => void
  reset: () => void
}

const IDLE_WORKING: AskWorkingState = { active: false, text: '', elapsedSec: 0, tokens: 0 }

/**
 * Mirror of the portal's sendAskQuestion + EventSource flow:
 *  1. POST /api/ask/:slug → { session_id, job_id }
 *  2. Open EventSource at /api/ask/stream/:job_id (no auth — jobId is secret)
 *  3. Pipe log/tokens/done/error events into local state
 *
 * Holds the conversation in component memory (same per-open lifetime as
 * the portal), and reuses session_id across turns so the agent has
 * continuity. `reset()` clears the local thread (does NOT delete the
 * server-side session — pick from history if you need that).
 */
export function useAskSession(slug: string | null | undefined): AskSession {
  const [messages, setMessages] = useState<AskMessage[]>([])
  const [working,  setWorking]  = useState<AskWorkingState>(IDLE_WORKING)
  const [busy,     setBusy]     = useState(false)

  const sessionIdRef = useRef<number | null>(null)
  const esRef        = useRef<EventSource | null>(null)
  const startedRef   = useRef<number>(0)
  const tickRef      = useRef<ReturnType<typeof setInterval> | null>(null)
  const tokensRef    = useRef<number>(0)

  // Reset local state when slug changes
  useEffect(() => {
    sessionIdRef.current = null
    setMessages([])
    setWorking(IDLE_WORKING)
    setBusy(false)
    return () => {
      if (esRef.current)   { esRef.current.close(); esRef.current = null }
      if (tickRef.current) { clearInterval(tickRef.current); tickRef.current = null }
    }
  }, [slug])

  const stopTicker = () => {
    if (tickRef.current) { clearInterval(tickRef.current); tickRef.current = null }
  }

  const reset = useCallback(() => {
    sessionIdRef.current = null
    setMessages([])
    setWorking(IDLE_WORKING)
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    stopTicker()
    setBusy(false)
  }, [])

  const send = useCallback((question: string) => {
    const trimmed = question.trim()
    if (!trimmed || !slug || busy) return

    setMessages(m => [...m, { role: 'user', content: trimmed }])
    setBusy(true)
    startedRef.current = Date.now()
    tokensRef.current = 0
    setWorking({ active: true, text: 'Spinning up container…', elapsedSec: 0, tokens: 0 })

    if (tickRef.current) clearInterval(tickRef.current)
    tickRef.current = setInterval(() => {
      const sec = Math.round((Date.now() - startedRef.current) / 1000)
      setWorking(w => w.active ? { ...w, elapsedSec: sec, tokens: tokensRef.current } : w)
    }, 1000)

    ;(async () => {
      try {
        const body: { question: string; session_id?: number } = { question: trimmed }
        if (sessionIdRef.current) body.session_id = sessionIdRef.current
        const d = await adminApi.post<{ session_id: number; job_id: number }>(
          `/api/ask/${encodeURIComponent(slug)}`,
          body,
        )
        sessionIdRef.current = d.session_id

        // EventSource — server endpoint has no auth (jobId is the secret)
        const es = new EventSource(`/api/ask/stream/${d.job_id}`)
        esRef.current = es
        let errCount = 0

        es.onmessage = (ev) => {
          errCount = 0
          let data: { type: string; text?: string; count?: number; answer?: string; message?: string }
          try { data = JSON.parse(ev.data) } catch { return }

          if (data.type === 'log') {
            const t = (data.text || '').replace(/^\[ask\]\s*/, '').replace(/^\[stderr\]\s*/, '')
            setWorking(w => w.active ? { ...w, text: t } : w)
          } else if (data.type === 'tokens') {
            tokensRef.current = data.count || 0
            setWorking(w => w.active ? { ...w, tokens: tokensRef.current } : w)
          } else if (data.type === 'done') {
            es.close(); esRef.current = null
            stopTicker()
            setWorking(IDLE_WORKING)
            setMessages(m => [...m, { role: 'assistant', content: data.answer || '(no response)' }])
            setBusy(false)
          } else if (data.type === 'error') {
            es.close(); esRef.current = null
            stopTicker()
            setWorking(IDLE_WORKING)
            setMessages(m => [...m, { role: 'assistant', content: '⚠️ ' + (data.message || 'error') }])
            setBusy(false)
          }
        }

        es.onerror = () => {
          errCount++
          if (errCount <= 5) {
            // Cold-start retry — EventSource auto-reconnects
            setWorking(w => w.active ? { ...w, text: 'Starting session…' } : w)
            return
          }
          es.close(); esRef.current = null
          stopTicker()
          setWorking(IDLE_WORKING)
          setMessages(m => [...m, { role: 'assistant', content: '⚠️ Could not connect. Please try again.' }])
          setBusy(false)
        }
      } catch (err) {
        stopTicker()
        setWorking(IDLE_WORKING)
        const msg = err instanceof Error ? err.message : 'Request failed'
        setMessages(m => [...m, { role: 'assistant', content: '⚠️ ' + msg }])
        setBusy(false)
      }
    })()
  }, [slug, busy])

  return { messages, working, busy, send, reset }
}
