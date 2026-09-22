import { useEffect, useState } from 'react'
import { useEnhancementSubmit } from '../../hooks/useEnhancementSubmit'
import { usePeek, PeekChip, peekToPromptPrefix } from '../../hooks/usePeek'

interface Props {
  slug:    string | null | undefined
  appName: string
  open:    boolean
  onClose: () => void
  width?:  number
  iframeRef?: React.RefObject<HTMLIFrameElement | null>
}

/**
 * Right drawer for "Request" — file an enhancement request against the app
 * currently in the frame. Mounted by the legacy portal (docs/login.html) as
 * <crane-request-panel>; the React SPA uses RequestModal for the same job.
 *
 * Pick-element (🎯) injects a hover/click overlay into the embedded iframe and
 * captures CSS-selector + text context to prepend to the prompt. Same-origin
 * only (AppCrane apps live under the same host).
 *
 * WHAT THIS PANEL NO LONGER DOES, and why (v2.85.0).
 *
 * It used to POST the request, open an EventSource on /api/plan/:id/stream,
 * narrate "Analyzing codebase…", and reveal a Build button once a plan
 * arrived. None of that could happen any more. v2.1.1 removed the plan job
 * POST /api/enhancements used to queue (server/routes/enhancements.js) — a
 * request now lands in triage for a person or an MCP-connected agent to pick
 * up. With no job row ever created, /api/plan/:id/stream answers "Queued —
 * waiting for worker to pick up the job…" on a 2s timer forever
 * (server/routes/plan.js), so the `plan` event never fired, `planReady` never
 * flipped, and the Build button — gated on planReady — could not appear. The
 * refine path was reachable only from that same dead state.
 *
 * So the panel showed a spinner that never resolved and promised code
 * generation that was never coming. It now says what is true: the request is
 * filed, it is tracked work, and a human or an agent picks it up from the
 * queue. Progress lives on the Requests page, not here.
 */
export function RequestPanel({ slug, appName, open, onClose, width = 420, iframeRef }: Props) {
  const [text, setText] = useState('')
  const { submit, busy, last, reset } = useEnhancementSubmit(slug)
  const peek = usePeek(iframeRef ?? { current: null })

  useEffect(() => {
    if (!open) { setText(''); peek.stop(); peek.clear(); reset() }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!open) return null

  async function onSubmit() {
    if (!text.trim() || busy) return
    const prefix = peek.ctx ? peekToPromptPrefix(peek.ctx) : ''
    const r = await submit(prefix + text.trim())
    if (r.ok) { setText(''); peek.clear() }
  }

  return (
    <div className="ask-panel open" style={{ width }}>
      <div className="ask-header">
        <span>💡 Request</span>
        <span className="ask-app-label">{appName}</span>
        <div className="ask-header-right">
          <button
            type="button"
            className={'ask-sessions-btn' + (peek.active ? ' active' : '')}
            onClick={() => peek.toggle()}
            title="Point at an element in the app to add it as context"
          >🎯</button>
          <button type="button" className="ask-close" onClick={onClose}>×</button>
        </div>
      </div>

      <div className="ask-messages">
        {!last && (
          <div className="ask-empty">
            Describe an enhancement or feature you want for this app. It is filed
            as a tracked request for this app's owners — or for an agent
            connected over MCP — to pick up.
          </div>
        )}

        {busy && (
          <div className="ask-msg assistant">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '.82rem' }}>
              <span className="az-spinner" />
              <span>Filing your request…</span>
            </div>
          </div>
        )}

        {last?.ok && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%' }}>
            ✅ Request {last.enhancementId ? `#${last.enhancementId} ` : ''}filed.
            <div style={{ fontSize: '.78rem', color: 'var(--dim)', marginTop: 6, lineHeight: 1.5 }}>
              It is in the queue for this app's owners, who triage it and decide
              what happens next. Nothing is being generated right now.
              {' '}
              <a href="/requests" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
                See it under Requests
              </a>.
            </div>
          </div>
        )}

        {last && !last.ok && last.message && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%', borderColor: '#ef4444' }}>
            ⚠️ {last.message}
          </div>
        )}
      </div>

      <div className="ask-input-area">
        {peek.ctx && <PeekChip ctx={peek.ctx} onClear={peek.clear} />}
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSubmit() }
            }}
            placeholder="Describe the enhancement or feature you want…"
            rows={3}
            disabled={busy}
          />
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={busy || !text.trim()}
            title="File this request for the app's owners to triage"
          >{busy ? '…' : '📤 Submit'}</button>
        </div>
      </div>
    </div>
  )
}
