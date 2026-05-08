import { useEffect, useRef, useState } from 'react'
import { useMe, isAdmin } from '../../hooks/useMe'
import { usePlanFlow } from '../../hooks/usePlanFlow'
import { type PeekCtx, peekToPromptPrefix } from '../../hooks/usePeek'

interface Props {
  slug:    string | null | undefined
  appName: string
  /** The picked element ctx — drives initial position + prompt prefix. */
  peekCtx: PeekCtx
  /** Close + drop the picked ctx. */
  onClose: () => void
}

const MODAL_W = 380
const MODAL_H_MIN = 280
const GUTTER = 12

/**
 * Compute the modal's initial top-left so it doesn't overlap the picked
 * element. Prefer "to the right of the element"; fall back to "below";
 * fall back to "viewport center" if neither fits the viewport.
 */
function initialPosition(rect: PeekCtx['rect']): { left: number; top: number } {
  const vw = window.innerWidth
  const vh = window.innerHeight
  if (!rect) {
    return { left: Math.max(GUTTER, (vw - MODAL_W) / 2), top: Math.max(GUTTER, (vh - MODAL_H_MIN) / 2) }
  }
  // Try right of element
  if (rect.left + rect.width + GUTTER + MODAL_W < vw) {
    return { left: rect.left + rect.width + GUTTER, top: Math.max(GUTTER, Math.min(rect.top, vh - MODAL_H_MIN - GUTTER)) }
  }
  // Try below
  if (rect.top + rect.height + GUTTER + MODAL_H_MIN < vh) {
    return { left: Math.max(GUTTER, Math.min(rect.left, vw - MODAL_W - GUTTER)), top: rect.top + rect.height + GUTTER }
  }
  // Try left
  if (rect.left - MODAL_W - GUTTER > 0) {
    return { left: rect.left - MODAL_W - GUTTER, top: Math.max(GUTTER, Math.min(rect.top, vh - MODAL_H_MIN - GUTTER)) }
  }
  // Center fallback
  return { left: Math.max(GUTTER, (vw - MODAL_W) / 2), top: Math.max(GUTTER, (vh - MODAL_H_MIN) / 2) }
}

/**
 * Floating draggable Request modal — replacement for the side-drawer
 * RequestPanel inside /applications' embedded frame view.
 *
 * Flow:
 *   1. User clicks the topbar Request button.
 *   2. Pick mode activates immediately (no drawer opens first).
 *   3. User clicks an element in the iframe.
 *   4. usePeek captures element + click coords; parent passes peekCtx to
 *      this modal which mounts at a position that doesn't cover the pick.
 *   5. User types the request, submits — same plan/refine/build flow as
 *      the original RequestPanel.
 *
 * The modal itself is fully self-contained: drag the header to move,
 * Esc or × to close.
 */
export function RequestModal({ slug, appName, peekCtx, onClose }: Props) {
  const me = useMe()
  const canBuild = isAdmin(me)
  const [text, setText] = useState('')
  const plan = usePlanFlow(slug)

  const [pos, setPos]       = useState(() => initialPosition(peekCtx.rect))
  const dragRef = useRef<{ startX: number; startY: number; left: number; top: number } | null>(null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  function onHeaderDown(e: React.MouseEvent) {
    if ((e.target as HTMLElement).tagName === 'BUTTON') return
    e.preventDefault()
    dragRef.current = { startX: e.clientX, startY: e.clientY, left: pos.left, top: pos.top }
    function onMove(ev: MouseEvent) {
      const d = dragRef.current
      if (!d) return
      const left = Math.max(0, Math.min(window.innerWidth  - MODAL_W,    d.left + ev.clientX - d.startX))
      const top  = Math.max(0, Math.min(window.innerHeight - MODAL_H_MIN, d.top  + ev.clientY - d.startY))
      setPos({ left, top })
    }
    function onUp() {
      dragRef.current = null
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup',   onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup',   onUp)
  }

  function onSubmit() {
    if (!text.trim() || plan.state.busy) return
    const prefix = peekCtx ? peekToPromptPrefix(peekCtx) : ''
    if (plan.state.planReady && !plan.state.built) {
      plan.refine(prefix + text.trim())
    } else {
      plan.submit(prefix + text.trim())
    }
    setText('')
  }

  const w = plan.state.working
  const elementLabel = (peekCtx.tag ? `<${peekCtx.tag}>` : '') +
    (peekCtx.text ? ` "${peekCtx.text.slice(0, 50)}"` : peekCtx.id ? ` #${peekCtx.id}` : '')

  return (
    <div
      className="request-modal"
      style={{ left: pos.left, top: pos.top, width: MODAL_W }}
      role="dialog"
      aria-label="Request enhancement"
    >
      <div className="request-modal-header" onMouseDown={onHeaderDown}>
        <span className="request-modal-title">💡 Request</span>
        <span className="request-modal-app" title={appName}>{appName}</span>
        <button type="button" className="request-modal-close" onClick={onClose} aria-label="Close">×</button>
      </div>

      <div className="request-modal-pinned" title={peekCtx.selector}>
        <span>🎯</span>
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{elementLabel}</span>
      </div>

      <div className="request-modal-body">
        {!plan.state.busy && !plan.state.planReady && !plan.state.error && (
          <div className="request-modal-empty">
            Describe what you want changed about this element. AppCrane plans it; click <strong>Build</strong> to ship.
          </div>
        )}

        {(plan.state.busy || w.elapsedSec > 0) && (
          <div className="request-modal-status">
            <span className="az-spinner" />
            <span>{w.text || 'Working…'}</span>
            {w.elapsedSec > 0 && <span style={{ color: 'var(--dim)', marginLeft: 'auto' }}>{w.elapsedSec}s</span>}
          </div>
        )}

        {plan.state.planText && (
          <div className="request-modal-plan">
            <div className="request-modal-plan-hdr">Plan #{plan.state.enhId}</div>
            <pre>{plan.state.planText}</pre>
          </div>
        )}

        {plan.state.error && (
          <div className="request-modal-error">⚠️ {plan.state.error}</div>
        )}

        {plan.state.built && !plan.state.error && (
          <div className="request-modal-built">✅ Build queued — track progress in 📋 Jobs.</div>
        )}
      </div>

      <div className="request-modal-input">
        {plan.state.planReady && canBuild && !plan.state.built && (
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
            <button
              type="button"
              className="ask-send plan-build-btn"
              onClick={() => plan.build()}
              disabled={plan.state.built}
            >🔨 Build</button>
          </div>
        )}
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSubmit() }
            }}
            placeholder={plan.state.planReady ? 'Refine the plan…' : 'What should change about this element?'}
            rows={3}
            disabled={plan.state.busy}
            autoFocus
          />
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={plan.state.busy || !text.trim()}
          >{
            plan.state.busy ? '…'
            : plan.state.planReady && !plan.state.built ? '🔁 Refine'
            : canBuild ? '📋 Plan'
            : '📤 Submit'
          }</button>
        </div>
      </div>
    </div>
  )
}
