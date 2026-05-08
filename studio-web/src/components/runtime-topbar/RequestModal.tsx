import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../../adminApi'
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
const MODAL_H_MIN = 220
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
  if (rect.left + rect.width + GUTTER + MODAL_W < vw) {
    return { left: rect.left + rect.width + GUTTER, top: Math.max(GUTTER, Math.min(rect.top, vh - MODAL_H_MIN - GUTTER)) }
  }
  if (rect.top + rect.height + GUTTER + MODAL_H_MIN < vh) {
    return { left: Math.max(GUTTER, Math.min(rect.left, vw - MODAL_W - GUTTER)), top: rect.top + rect.height + GUTTER }
  }
  if (rect.left - MODAL_W - GUTTER > 0) {
    return { left: rect.left - MODAL_W - GUTTER, top: Math.max(GUTTER, Math.min(rect.top, vh - MODAL_H_MIN - GUTTER)) }
  }
  return { left: Math.max(GUTTER, (vw - MODAL_W) / 2), top: Math.max(GUTTER, (vh - MODAL_H_MIN) / 2) }
}

/**
 * Floating draggable Request modal — replacement for the side-drawer
 * RequestPanel inside /applications' embedded frame view.
 *
 * v2.3.3 simplification: submit-and-close. The modal's only job is to
 * collect the request text + element context and POST to /api/enhancements.
 * Plan / refine / build moved to the Jobs panel — that's where users
 * watch their requests progress, not here.
 *
 * Flow:
 *   1. User clicks the topbar Request button.
 *   2. Pick mode activates immediately (no drawer opens first).
 *   3. User clicks an element in the iframe.
 *   4. usePeek captures element + click coords; parent passes peekCtx.
 *   5. Modal mounts at a position that doesn't cover the pick.
 *   6. User types, hits Enter or Submit → POST /api/enhancements → close.
 */
export function RequestModal({ slug, appName, peekCtx, onClose }: Props) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [pos, setPos] = useState(() => initialPosition(peekCtx.rect))
  const dragRef = useRef<{ startX: number; startY: number; left: number; top: number } | null>(null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, busy])

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

  async function onSubmit() {
    if (!slug || !text.trim() || busy) return
    setBusy(true)
    setError(null)
    try {
      const prefix = peekToPromptPrefix(peekCtx)
      const message = prefix + text.trim()
      const r = await adminApi.post<{ enhancement_id?: number; error?: { message?: string } }>(
        '/api/enhancements', { message, app_slug: slug },
      )
      if (r?.error) throw new Error(r.error.message || 'Submission failed')
      // Done — modal closes; user follows progress in 📋 Jobs.
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }

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
        <button type="button" className="request-modal-close" onClick={onClose} aria-label="Close" disabled={busy}>×</button>
      </div>

      <div className="request-modal-pinned" title={peekCtx.selector}>
        <span>🎯</span>
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{elementLabel}</span>
      </div>

      <div className="request-modal-input">
        {error && <div className="request-modal-error" style={{ marginBottom: 8 }}>⚠️ {error}</div>}
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSubmit() }
            }}
            placeholder="What should change about this element?"
            rows={4}
            disabled={busy}
            autoFocus
          />
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={busy || !text.trim()}
            title="Submit. Track progress in 📋 Jobs."
          >{busy ? '…' : '📤 Submit'}</button>
        </div>
        <div style={{ marginTop: 6, fontSize: '.72rem', color: 'var(--dim)' }}>
          Track progress in <strong>📋 Jobs</strong> after submit.
        </div>
      </div>
    </div>
  )
}
