import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Element-pick overlay over the embedded app iframe — same UX as the
 * portal's togglePeekMode in docs/login.html. Hover highlights, click
 * captures, Escape cancels.
 *
 * Works only when the iframe is same-origin (the AppCrane apps live
 * under the same host so `iframe.contentDocument` is reachable).
 *
 * Returns:
 *   active   — picker is currently capturing
 *   ctx      — last picked element, until cleared via clear()
 *   start()  — begin picking
 *   stop()   — abort
 *   clear()  — drop the captured ctx
 */
export interface PeekCtx {
  selector: string
  tag:      string
  id:       string
  text:     string
  path:     string  // page URL where the element was picked
}

export function usePeek(iframeRef: React.RefObject<HTMLIFrameElement | null>) {
  const [active, setActive] = useState(false)
  const [ctx,    setCtx]    = useState<PeekCtx | null>(null)
  const hoverElRef = useRef<Element | null>(null)
  const cleanupRef = useRef<(() => void) | null>(null)

  const stop = useCallback(() => {
    if (cleanupRef.current) cleanupRef.current()
    cleanupRef.current = null
    setActive(false)
  }, [])

  const start = useCallback(() => {
    const iframe = iframeRef.current
    if (!iframe) return
    let doc: Document
    try {
      const d = iframe.contentDocument
      if (!d || !d.body) throw new Error('iframe not ready')
      doc = d
    } catch {
      alert("Can't access this app's content for point-and-click — the app is served from a different origin than the dashboard.")
      return
    }

    const STYLE_ID = '__ac_peek_style'
    let style = doc.getElementById(STYLE_ID)
    if (!style) {
      style = doc.createElement('style')
      style.id = STYLE_ID
      style.textContent =
        '.__ac_peek_hover{outline:2px solid #3b82f6!important;outline-offset:1px!important;background:#3b82f61a!important;cursor:crosshair!important}' +
        ' *{cursor:crosshair!important}'
      doc.head.appendChild(style)
    }

    const onOver = (e: Event) => {
      if (hoverElRef.current) (hoverElRef.current as Element).classList.remove('__ac_peek_hover')
      hoverElRef.current = e.target as Element
      hoverElRef.current?.classList?.add('__ac_peek_hover')
    }
    const onOut = (e: Event) => {
      ;(e.target as Element)?.classList?.remove('__ac_peek_hover')
    }
    const onClick = (e: MouseEvent) => {
      e.preventDefault()
      e.stopPropagation()
      const info = capture(e.target as Element)
      setCtx(info)
      stop()
    }
    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); stop() }
    }

    doc.addEventListener('mouseover', onOver, true)
    doc.addEventListener('mouseout',  onOut,  true)
    doc.addEventListener('click',     onClick, true)
    doc.addEventListener('keydown',   onKeydown, true)
    document.addEventListener('keydown', onKeydown, true)

    cleanupRef.current = () => {
      try {
        if (hoverElRef.current) (hoverElRef.current as Element).classList.remove('__ac_peek_hover')
        doc.getElementById(STYLE_ID)?.remove()
        doc.removeEventListener('mouseover', onOver, true)
        doc.removeEventListener('mouseout',  onOut,  true)
        doc.removeEventListener('click',     onClick, true)
        doc.removeEventListener('keydown',   onKeydown, true)
      } catch (_) {}
      document.removeEventListener('keydown', onKeydown, true)
      hoverElRef.current = null
    }
    setActive(true)
  }, [iframeRef, stop])

  const toggle = useCallback(() => { active ? stop() : start() }, [active, start, stop])
  const clear  = useCallback(() => setCtx(null), [])

  // Cleanup on unmount
  useEffect(() => () => stop(), [stop])

  return { active, ctx, start, stop, toggle, clear }
}

function capture(el: Element): PeekCtx {
  const doc = el.ownerDocument
  const win = doc.defaultView
  const root = doc.documentElement
  const path: string[] = []
  let cur: Element | null = el
  while (cur && cur.nodeType === 1 && cur !== root) {
    let sel = cur.nodeName.toLowerCase()
    if (cur.id) { sel += '#' + cur.id; path.unshift(sel); break }
    let sib: Element | null = cur, nth = 1
    while ((sib = sib.previousElementSibling)) if (sib.nodeName === cur.nodeName) nth++
    if (nth > 1) sel += `:nth-of-type(${nth})`
    path.unshift(sel)
    cur = cur.parentElement
  }
  return {
    selector: path.join(' > '),
    tag:      el.nodeName.toLowerCase(),
    id:       (el as HTMLElement).id || '',
    text:     ((el as HTMLElement).innerText || '').trim().slice(0, 200),
    path:     win?.location?.pathname || '',
  }
}

/**
 * Renders a small chip with the picked element info + an X to clear.
 * Drop in just above the input row in any panel that uses usePeek.
 */
export function PeekChip({ ctx, onClear }: { ctx: PeekCtx; onClear: () => void }) {
  const label = (ctx.tag ? `<${ctx.tag}>` : '') + (ctx.text ? ` "${ctx.text.slice(0, 60)}"` : ` ${ctx.selector}`)
  return (
    <div className="ask-peek-bar" title={ctx.selector}>
      <span>🎯</span>
      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
      <button onClick={onClear} title="Drop the picked element">×</button>
    </div>
  )
}

/**
 * Format the picked element as a context block to prepend to the prompt
 * (matches portal's planPeekCtx prepend in sendPlanRequest).
 */
export function peekToPromptPrefix(ctx: PeekCtx): string {
  return [
    '--- Pointed element ---',
    `URL: ${ctx.path}`,
    `Selector: ${ctx.selector}`,
    `Tag: <${ctx.tag}>${ctx.id ? ' #' + ctx.id : ''}`,
    ctx.text ? `Text: "${ctx.text}"` : null,
  ].filter(Boolean).join('\n') + '\n\n'
}
