import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Element-pick overlay over the embedded app iframe — same UX as the
 * portal's togglePeekMode in docs/login.html. Hover highlights, click
 * captures, Escape cancels.
 *
 * Works only when the iframe is same-origin (the AppCrane apps live
 * under the same host so `iframe.contentDocument` is reachable). With app
 * isolation on, each app has its own address and the dashboard cannot see
 * inside it: start() then hands back the whole page (empty selector) at once,
 * so the Request and coder flows still open, just without a pointed element.
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
  /**
   * Click coordinates and element bounding rect at the moment of capture,
   * in viewport coordinates of the parent (host) document — already
   * translated through the iframe's getBoundingClientRect so the consumer
   * doesn't need to know about the iframe at all. Used by the floating
   * request modal to position itself next to the picked element.
   * Both are missing when usePeek runs against a non-iframe document.
   */
  clickX?: number
  clickY?: number
  rect?:   { left: number; top: number; width: number; height: number }
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
      setCtx({ selector: '', tag: '', id: '', text: '', path: iframe.src })
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
      // Translate iframe-relative click + element rect into host-document
      // viewport coords so a floating modal in the host page can position
      // itself relative to the actual visual click target.
      try {
        const iframeRect = iframe.getBoundingClientRect()
        const elRect = (e.target as Element).getBoundingClientRect()
        info.clickX = iframeRect.left + e.clientX
        info.clickY = iframeRect.top  + e.clientY
        info.rect = {
          left:   iframeRect.left + elRect.left,
          top:    iframeRect.top  + elRect.top,
          width:  elRect.width,
          height: elRect.height,
        }
      } catch (_) { /* leave undefined */ }
      setCtx(info)
      stop()
    }
    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); stop() }
    }
    // The pick's press/release must not reach the app either: menus and
    // drawers that open on pointerdown/mouseup would open under the modal,
    // grab focus, and retarget the click to <body>. Window capture (for the
    // click too) runs before the app's own document listeners. Touch events
    // are only stopped — cancelling them would suppress the click that picks.
    const win = doc.defaultView
    const onPress = (e: Event) => {
      if (!e.type.startsWith('touch')) e.preventDefault()
      e.stopImmediatePropagation()
    }
    const PRESS = ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'touchstart', 'touchend']
    PRESS.forEach(t => win?.addEventListener(t, onPress, true))

    doc.addEventListener('mouseover', onOver, true)
    doc.addEventListener('mouseout',  onOut,  true)
    win?.addEventListener('click',    onClick, true)
    doc.addEventListener('keydown',   onKeydown, true)
    document.addEventListener('keydown', onKeydown, true)

    cleanupRef.current = () => {
      try {
        if (hoverElRef.current) (hoverElRef.current as Element).classList.remove('__ac_peek_hover')
        doc.getElementById(STYLE_ID)?.remove()
        doc.removeEventListener('mouseover', onOver, true)
        doc.removeEventListener('mouseout',  onOut,  true)
        win?.removeEventListener('click',    onClick, true)
        doc.removeEventListener('keydown',   onKeydown, true)
        PRESS.forEach(t => win?.removeEventListener(t, onPress, true))
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
export const WHOLE_PAGE_LABEL = 'This page (this app opens on its own address, so you can\'t point at one part of it)'

export function PeekChip({ ctx, onClear }: { ctx: PeekCtx; onClear: () => void }) {
  const label = !ctx.selector ? WHOLE_PAGE_LABEL
    : (ctx.tag ? `<${ctx.tag}>` : '') + (ctx.text ? ` "${ctx.text.slice(0, 60)}"` : ` ${ctx.selector}`)
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
  if (!ctx.selector) return `--- Page ---\nURL: ${ctx.path}\n\n`
  return [
    '--- Pointed element ---',
    `URL: ${ctx.path}`,
    `Selector: ${ctx.selector}`,
    `Tag: <${ctx.tag}>${ctx.id ? ' #' + ctx.id : ''}`,
    ctx.text ? `Text: "${ctx.text}"` : null,
  ].filter(Boolean).join('\n') + '\n\n'
}
