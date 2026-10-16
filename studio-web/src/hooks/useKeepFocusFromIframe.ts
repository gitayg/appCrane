import { useCallback, useEffect, useRef } from 'react'

/**
 * Keep keyboard focus in a dashboard text box while the app iframe beside it
 * tries to take it.
 *
 * The app can pull focus into its iframe after a pick (a menu opened by hover,
 * a focus trap, a refocus timer) and then nothing typed in the box lands. Focus
 * is handed back unless the user's own last press was in the app, and until
 * then the focus loss is hidden from the app so a trap that refocuses on
 * blur/focusout doesn't take it straight back.
 *
 * Wire `onBlur` to the box. Call `claim()` instead of focusing the box after a
 * pick: the picking press itself landed in the app, and must not count as the
 * user choosing to work there.
 *
 * `frameKey` re-attaches the listeners when the iframe element is replaced
 * (AppFrame keys its iframe on the URL); `enabled` detaches them while the
 * box isn't shown.
 */
export function useKeepFocusFromIframe(
  iframeRef: React.RefObject<HTMLIFrameElement | null> | undefined,
  targetRef: React.RefObject<HTMLElement | null>,
  { enabled = true, frameKey }: { enabled?: boolean; frameKey?: unknown } = {},
) {
  const userInAppRef = useRef(false)
  useEffect(() => {
    if (!enabled) return
    const iframe = iframeRef?.current
    if (!iframe) return
    let appWin: Window | null = null
    const onAppPress = () => { userInAppRef.current = true }
    const onHostPress = () => { userInAppRef.current = false }
    const onAppFocusLoss = (e: FocusEvent) => {
      if (!userInAppRef.current && !e.relatedTarget) e.stopImmediatePropagation()
    }
    const attach = () => {
      try {
        appWin = iframe.contentWindow
        appWin?.addEventListener('pointerdown', onAppPress, true)
        appWin?.addEventListener('focusout', onAppFocusLoss, true)
        appWin?.addEventListener('blur', onAppFocusLoss, true)
      } catch { appWin = null }
    }
    attach()
    iframe.addEventListener('load', attach)
    window.addEventListener('pointerdown', onHostPress, true)
    return () => {
      iframe.removeEventListener('load', attach)
      window.removeEventListener('pointerdown', onHostPress, true)
      try {
        appWin?.removeEventListener('pointerdown', onAppPress, true)
        appWin?.removeEventListener('focusout', onAppFocusLoss, true)
        appWin?.removeEventListener('blur', onAppFocusLoss, true)
      } catch { /* navigated away */ }
    }
  }, [iframeRef, enabled, frameKey])

  const onBlur = useCallback(() => {
    // A microtask, not a timer: it runs before the next keystroke is handled.
    queueMicrotask(() => {
      const iframe = iframeRef?.current
      if (iframe && document.activeElement === iframe && !userInAppRef.current) targetRef.current?.focus()
    })
  }, [iframeRef, targetRef])

  const claim = useCallback(() => {
    userInAppRef.current = false
    targetRef.current?.focus()
  }, [targetRef])

  return { onBlur, claim }
}
