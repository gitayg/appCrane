/**
 * Popup sign-in for the sign-in page when it runs inside an iframe.
 *
 * Identity providers refuse to be framed, so navigating the frame to the IdP
 * shows "refused to connect". In a frame, SSO opens in a top-level popup
 * instead; password sign-in stays in the frame. The popup's completion page
 * (server/utils/ssoPopup.js) posts { type: 'signed-in' } on SSO_CHANNEL and
 * closes; a failed sign-in posts { type: 'sign-in-failed' } and stays open to
 * show why. The frame also polls /api/me (cookie) in case BroadcastChannel is
 * unavailable, bounded by POLL_MAX_MS.
 *
 * The popup handle's `closed` is NOT used to notice the user closing the
 * window. Measured in Chrome 153: once the popup navigates to an IdP sending
 * Cross-Origin-Opener-Policy: same-origin, the opener's handle reports
 * closed === true within ~50 ms while the popup is still open, and never
 * changes after that. A closed window therefore only ends the wait through the
 * POLL_MAX_MS bound; the Sign in button stays usable meanwhile.
 *
 * Kept free of imports and non-erasable TypeScript so node:test can load it
 * directly.
 */

export const SSO_CHANNEL = 'appcrane-sso'
export const POPUP_NAME = 'appcrane-sso'
export const POPUP_FEATURES = 'width=520,height=680'
export const POLL_INTERVAL_MS = 1500
export const POLL_MAX_MS = 5 * 60 * 1000

export type SsoProvider = 'oidc' | 'saml'

/** Framed when top is not self; being unable to read top also means framed. */
export function isFramed(win: { readonly top: unknown; readonly self: unknown }): boolean {
  try {
    return win.top !== win.self
  } catch {
    return true
  }
}

export interface SignInPlan {
  /** Password form is shown whenever SSO is not required, framed or not. */
  showPassword: boolean
  /** How the IdP step runs. */
  sso: 'none' | 'navigate' | 'popup'
}

export function signInPlan(o: { framed: boolean; ssoEnabled: boolean; ssoOnly: boolean }): SignInPlan {
  return {
    showPassword: !o.ssoOnly,
    sso: !o.ssoEnabled ? 'none' : o.framed ? 'popup' : 'navigate',
  }
}

export function shouldUsePopupSignIn(o: { framed: boolean; ssoEnabled: boolean }): boolean {
  return signInPlan({ ...o, ssoOnly: false }).sso === 'popup'
}

export function popupStartUrl(provider: SsoProvider, redirect: string): string {
  return `/api/auth/${provider}/start?` + new URLSearchParams({ redirect, mode: 'popup' }).toString()
}

/** Where the frame goes once signed in: the validated `redirect`, or null to reload in place. */
export function reloadTargetAfterSignIn(search: string, isSafe: (v: string | null) => boolean): string | null {
  const redirect = new URLSearchParams(search).get('redirect')
  return isSafe(redirect) ? redirect : null
}

export function isSignedInMessage(data: unknown): boolean {
  return typeof data === 'object' && data !== null && (data as { type?: unknown }).type === 'signed-in'
}

export function isSignInFailedMessage(data: unknown): boolean {
  return typeof data === 'object' && data !== null && (data as { type?: unknown }).type === 'sign-in-failed'
}

export interface ChannelLike {
  listen: (fn: (data: unknown) => void) => void
  close: () => void
}

export interface WaitDeps {
  openChannel: (name: string) => ChannelLike | null
  /** Resolves true when the browser now holds a signed-in session. */
  checkSession: () => Promise<boolean>
  setInterval: (fn: () => void, ms: number) => unknown
  clearInterval: (h: unknown) => void
  setTimeout: (fn: () => void, ms: number) => unknown
  clearTimeout: (h: unknown) => void
}

export type WaitResult = 'signed-in' | 'failed' | 'timeout' | 'cancelled'

export function waitForPopupSignIn(
  deps: WaitDeps,
  opts: { intervalMs?: number; maxMs?: number } = {},
): { done: Promise<WaitResult>; cancel: () => void } {
  const intervalMs = opts.intervalMs ?? POLL_INTERVAL_MS
  const maxMs = Math.min(opts.maxMs ?? POLL_MAX_MS, POLL_MAX_MS)
  let settled = false
  let resolveDone: (r: WaitResult) => void = () => {}
  const done = new Promise<WaitResult>((r) => { resolveDone = r })

  let channel: ChannelLike | null = null
  let interval: unknown = null
  let timeout: unknown = null
  const finish = (result: WaitResult) => {
    if (settled) return
    settled = true
    if (channel) channel.close()
    deps.clearInterval(interval)
    deps.clearTimeout(timeout)
    resolveDone(result)
  }

  // The poll only counts once a baseline check said "not signed in"; a session
  // that already existed must not be mistaken for this sign-in finishing.
  let pollArmed = false
  let failing = false

  channel = deps.openChannel(SSO_CHANNEL)
  if (channel) channel.listen((data) => {
    if (isSignedInMessage(data)) finish('signed-in')
    else if (isSignInFailedMessage(data) && !failing) {
      // One last session check, so a sign-in that did land (another window,
      // a retry) wins over a failure page from an earlier attempt.
      failing = true
      const fail = () => finish('failed')
      if (!pollArmed) return fail()
      deps.checkSession().then((ok) => finish(ok ? 'signed-in' : 'failed'), fail)
    }
  })

  deps.checkSession().then((ok) => { if (!ok) pollArmed = true }, () => { pollArmed = true })
  interval = deps.setInterval(() => {
    if (!pollArmed || settled) return
    deps.checkSession().then((ok) => { if (ok) finish('signed-in') }, () => {})
  }, intervalMs)
  timeout = deps.setTimeout(() => finish('timeout'), maxMs)

  return { done, cancel: () => finish('cancelled') }
}

export function browserWaitDeps(): WaitDeps {
  return {
    openChannel: (name) => {
      if (typeof BroadcastChannel === 'undefined') return null
      const ch = new BroadcastChannel(name)
      return { listen: (fn) => { ch.onmessage = (e) => fn(e.data) }, close: () => ch.close() }
    },
    checkSession: () => fetch('/api/me', { credentials: 'same-origin', cache: 'no-store' }).then((r) => r.ok),
    setInterval: (fn, ms) => window.setInterval(fn, ms),
    clearInterval: (h) => window.clearInterval(h as number),
    setTimeout: (fn, ms) => window.setTimeout(fn, ms),
    clearTimeout: (h) => window.clearTimeout(h as number),
  }
}
