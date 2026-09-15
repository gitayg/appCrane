/**
 * What the sign-in landing page does with `?redirect=/<slug>`.
 *
 * forward_auth sends a browser it will not let through to /login, which lands
 * on /launch?redirect=/<slug>. The landing page used to forward to the target
 * whenever a token merely EXISTED in localStorage. When forward_auth had refused
 * because that token's session was gone, or because the cookie it reads was
 * missing, or because the user has no role on the app, the target refused
 * again and sent the browser straight back: a reload loop that an embedded
 * frame shows as a flickering screen.
 *
 * So the landing page now:
 *   - never forwards on `denied=1` — forward_auth already decided, and asking
 *     again cannot change the answer; the user sees who they are not allowed as;
 *   - confirms the credential server-side before forwarding. For an identity
 *     token that call is POST /api/identity/refresh-cookie, which also sets the
 *     cookie forward_auth reads, so the forward that follows can succeed;
 *   - on a refused credential, drops it and shows sign-in instead;
 *   - refuses to forward to the same target more than REDIRECT_MAX times within
 *     REDIRECT_WINDOW_MS, whatever the reason, and says so.
 *
 * Kept free of imports and non-erasable TypeScript so node:test can load it
 * directly.
 */

/** Landing routes: forwarding to one of these is a navigation to the page already shown. */
const LANDING_ROUTE = /^\/(login|applications|launch)(\/|\?|$)/

/**
 * Loop breaker. A legitimate sign-in forwards to a target once per sign-in, and
 * each sign-in takes a human several seconds. The measured loop forwards to the
 * same target every few hundred milliseconds. Three forwards inside thirty
 * seconds allows a sign-in, a retry and one more; the fourth inside the window
 * is a loop, and stopping it costs at most three flickers.
 */
export const REDIRECT_MAX = 3
export const REDIRECT_WINDOW_MS = 30_000
export const REDIRECT_STORE_PREFIX = 'cc_landing_redirects:'

const NAME_MAX = 120

export interface LandingIntent {
  /** Safe same-origin target to forward to, or null. */
  target: string | null
  denied: boolean
  /** Display name of the refused app. Plain text; render it as text, never as HTML. */
  appName: string
}

export function readLandingIntent(search: string, isSafe: (v: string | null) => boolean): LandingIntent {
  const params = new URLSearchParams(search)
  const redirect = params.get('redirect')
  const target = isSafe(redirect) && !LANDING_ROUTE.test(redirect as string) ? redirect : null
  const appName = (params.get('name') || params.get('app') || '').slice(0, NAME_MAX)
  return { target, denied: params.get('denied') === '1', appName }
}

export type Landing =
  | { kind: 'none' }
  | { kind: 'denied'; appName: string; target: string | null }
  | { kind: 'checking'; target: string }
  | { kind: 'go'; target: string }
  | { kind: 'stale' }
  | { kind: 'loop'; target: string }

export function initialLanding(intent: LandingIntent, isAuthed: boolean): Landing {
  if (intent.denied) return { kind: 'denied', appName: intent.appName, target: intent.target }
  if (!intent.target || !isAuthed) return { kind: 'none' }
  return { kind: 'checking', target: intent.target }
}

export type SessionCheck = 'valid' | 'invalid' | 'unreachable'

export interface SessionCheckDeps {
  token: string
  apiKey: string
  fetch: (url: string, init: { method: string; headers: Record<string, string> }) => Promise<{ status: number; ok: boolean }>
}

/**
 * Ask the server whether the stored credential still works.
 *
 * 401/403 is a refusal. A network error or a 5xx is not proof the credential
 * died, so it answers 'unreachable' and the credential is kept.
 */
export async function checkSession(deps: SessionCheckDeps): Promise<SessionCheck> {
  let r: { status: number; ok: boolean }
  try {
    if (deps.token) {
      r = await deps.fetch('/api/identity/refresh-cookie', { method: 'POST', headers: { Authorization: `Bearer ${deps.token}` } })
    } else if (deps.apiKey) {
      r = await deps.fetch('/api/me', { method: 'GET', headers: { 'X-API-Key': deps.apiKey } })
    } else {
      return 'invalid'
    }
  } catch {
    return 'unreachable'
  }
  if (r.status === 401 || r.status === 403) return 'invalid'
  return r.ok ? 'valid' : 'unreachable'
}

export interface AttemptStore {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

function recentAttempts(store: AttemptStore, target: string, now: number): number[] {
  let list: unknown
  try { list = JSON.parse(store.getItem(REDIRECT_STORE_PREFIX + target) || '[]') } catch { list = [] }
  return Array.isArray(list) ? list.filter((t): t is number => typeof t === 'number' && now - t < REDIRECT_WINDOW_MS && t <= now) : []
}

/**
 * Record a forward to `target` and say whether it may happen. False once
 * REDIRECT_MAX forwards already happened inside the window. Storage that throws
 * allows the forward: the session check above still prevents the known loops.
 */
export function allowRedirect(store: AttemptStore | null, target: string, now: number): boolean {
  if (!store) return true
  try {
    const recent = recentAttempts(store, target, now)
    if (recent.length >= REDIRECT_MAX) return false
    store.setItem(REDIRECT_STORE_PREFIX + target, JSON.stringify([...recent, now]))
    return true
  } catch {
    return true
  }
}

export function clearRedirectAttempts(store: AttemptStore | null, target: string): void {
  try { store?.removeItem(REDIRECT_STORE_PREFIX + target) } catch { /* locked storage */ }
}

export function afterCheck(target: string, check: SessionCheck, store: AttemptStore | null, now: number): Landing {
  if (check === 'invalid') return { kind: 'stale' }
  return allowRedirect(store, target, now) ? { kind: 'go', target } : { kind: 'loop', target }
}
