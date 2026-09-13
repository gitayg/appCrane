/**
 * What to do when the server says the session is gone.
 *
 * THE POLARITY IS THE POINT. The previous rule was an allowlist: redirect only
 * when the 401 body matched one of five known-bad messages. The server returns
 * TWELVE distinct 401 messages, so the list failed OPEN — an expired identity
 * token answers `Token expired`, which was not on it, so nothing happened at
 * all. No redirect, no cleared credential, dead session, silent screen.
 *
 * A guard that has to enumerate every message the server might invent, and does
 * nothing when it misses one, is a guard that quietly stops working. So the
 * rule is inverted: a 401 from a session-gated route means the session is gone,
 * and the few routes that answer 401 for other reasons are named explicitly.
 * Now a message nobody anticipated bounces the user to sign-in instead of
 * leaving them looking at a stale screen.
 *
 * EXCLUDED, deliberately: the login routes. A wrong password is a 401 and is
 * the sign-in screen's own answer, not a lapsed session — redirecting there
 * would be a loop that never lets anyone type a password.
 *
 * LATCHED, not evented. Several pollers refuse in the same instant when a
 * cookie lapses; each would otherwise call replace() and the user would be
 * bounced once per poller. The latch makes it one bounce, and lets callers stop
 * polling instead of retrying into a session that is already gone.
 */

/**
 * Routes whose 401 is a legitimate answer rather than a lapsed session.
 * Matched against the request path with `startsWith` after stripping origin.
 */
export const NON_SESSION_401_PATHS: readonly string[] = [
  '/api/identity/login',
  '/api/identity/register',
  '/api/auth/login',
]

/** Has a bounce already been triggered? Exported for tests and for pollers. */
let bounced = false

export function sessionHasLapsed(): boolean {
  return bounced
}

/** Test seam. Not used in the app. */
export function __resetSessionExpiryLatch(): void {
  bounced = false
}

function pathOf(input: string): string {
  try {
    return new URL(input, window.location.origin).pathname
  } catch (_) {
    return input
  }
}

/** Is this a route whose 401 does NOT mean the session lapsed? */
export function isNonSessionRoute(url: string): boolean {
  const p = pathOf(url)
  return NON_SESSION_401_PATHS.some((x) => p.startsWith(x))
}

/**
 * Drop the dead credential and send the browser to sign in. Idempotent: the
 * first caller wins and the rest are no-ops.
 *
 * The cc_token cookie is httpOnly and cannot be cleared from JS — it does not
 * need to be. forward_auth validates it server-side, and a lapsed session means
 * the token is already dead; /verify rejects it.
 *
 * The current location travels as ?redirect= so Login can put the user back.
 * '/applications' and '/login' are skipped: bouncing a user to the page they
 * are already on is a loop.
 */
export function clearCredentialsAndRedirect(): void {
  if (bounced) return
  bounced = true

  try {
    localStorage.removeItem('cc_api_key')
    localStorage.removeItem('cc_identity_token')
  } catch (_) { /* SSR / locked storage */ }

  const here = window.location.pathname + window.location.search
  const target = '/applications' + (here && here !== '/applications' && here !== '/login'
    ? '?redirect=' + encodeURIComponent(here)
    : '')
  window.location.replace(target)
}

/**
 * Handle a 401. Returns the server's message so the caller can throw with it.
 *
 * Reads a CLONE so the caller can still consume the body.
 */
export async function handleUnauthorized(r: Response, url: string): Promise<string> {
  const body = await r.clone().json().catch(() => ({}))
  const message = (body as { error?: { message?: string } })?.error?.message || ''
  if (!isNonSessionRoute(url)) clearCredentialsAndRedirect()
  return message
}

/**
 * Does the session still work?
 *
 * For EventSource, which reports errors with NO STATUS CODE. An SSE error is
 * ambiguous — a dropped connection and a lapsed session look identical — so the
 * only way to tell them apart is to ask over a channel that can answer. A
 * reconnect loop against a dead session is the failure this exists to stop:
 * it produces no error and no sign anything is wrong, forever.
 *
 * Returns true when the caller should reconnect, false when it must stop
 * because a bounce is under way. A NETWORK failure answers true: the ambiguous
 * case must reconnect, not sign a user out of a working session because their
 * wifi dropped.
 */
export async function sessionStillValid(probePath = '/api/me'): Promise<boolean> {
  if (bounced) return false
  let r: Response
  try {
    const read = (k: string) => { try { return localStorage.getItem(k) || '' } catch { return '' } }
    const token = read('cc_identity_token')
    const apiKey = read('cc_api_key')
    const headers: Record<string, string> = {}
    if (token) headers.Authorization = `Bearer ${token}`
    else if (apiKey) headers['X-API-Key'] = apiKey
    r = await fetch(probePath, { headers })
  } catch (_) {
    return true // offline or unreachable — not proof the session died
  }
  if (r.status !== 401) return true
  await handleUnauthorized(r, probePath)
  return false
}
