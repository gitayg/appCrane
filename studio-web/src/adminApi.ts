// Admin API — all fetch helpers for the admin SPA AND for the shared
// React panels (Ask / Request / Bug) when mounted in the portal page.
// Auth precedence: X-API-Key (admin SPA stores in cc_api_key) →
// Bearer token (portal stores its identity session in cc_identity_token).
// This lets the same panels work in both contexts without bundling a
// separate fetch helper for portal.

/**
 * Strip any character that can't go into an HTTP header. Browsers throw
 * "String contains non ISO-8859-1 code point" out of fetch otherwise.
 * Defense in depth — useAuth.setKey already validates at write time, but
 * a key that pre-dates that validation (e.g. one stored before v2.1.5)
 * shouldn't crash the SPA.
 */
function asciiOnly(s: string): string {
  return s.replace(/[^\x20-\x7E]/g, '').trim()
}

function authHeaders(): Record<string, string> {
  const key = asciiOnly(localStorage.getItem('cc_api_key') || '')
  if (key) return { 'X-API-Key': key }
  const bearer = asciiOnly(localStorage.getItem('cc_identity_token') || '')
  if (bearer) return { 'Authorization': 'Bearer ' + bearer }
  return {}
}

/** Token used for SSE EventSource ?token= query (no header support). */
export function authTokenForSSE(): string {
  return localStorage.getItem('cc_api_key')
      || localStorage.getItem('cc_identity_token')
      || ''
}

/** Server messages that mean the stored credential is genuinely bad and
 *  should be cleared. Anything else (a missing header due to a transient
 *  state mismatch, a scope-restricted key, etc.) leaves localStorage alone
 *  so a single oddball 401 doesn't take out a working session. */
// v2.6.7: also treat "Missing X-API-Key header or Bearer token" as
// proven-bad. Previously this was the "transient" branch that left
// localStorage alone, but the practical effect was: an expired session
// where the SPA still considered the user authed (token in localStorage
// but server rejected it) would render the raw JSON error instead of
// the Login form. Clearing on this message + reloading puts the user
// back on Login where they can sign in. False-positive risk is low —
// if the SPA sent no creds, it means it didn't have any to send.
const PROVEN_BAD_CREDENTIAL_MESSAGES = new Set([
  'Invalid API key',
  'Invalid or expired session',
  'Account is deactivated',
  'Issuer account is deactivated',
  'Missing X-API-Key header or Bearer token',
])

async function req<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init?.headers || {}),
    },
  })
  if (r.status === 401) {
    // Read the server's specific message before deciding whether to nuke
    // the session. Older logic wiped cc_api_key on ANY 401 — which
    // includes "Missing X-API-Key header or Bearer token" (the header
    // failed to attach for a reason unrelated to the key being valid)
    // and would chain-react: one transient miss → cleared session →
    // every subsequent fetch un-authed.
    const body = await r.clone().json().catch(() => ({}))
    const message = (body as { error?: { message?: string } })?.error?.message || ''
    const provenBad = PROVEN_BAD_CREDENTIAL_MESSAGES.has(message)

    if (provenBad) {
      // v2.6.7: clear BOTH credential types AND the cc_token cookie
      // that forward_auth reads. Old behavior only cleared cc_api_key,
      // so Bearer-only sessions (the unified-login default since v2.4.0)
      // never got reset on a server-side 401 and the user kept seeing
      // raw-JSON errors. Reload to /applications so AdminApp re-renders
      // with no auth → Login form takes over with a fresh state.
      try {
        localStorage.removeItem('cc_api_key')
        localStorage.removeItem('cc_identity_token')
        document.cookie = 'cc_token=; Path=/; Max-Age=0; SameSite=Lax'
      } catch (_) { /* SSR / locked storage */ }
      // Preserve the user's intended destination so Login can bounce
      // them back after re-auth (Login.tsx already handles ?redirect=).
      const here = window.location.pathname + window.location.search
      const target = '/applications' + (here && here !== '/applications' && here !== '/login'
        ? '?redirect=' + encodeURIComponent(here)
        : '')
      window.location.replace(target)
    }
    throw new Error(message ? `Unauthorized: ${message}` : 'Unauthorized')
  }
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    const msg = (body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`
    throw new Error(msg)
  }
  const data = await r.json().catch(() => ({}))
  return data as T
}

const get  = <T>(path: string) => req<T>(path)
const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined })
const put  = <T>(path: string, body: unknown) =>
  req<T>(path, { method: 'PUT', body: JSON.stringify(body) })
const del  = <T>(path: string) => req<T>(path, { method: 'DELETE' })
const getText = (path: string) =>
  fetch(path, { headers: authHeaders() }).then(r => r.text())

export const adminApi = { get, post, put, del, getText, authHeaders }
