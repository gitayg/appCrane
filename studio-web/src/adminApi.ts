import { handleUnauthorized } from './sessionExpiry'

// Admin API — all fetch helpers for the admin SPA AND for the shared
// React panels (Ask / Request / Bug) when mounted in the portal page.
// Auth precedence: the identity session first (cc_identity_token, what the
// portal signs a person in with), then an API key (cc_api_key, what the admin
// SPA stores). api.ts resolves them in this same order — the two used to
// disagree, so a browser holding both authenticated as a different principal
// depending on which helper a component imported.
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

export function authHeaders(): Record<string, string> {
  const bearer = asciiOnly(localStorage.getItem('cc_identity_token') || '')
  if (bearer) return { 'Authorization': 'Bearer ' + bearer }
  const key = asciiOnly(localStorage.getItem('cc_api_key') || '')
  if (key) return { 'X-API-Key': key }
  return {}
}

/** Token used for SSE EventSource ?token= query (no header support). */
export function authTokenForSSE(): string {
  return localStorage.getItem('cc_identity_token')
      || localStorage.getItem('cc_api_key')
      || ''
}

/**
 * Query params that authenticate an EventSource, named the way the route
 * expects them.
 *
 * authTokenForSSE() returns "whichever credential this browser holds" and
 * loses which KIND it is. /api/ask can live with that — it looks the ?token=
 * value up against BOTH identity_sessions and users.api_key_hash. /api/coder
 * does not: it promotes ?token= to `Authorization: Bearer` and ?api_key= to
 * `X-API-Key`, and those are two different lookups. An admin-SPA browser
 * holding only cc_api_key therefore 401s if its key is sent as ?token=.
 * This returns the credential under the name that resolves it, mirroring
 * authHeaders()' precedence exactly.
 */
export function authParamsForSSE(): Record<string, string> {
  const bearer = asciiOnly(localStorage.getItem('cc_identity_token') || '')
  if (bearer) return { token: bearer }
  const key = asciiOnly(localStorage.getItem('cc_api_key') || '')
  if (key) return { api_key: key }
  return {}
}

/**
 * An HTTP failure that kept its status and error code.
 *
 * The routes answer refusals with `{ error: { code, message } }` and a
 * meaningful status — NOT_CRANE_HOSTED, NOT_CONFIGURED, BUILDER_OCCUPIED,
 * ENV_FILE_IN_PUSH are each a different thing for the user to do. Flattening
 * them to `new Error(message)` (what req() did for everything) leaves a caller
 * no way to branch, so it renders every refusal as the same red box.
 * Extends Error, so existing `e.message` / `String(e)` callers are unaffected.
 */
export class ApiError extends Error {
  status: number
  code: string
  constructor(message: string, status: number, code: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

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
    // Any 401 from a session-gated route means the session is gone. The old
    // rule matched the body against five known-bad messages and did nothing
    // otherwise -- and the server has twelve, so `Token expired` fell through
    // and an expired session simply rendered a raw error. See sessionExpiry.ts.
    const message = await handleUnauthorized(r, path)
    throw new Error(message ? `Unauthorized: ${message}` : 'Unauthorized')
  }
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    const err = (body as { error?: { message?: string; code?: string } })?.error
    throw new ApiError(err?.message || `HTTP ${r.status}`, r.status, err?.code || 'HTTP_ERROR')
  }
  const data = await r.json().catch(() => ({}))
  return data as T
}

// v2.45.2: coalesce GETs that are already in flight.
//
// Settings mounts several panels at once and three of them independently ask
// for /api/apps in the same tick, so the server built the same payload three
// times per visit — on an instance with dozens of apps that is the single most
// expensive thing the page does.
//
// Deliberately NOT a cache with a TTL: entries live only for the duration of
// the request itself, so the second caller shares a response it would have
// waited for anyway and nobody can ever read a stale one. A GET issued after
// the first settles goes to the network exactly as before.
const inFlightGets = new Map<string, Promise<unknown>>()

const get = <T>(path: string): Promise<T> => {
  const shared = inFlightGets.get(path)
  if (shared) return shared as Promise<T>
  const p = req<T>(path)
  // The stored promise must be the one handed to every caller, including the
  // first — chaining .finally() produces a NEW promise, so storing one and
  // returning the other would let the map outlive the request it tracks.
  const tracked = p.finally(() => { inFlightGets.delete(path) })
  // A shared rejection would otherwise be unhandled for however many callers
  // never attached a catch; each caller attaches its own below.
  tracked.catch(() => {})
  inFlightGets.set(path, tracked)
  return tracked as Promise<T>
}
const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined })
const put  = <T>(path: string, body: unknown) =>
  req<T>(path, { method: 'PUT', body: JSON.stringify(body) })
const patch = <T>(path: string, body: unknown) =>
  req<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
const del  = <T>(path: string) => req<T>(path, { method: 'DELETE' })
const getText = (path: string) =>
  fetch(path, { headers: authHeaders() }).then(r => r.text())

export const adminApi = { get, post, put, patch, del, getText, authHeaders }
