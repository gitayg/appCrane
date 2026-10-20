// Browser error reporter: uncaught errors and unhandled rejections go to
// POST /api/client-errors as a compact, scrubbed report. Installed once per
// page by main.tsx (admin SPA) and by the topbar bundle's entry (sign-in page);
// whichever runs first wins, the other is a no-op.
//
// Never sent: tokens, localStorage contents, form values, query strings or
// fragments. The server scrubs again; this is the first of two passes.

export type ClientErrorSource = 'admin' | 'topbar' | 'login'

interface InstallOptions {
  source: ClientErrorSource
  headers?: () => Record<string, string>
}

interface ReporterState {
  source: ClientErrorSource
  headers?: () => Record<string, string>
  version: string | null
  seen: Set<string>
  sentAt: number[]
  total: number
}

const ENDPOINT = '/api/client-errors'
export const MAX_PER_MINUTE = 5
export const MAX_PER_PAGE = 30
const MESSAGE_MAX = 500
const STACK_MAX = 4000

const GLOBAL_KEY = '__craneClientErrors'

const SCRUBBERS: [RegExp, string | ((m: string) => string)][] = [
  [/\bdhk_[A-Za-z0-9_-]+/g, 'dhk_[redacted]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g, '[redacted-jwt]'],
  [/((?:https?:)?\/\/[^\s?#'"()<>]+|\/[^\s?#'"()<>]*)[?#][^\s'"()<>]*/g, '$1'],
  [/\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)["']?\s*[:=]\s*["']?)[^\s"'&,;]+/gi, '$1[redacted]'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]'],
  [/\b[0-9a-fA-F]{32,}\b/g, '[redacted-hex]'],
  [/[A-Za-z0-9+_-]{40,}={0,2}/g, m => (/\d/.test(m) && /[A-Za-z]/.test(m) ? '[redacted-b64]' : m)],
]

export function scrub(value: string): string {
  let s = value
  for (const [re, rep] of SCRUBBERS) s = s.replace(re, rep as string)
  return s
}

export function stripQuery(pathOrUrl: string): string {
  return pathOrUrl.split(/[?#]/, 1)[0]
}

function state(): ReporterState | undefined {
  return (window as unknown as Record<string, ReporterState | undefined>)[GLOBAL_KEY]
}

export function setClientErrorVersion(version: string) {
  const s = state()
  if (s && version) s.version = version.replace(/^v/, '').slice(0, 40)
}

function appSlug(): string | null {
  const el = document.querySelector('crane-app-topbar[app-slug]')
  const slug = el?.getAttribute('app-slug') || ''
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(slug) ? slug : null
}

function describe(err: unknown, fallback?: string): { message: string; stack: string } {
  if (err instanceof Error) return { message: err.message || err.name || 'Error', stack: err.stack || '' }
  if (typeof err === 'string') return { message: err, stack: '' }
  if (fallback) return { message: fallback, stack: '' }
  try { return { message: 'Non-Error thrown: ' + String(err), stack: '' } } catch { return { message: 'Non-Error thrown', stack: '' } }
}

function topFrame(stack: string): string {
  for (const line of stack.split('\n')) {
    const t = line.trim()
    if (/^at\s|@|:\d+:\d+/.test(t)) return t
  }
  return ''
}

function allowed(s: ReporterState, now: number): boolean {
  if (s.total >= MAX_PER_PAGE) return false
  s.sentAt = s.sentAt.filter(t => now - t < 60_000)
  if (s.sentAt.length >= MAX_PER_MINUTE) return false
  s.sentAt.push(now)
  s.total++
  return true
}

function send(s: ReporterState, body: string) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  try { Object.assign(headers, s.headers?.() || {}) } catch { /* reporting must never throw */ }
  if (typeof fetch === 'function') {
    fetch(ENDPOINT, { method: 'POST', keepalive: true, credentials: 'same-origin', headers, body }).catch(() => {})
    return
  }
  if (navigator.sendBeacon) navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'application/json' }))
}

export function reportClientError(err: unknown, fallbackMessage?: string) {
  const s = state()
  if (!s) return
  try {
    const raw = describe(err, fallbackMessage)
    const message = scrub(raw.message).slice(0, MESSAGE_MAX)
    const stack = scrub(raw.stack).slice(0, STACK_MAX)
    const key = message + '\n' + topFrame(stack)
    if (s.seen.has(key)) return
    s.seen.add(key)
    if (!allowed(s, Date.now())) return
    send(s, JSON.stringify({
      message,
      stack,
      page: stripQuery(window.location.pathname),
      version: s.version,
      userAgent: navigator.userAgent.slice(0, 300),
      ts: new Date().toISOString(),
      source: s.source,
      appSlug: appSlug(),
    }))
  } catch { /* reporting must never throw */ }
}

export function installClientErrorReporter(opts: InstallOptions) {
  if (typeof window === 'undefined' || state()) return
  const s: ReporterState = { source: opts.source, headers: opts.headers, version: null, seen: new Set(), sentAt: [], total: 0 }
  ;(window as unknown as Record<string, ReporterState>)[GLOBAL_KEY] = s
  window.addEventListener('error', (e: ErrorEvent) => {
    if (!e.error && !e.message) return
    reportClientError(e.error, e.message)
  })
  window.addEventListener('unhandledrejection', (e: PromiseRejectionEvent) => {
    reportClientError(e.reason, 'Unhandled promise rejection')
  })
}
