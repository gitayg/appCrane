/**
 * What GET /api/apps/:slug/health/:env says about whether the app viewer
 * should show the app or a status panel. `last_incident` and `unstable` come
 * from the restart tracker and may be absent; absent means no reason line.
 */
export interface EnvHealthResponse {
  env: string
  config?: { interval_sec?: number; fail_threshold?: number; down_threshold?: number; enabled?: number } | null
  state?: { consecutive_fails?: number; last_check_at?: string | null; last_status?: number | null; is_down?: number } | null
  unstable?: boolean
  last_incident?: { summary?: string; created_at?: string; trigger?: string } | null
}

export type EnvPhase = 'checking' | 'up' | 'unstable' | 'restarting' | 'down' | 'unknown'

export interface EnvStatus {
  phase: EnvPhase
  /** Show the panel instead of the iframe. */
  block: boolean
  reason: string | null
  /** Seconds until the health checker looks again, when it can be told. */
  nextCheckSec: number | null
}

// SQLite datetime('now') is UTC without a zone: "2026-11-24 14:05:09".
function parseDbTime(s: string | null | undefined): number | null {
  if (!s) return null
  const t = Date.parse(s.includes('T') ? s : `${s.replace(' ', 'T')}Z`)
  return Number.isFinite(t) ? t : null
}

export function deriveEnvStatus(h: EnvHealthResponse | null, now = Date.now()): EnvStatus {
  const none: EnvStatus = { phase: 'unknown', block: false, reason: null, nextCheckSec: null }
  if (!h || !h.state || h.config?.enabled === 0) return none
  const reason = h.last_incident?.summary?.trim() || null
  const interval = h.config?.interval_sec ?? 30
  const last = parseDbTime(h.state.last_check_at)
  const nextCheckSec = last == null ? null : Math.max(5, Math.round((last + interval * 1000 - now) / 1000))
  const fails = h.state.consecutive_fails ?? 0
  if (h.state.is_down) return { phase: 'down', block: true, reason, nextCheckSec }
  // At fail_threshold the health checker restarts the container.
  if (fails >= (h.config?.fail_threshold ?? 3)) return { phase: 'restarting', block: true, reason, nextCheckSec }
  if (h.unstable) return { phase: 'unstable', block: false, reason, nextCheckSec }
  return { phase: 'up', block: false, reason: null, nextCheckSec }
}

const ENV_LABEL: Record<string, string> = { production: 'Production', sandbox: 'Sandbox' }

/** "Sandbox restarting: memory limit hit, checking again in ~30s" */
export function statusHeadline(env: string, s: EnvStatus): string {
  const label = ENV_LABEL[env] || env
  const what = s.phase === 'down' ? `${label} is down`
    : s.phase === 'restarting' ? `${label} restarting`
    : s.phase === 'unstable' ? `${label} keeps restarting`
    : `${label} is not answering`
  return s.reason ? `${what}: ${s.reason}` : what
}

/**
 * Whether a same-origin page the iframe loaded is AppCrane's "unavailable"
 * page (Caddy's own, or AppCrane's crash page) rather than the app. A
 * cross-origin frame cannot be read and counts as loaded.
 */
export function frameShowsUnavailable(frame: HTMLIFrameElement | null): boolean {
  try {
    const doc = frame?.contentDocument
    if (!doc) return false
    if (doc.querySelector('meta[name="appcrane-unavailable"]')) return true
    return / is unavailable$/.test(doc.title || '') && !!doc.querySelector('a[href="/dashboard"]')
  } catch {
    return false
  }
}
