// Pure helpers for the inactivity sign-out (IdleSessionGuard) and the message
// the sign-in screen shows afterwards.

export const IDLE_SIGNED_OUT_KEY = 'cc_signed_out_idle_minutes'
export const LAST_ACTIVITY_KEY = 'cc_last_activity'

export type IdleState = { phase: 'active' } | { phase: 'warn'; secondsLeft: number } | { phase: 'expired' }

export function idleState(nowMs: number, lastActivityMs: number, idleMinutes: number, warnSeconds: number): IdleState {
  const left = Math.ceil((lastActivityMs + idleMinutes * 60_000 - nowMs) / 1000)
  if (left <= 0) return { phase: 'expired' }
  if (left <= warnSeconds) return { phase: 'warn', secondsLeft: left }
  return { phase: 'active' }
}

export function signedOutMessage(minutes: string | null): string | null {
  const n = Number(minutes)
  if (!minutes || !Number.isFinite(n) || n <= 0) return null
  return `You were signed out after ${n} minute${n === 1 ? '' : 's'} of inactivity.`
}

export function formatCountdown(seconds: number): string {
  const s = Math.max(0, seconds)
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

/** Read and clear the one-shot "signed out for inactivity" note. */
export function takeSignedOutMessage(): string | null {
  try {
    const v = sessionStorage.getItem(IDLE_SIGNED_OUT_KEY)
    sessionStorage.removeItem(IDLE_SIGNED_OUT_KEY)
    return signedOutMessage(v)
  } catch {
    return null
  }
}
