import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../../adminApi'
import { formatCountdown, idleState, IDLE_SIGNED_OUT_KEY, LAST_ACTIVITY_KEY, type IdleState } from './idle'

// Signs an identity session out after the policy's idle timeout without user
// input (mouse, keys, touch, scroll), warning two minutes before. Activity is
// shared across tabs through localStorage. The server enforces the same timeout
// on requests (services/sessionPolicy.js); this covers a tab left open whose
// background polling would otherwise keep the session alive.

interface SessionPolicy { idle_minutes: number; warn_before_seconds: number }

const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel'] as const
const read = (k: string) => { try { return localStorage.getItem(k) } catch { return null } }

function markActivity(now = Date.now()) {
  try { localStorage.setItem(LAST_ACTIVITY_KEY, String(now)) } catch { /* storage blocked */ }
  return now
}

export function IdleSessionGuard() {
  const [policy, setPolicy] = useState<SessionPolicy | null>(null)
  const [state, setState] = useState<IdleState>({ phase: 'active' })
  const local = useRef(Date.now())
  const lastWrite = useRef(0)

  useEffect(() => {
    if (!read('cc_identity_token')) return
    adminApi.get<SessionPolicy>('/api/identity/mfa/session-policy').then(setPolicy).catch(() => {})
  }, [])

  useEffect(() => {
    if (!policy) return
    local.current = markActivity()
    const onActivity = () => {
      const now = Date.now()
      local.current = now
      if (now - lastWrite.current > 5000) { lastWrite.current = now; markActivity(now) }
    }
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, onActivity, { passive: true })
    const tick = () => {
      const shared = Number(read(LAST_ACTIVITY_KEY)) || 0
      const s = idleState(Date.now(), Math.max(local.current, shared), policy.idle_minutes, policy.warn_before_seconds)
      setState(prev => (prev.phase === s.phase && (s.phase !== 'warn' || (prev.phase === 'warn' && prev.secondsLeft === s.secondsLeft)) ? prev : s))
      if (s.phase === 'expired') signOut(policy.idle_minutes)
    }
    const id = window.setInterval(tick, 1000)
    return () => {
      window.clearInterval(id)
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, onActivity)
    }
  }, [policy])

  function stay() {
    local.current = markActivity()
    setState({ phase: 'active' })
    adminApi.get('/api/identity/mfa/session-policy').catch(() => {})
  }

  if (state.phase !== 'warn') return null
  return (
    <div role="alertdialog" aria-live="assertive" style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)', zIndex: 10000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div className="setting-card" style={{ maxWidth: 380, background: 'var(--bg, #1a1d27)' }}>
        <h3>Still there?</h3>
        <p style={{ fontSize: '.9rem' }}>
          You will be signed out in {formatCountdown(state.secondsLeft)} because of inactivity.
        </p>
        <button className="btn btn-accent" onClick={stay} autoFocus>Stay signed in</button>
      </div>
    </div>
  )
}

let signingOut = false
function signOut(idleMinutes: number) {
  if (signingOut) return
  signingOut = true
  const token = read('cc_identity_token') || ''
  try { sessionStorage.setItem(IDLE_SIGNED_OUT_KEY, String(idleMinutes)) } catch { /* storage blocked */ }
  try { localStorage.removeItem('cc_identity_token') } catch { /* storage blocked */ }
  const done = () => {
    const here = window.location.pathname + window.location.search
    window.location.replace('/applications' + (here && here !== '/applications' && here !== '/login' ? '?redirect=' + encodeURIComponent(here) : ''))
  }
  fetch('/api/identity/logout', { method: 'POST', headers: { Authorization: `Bearer ${token}` } }).finally(done)
}
