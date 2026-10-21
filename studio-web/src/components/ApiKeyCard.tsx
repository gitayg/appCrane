import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Settings > Account: when the signed-in person's own API key expires, and
// Rotate (POST /api/me/api-key/rotate), which shows the new key once and makes
// the old one stop working immediately. Backed by server/routes/apiKeys.js.

interface KeyState {
  has_key: boolean
  expired: boolean
  issued_at: string | null
  expires_at: string | null
  last_used_at: string | null
  max_age_days: number
}

function fmt(iso: string | null): string {
  if (!iso) return 'unknown'
  const ms = Date.parse(iso)
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString()
}

export function ApiKeyCard() {
  const [state, setState] = useState<KeyState | null>(null)
  const [busy, setBusy] = useState(false)
  const [shown, setShown] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    adminApi.get<KeyState>('/api/me/api-key').then(setState).catch(e => setErr((e as Error).message))
  }, [])

  async function rotate() {
    if (!confirm('Rotate your API key?\n\nThe current key stops working immediately, everywhere you use it (CLI, scripts, agents). The new key is shown once.')) return
    setBusy(true)
    setErr(null)
    try {
      const r = await adminApi.post<KeyState & { api_key?: string }>('/api/me/api-key/rotate', {})
      if (!r.api_key) throw new Error('Server returned no key')
      try {
        if (localStorage.getItem('cc_api_key')) localStorage.setItem('cc_api_key', r.api_key)
      } catch (_) { /* storage unavailable: the person still has the key on screen */ }
      setShown(r.api_key)
      setState({ has_key: r.has_key, expired: r.expired, issued_at: r.issued_at, expires_at: r.expires_at, last_used_at: r.last_used_at, max_age_days: r.max_age_days })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const ms = state?.expires_at ? Date.parse(state.expires_at) : NaN
  const daysLeft = Number.isFinite(ms) ? Math.floor((ms - Date.now()) / 86_400_000) : null
  const colour = state?.expired ? 'var(--red)' : daysLeft != null && daysLeft <= 14 ? 'var(--yellow)' : 'var(--dim)'

  return (
    <div className="setting-card">
      <h3>API key</h3>
      <p className="settings-hint">
        Your personal AppCrane API key (dhk_user_ or dhk_admin_), used by the CLI and scripts.
        {state ? ` Keys expire ${state.max_age_days} days after they are created or rotated; you get an e-mail 14 and 3 days before.` : ''}
      </p>
      {state && (
        <p style={{ fontSize: '.85rem', color: colour, margin: '8px 0' }}>
          {!state.has_key
            ? 'You have no API key.'
            : state.expired
              ? `Expired on ${fmt(state.expires_at)}. Rotate to get a new one.`
              : `Expires on ${fmt(state.expires_at)}${daysLeft != null ? ` (in ${daysLeft} day${daysLeft === 1 ? '' : 's'})` : ''}.`}
          {state.last_used_at ? ` Last used ${fmt(state.last_used_at)}.` : ''}
        </p>
      )}
      <button className="btn" onClick={rotate} disabled={busy || !state}>{busy ? 'Rotating...' : (state?.has_key ? 'Rotate' : 'Create')}</button>
      {err && <p style={{ color: 'var(--red)', fontSize: '.8rem', marginTop: 8 }}>{err}</p>}
      {shown && (
        <div style={{ marginTop: 12 }}>
          <code style={{ display: 'block', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', fontFamily: 'monospace', wordBreak: 'break-all', userSelect: 'all' }}>{shown}</code>
          <p style={{ fontSize: '.8rem', color: 'var(--yellow)', margin: '8px 0' }}>Shown once. Copy it now; the old key no longer works.</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn" onClick={() => navigator.clipboard.writeText(shown).catch(() => {})}>Copy</button>
            <button className="btn" onClick={() => setShown(null)}>Done</button>
          </div>
        </div>
      )}
    </div>
  )
}
