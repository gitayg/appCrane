import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { PasswordInput } from './secret/PasswordInput'

// The signed-in person's own password, via POST /api/identity/set-password.
// The server is the authority: it asks for the current password once one is
// set, enforces the 12-character minimum, refuses an unchanged password, and
// signs out every other session. The checks here only save a round trip.

const MIN_LENGTH = 12

const labelStyle: React.CSSProperties = { fontSize: '.78rem', color: 'var(--dim)', marginBottom: 4, display: 'block' }

interface SetPasswordResponse { ok: boolean; token: string; expires_at: string }

export function passwordFormError(hasPassword: boolean, current: string, next: string, confirm: string): string | null {
  if (hasPassword && !current) return 'Enter your current password.'
  if (next.length < MIN_LENGTH) return `The new password must be at least ${MIN_LENGTH} characters.`
  if (next !== confirm) return 'The new password and its confirmation do not match.'
  if (hasPassword && next === current) return 'The new password must be different from the current one.'
  return null
}

export function ChangePasswordCard() {
  const [hasPassword, setHasPassword] = useState<boolean | null>(null)
  const [ssoOnly, setSsoOnly] = useState<boolean | null>(null)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    adminApi.get<{ user: { has_password?: boolean } }>('/api/auth/me')
      .then(m => setHasPassword(!!m.user.has_password))
      .catch(e => setLoadErr(e instanceof Error ? e.message : 'Could not read your account'))
    adminApi.get<{ value?: string }>('/api/settings/auth_sso_only')
      .then(r => setSsoOnly(r?.value === 'true'))
      .catch(() => setSsoOnly(false))
  }, [])

  async function save() {
    if (busy || hasPassword === null) return
    const err = passwordFormError(hasPassword, current, next, confirm)
    if (err) { setMsg({ ok: false, text: err }); return }
    setBusy(true)
    setMsg(null)
    try {
      const r = await adminApi.post<SetPasswordResponse>('/api/identity/set-password',
        hasPassword ? { current_password: current, password: next } : { password: next })
      // Every earlier session was deleted server-side; this one replaces it,
      // stored where sign-in stores it so this tab stays signed in.
      localStorage.setItem('cc_identity_token', r.token)
      setCurrent('')
      setNext('')
      setConfirm('')
      setMsg({ ok: true, text: hasPassword ? 'Password changed. Your other sessions were signed out.' : 'Password set. You can now sign in with it.' })
      setHasPassword(true)
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Could not change the password' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="setting-card">
      <h3>Password</h3>
      {loadErr && <p style={{ color: 'var(--red)', fontSize: '.85rem' }}>{loadErr}</p>}
      {!loadErr && (hasPassword === null || ssoOnly === null) && <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>Loading…</p>}
      {ssoOnly && (
        <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
          Password sign-in is turned off on this instance; everyone signs in with single sign-on.
          Change your password with your identity provider.
        </p>
      )}
      {ssoOnly === false && hasPassword !== null && (
        <form onSubmit={e => { e.preventDefault(); save() }}>
          <p>
            {hasPassword
              ? 'Changing it signs out every other session you have.'
              : 'You have no password yet. Set one to sign in with your username or email.'}
          </p>
          {hasPassword && (
            <div style={{ marginBottom: 12 }}>
              <label style={labelStyle}>Current password</label>
              <PasswordInput styled label="current password" autoComplete="current-password"
                value={current} onChange={e => setCurrent(e.target.value)} disabled={busy} />
            </div>
          )}
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>New password (at least {MIN_LENGTH} characters)</label>
            <PasswordInput styled label="new password" autoComplete="new-password"
              value={next} onChange={e => setNext(e.target.value)} disabled={busy} />
          </div>
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>Confirm new password</label>
            <PasswordInput styled label="confirm new password" autoComplete="new-password"
              value={confirm} onChange={e => setConfirm(e.target.value)} disabled={busy} />
          </div>
          <div className="save-row">
            <button type="submit" className="btn btn-accent" disabled={busy || !next || !confirm || (hasPassword && !current)}>
              {busy ? 'Saving…' : hasPassword ? 'Change password' : 'Set password'}
            </button>
            {msg && (
              <span role={msg.ok ? 'status' : 'alert'} style={{ marginLeft: 10, fontSize: '.85rem', color: msg.ok ? 'var(--green)' : 'var(--red)' }}>
                {msg.text}
              </span>
            )}
          </div>
        </form>
      )}
    </div>
  )
}
