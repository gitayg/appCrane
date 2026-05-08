import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'

/**
 * v2.4.0 — unified login screen.
 *
 * Email/username + password is the only first-class path now. The
 * `dhk_admin_*` paste box is demoted to a small "Have an API key?"
 * disclosure for legacy / break-glass cases, and is intended to be
 * removed entirely once every admin has set a password.
 *
 * For admins who land here without a password yet (e.g. fresh installs
 * where the bootstrap admin's password_hash is still NULL), the helper
 * text below the form points them at:
 *   1. Click "Have an API key?", paste their dhk_admin_* once
 *   2. After login, hit POST /api/identity/set-password to bridge to
 *      Bearer auth, then log out and back in with email + password
 */
export function Login() {
  const { setKey } = useAuth()
  const [showKey, setShowKey] = useState(false)
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [keyVal, setKeyVal] = useState('')
  const [error, setError] = useState('')

  const doKeyLogin = () => {
    if (!keyVal.trim()) return
    setKey(keyVal.trim())
    window.location.reload()
  }

  const doPassLogin = async () => {
    if (!login || !password) return
    setError('')
    try {
      const res = await fetch('/api/identity/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login, password }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error?.message || 'Login failed'); return }
      localStorage.setItem('cc_identity_token', data.token)
      window.location.reload()
    } catch { setError('Connection failed') }
  }

  return (
    <div className="login-wrap">
      <div className="login-box">
        <h2 style={{ marginBottom: 4, fontSize: '1.3rem' }}>Sign In</h2>
        <p style={{ color: 'var(--dim)', marginBottom: 20, fontSize: '.9rem' }}>
          Email or username and password.
        </p>
        {error && <div className="login-error">{error}</div>}

        <input
          type="text"
          placeholder="Email or username"
          value={login}
          onChange={e => setLogin(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && document.getElementById('loginPass')?.focus()}
          autoFocus
          style={{ width: '100%', marginBottom: 8 }}
        />
        <input
          id="loginPass"
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doPassLogin()}
          style={{ width: '100%', marginBottom: 12 }}
        />
        <button className="btn btn-accent" onClick={doPassLogin} style={{ width: '100%', padding: 10 }}>Sign In</button>

        {!showKey ? (
          <p style={{ marginTop: 18, marginBottom: 0, fontSize: '.78rem', color: 'var(--dim)', textAlign: 'center' }}>
            <button
              type="button"
              className="login-key-link"
              onClick={() => setShowKey(true)}
              style={{ background: 'none', border: 'none', color: 'var(--dim)', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit' }}
            >Have an API key? Sign in with it once and set a password.</button>
          </p>
        ) : (
          <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--border, #333)' }}>
            <p style={{ color: 'var(--dim)', fontSize: '.78rem', marginBottom: 8 }}>
              Legacy / break-glass. After signing in, go to your profile to set a password — future logins will use email + password.
            </p>
            <input
              type="password"
              placeholder="dhk_admin_… or dhk_user_…"
              value={keyVal}
              onChange={e => setKeyVal(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && doKeyLogin()}
              style={{ width: '100%', marginBottom: 10, fontFamily: 'monospace', fontSize: '.85rem' }}
            />
            <button className="btn" onClick={doKeyLogin} style={{ width: '100%', padding: 8 }}>Sign in with key</button>
          </div>
        )}
      </div>
    </div>
  )
}
