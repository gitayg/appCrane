import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'

export function Login() {
  const { setKey } = useAuth()
  const [tab, setTab] = useState<'user' | 'key'>('user')
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
      window.location.href = '/login'
    } catch { setError('Connection failed') }
  }

  return (
    <div className="login-wrap">
      <div className="login-box">
        <h2 style={{ marginBottom: 4, fontSize: '1.3rem' }}>Sign In</h2>
        <p style={{ color: 'var(--dim)', marginBottom: 20, fontSize: '.9rem' }}>Choose your login method</p>
        {error && <div className="login-error">{error}</div>}
        <div className="login-tabs">
          <button className={'login-tab' + (tab === 'user' ? ' active' : '')} onClick={() => setTab('user')}>User Login</button>
          <button className={'login-tab' + (tab === 'key' ? ' active' : '')} onClick={() => setTab('key')}>Admin Key</button>
        </div>
        {tab === 'user' ? (
          <div>
            <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 12 }}>Sign in to access your assigned apps</p>
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
          </div>
        ) : (
          <div>
            <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 12 }}>For AppCrane administrators only</p>
            <input
              type="password"
              placeholder="dhk_admin_..."
              value={keyVal}
              onChange={e => setKeyVal(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && doKeyLogin()}
              autoFocus
              style={{ width: '100%', marginBottom: 12 }}
            />
            <button className="btn btn-accent" onClick={doKeyLogin} style={{ width: '100%', padding: 10 }}>Sign In with Admin Key</button>
          </div>
        )}
      </div>
    </div>
  )
}
