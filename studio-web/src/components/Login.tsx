import { useEffect, useState } from 'react'
import { useAuth } from '../hooks/useAuth'

/**
 * Set the cc_token cookie that Caddy's forward_auth on per-app routes
 * reads via /api/identity/verify. localStorage alone isn't enough — that
 * only travels with explicit fetches, not with browser navigation into
 * proxied apps. SameSite=Lax so it survives the first-party navigation
 * but doesn't leak across cross-site requests; Secure when on HTTPS.
 *
 * Mirrors docs/login.html's setAuthCookie before v2.5.14 collapsed the
 * dual-login flow into the SPA. Without this, post-SPA-login navigation
 * to a Caddy-proxied app would fail forward_auth and produce the
 * /{slug}/login loop the operator reported.
 */
function setAuthCookie(token: string) {
  const secure = window.location.protocol === 'https:' ? '; Secure' : ''
  document.cookie =
    'cc_token=' + encodeURIComponent(token) +
    '; Path=/; Max-Age=' + (7 * 24 * 3600) + '; SameSite=Lax' + secure
}

/**
 * v2.5.14 — single canonical login.
 *
 * Replaces the dual /login (docs/login.html) + SPA-Login.tsx duplication.
 * Email/username + password is the first-class path; the API-key paste
 * box is a small disclosure for legacy / break-glass cases.
 *
 * SSO callback handling absorbed from docs/login.html so the OIDC and
 * SAML flows still work without the legacy HTML page in the loop:
 *   - ?oidc_token=… (also used by SAML callbacks) → store + clean URL
 *     + go to ?redirect= or /applications
 *   - ?sso_error=… / ?saml_error=… → render inline
 *   - ?redirect=… → preserved and used after successful password login
 */
interface SsoCfg { enabled?: boolean; provider_name?: string }

export function Login() {
  const { setKey } = useAuth()
  const [showKey, setShowKey] = useState(false)
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [keyVal, setKeyVal] = useState('')
  const [error, setError] = useState('')
  // v2.5.15: SSO entry-point buttons. Fetched from the public
  // /api/auth/oidc/config and /api/auth/saml/config, shown only when the
  // provider is enabled. Clicking goes through /api/auth/{oidc,saml}/start
  // which redirects to the IdP; the IdP comes back to /login (now
  // forwarded to /applications) with ?oidc_token=… that the useEffect
  // above absorbs.
  const [oidc, setOidc] = useState<SsoCfg>({})
  const [saml, setSaml] = useState<SsoCfg>({})
  // v2.7.0: SSO-only mode. When a platform admin has required SSO, hide the
  // password form and the API-key break-glass paste entirely — the IdP
  // button is the only browser login path (full lockdown).
  // v2.7.3: tri-state (null = policy not yet fetched). We must NOT render the
  // password form before we know — otherwise an SSO-only instance briefly
  // flashes the username/password screen until the fetch resolves. While
  // null we render a tiny loading line instead.
  const [ssoOnly, setSsoOnly] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/api/auth/oidc/config').then(r => r.json()).then(setOidc).catch(() => {})
    fetch('/api/auth/saml/config').then(r => r.json()).then(setSaml).catch(() => {})
    fetch('/api/settings/auth_sso_only')
      .then(r => r.json())
      .then(d => setSsoOnly(d?.value === 'true'))
      .catch(() => setSsoOnly(false))
  }, [])

  function startOidc() {
    const redirect = new URLSearchParams(window.location.search).get('redirect')
      || window.location.origin + '/applications'
    window.location.href = '/api/auth/oidc/start?redirect=' + encodeURIComponent(redirect)
  }
  function startSaml() {
    const redirect = new URLSearchParams(window.location.search).get('redirect')
      || window.location.origin + '/applications'
    window.location.href = '/api/auth/saml/start?redirect=' + encodeURIComponent(redirect)
  }

  // Read SSO callback / redirect query params on mount. Both providers
  // hand the bearer back via ?oidc_token=…; we store it as cc_identity_token
  // (same key the unified login uses) and forward to the redirect target.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const ssoErr = params.get('sso_error') || params.get('saml_error')
    if (ssoErr) {
      setError('SSO failed: ' + ssoErr)
      const url = new URL(window.location.href)
      url.searchParams.delete('sso_error')
      url.searchParams.delete('saml_error')
      window.history.replaceState({}, '', url.toString())
      return
    }
    const oidcToken = params.get('oidc_token')
    if (oidcToken) {
      localStorage.setItem('cc_identity_token', oidcToken)
      setAuthCookie(oidcToken)
      const redirect = params.get('redirect')
      if (redirect && redirect.startsWith('/')) {
        window.location.replace(redirect)
      } else {
        // Strip the SSO-token from the URL before reload so it doesn't
        // sit in the address bar / browser history.
        const url = new URL(window.location.href)
        url.searchParams.delete('oidc_token')
        url.searchParams.delete('redirect')
        window.location.replace(url.pathname + url.search + url.hash)
      }
    }
  }, [])

  function postLoginRedirect() {
    const redirect = new URLSearchParams(window.location.search).get('redirect')
    if (redirect && redirect.startsWith('/')) {
      window.location.replace(redirect)
    } else {
      window.location.reload()
    }
  }

  const doKeyLogin = () => {
    if (!keyVal.trim()) return
    setKey(keyVal.trim())
    postLoginRedirect()
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
      setAuthCookie(data.token)
      postLoginRedirect()
    } catch { setError('Connection failed') }
  }

  return (
    <div className="login-wrap">
      <div className="login-box">
        <h2 style={{ marginBottom: 4, fontSize: '1.3rem' }}>Sign In</h2>
        {ssoOnly === null ? (
          // Policy unknown — render nothing actionable yet so we never flash
          // the password form on an SSO-only instance.
          <p style={{ color: 'var(--dim)', marginTop: 16, fontSize: '.9rem' }}>Loading…</p>
        ) : (
        <>
        <p style={{ color: 'var(--dim)', marginBottom: 20, fontSize: '.9rem' }}>
          {ssoOnly ? 'Single sign-on is required for this instance.' : 'Email or username and password.'}
        </p>
        {error && <div className="login-error">{error}</div>}

        {!ssoOnly && (
          <>
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
          </>
        )}

        {(oidc.enabled || saml.enabled) && (
          <div style={{ marginTop: ssoOnly ? 0 : 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {!ssoOnly && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--dim)', fontSize: '.74rem' }}>
                <span style={{ flex: 1, height: 1, background: 'var(--border, #333)' }} />
                <span>or</span>
                <span style={{ flex: 1, height: 1, background: 'var(--border, #333)' }} />
              </div>
            )}
            {oidc.enabled && (
              <button
                type="button"
                className="btn"
                onClick={startOidc}
                style={{ width: '100%', padding: 10 }}
              >Sign in with {oidc.provider_name || 'SSO'}</button>
            )}
            {saml.enabled && (
              <button
                type="button"
                className="btn"
                onClick={startSaml}
                style={{ width: '100%', padding: 10 }}
              >Sign in with {saml.provider_name || 'Okta'}</button>
            )}
          </div>
        )}

        {ssoOnly ? null : !showKey ? (
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
        </>
        )}
      </div>
    </div>
  )
}
