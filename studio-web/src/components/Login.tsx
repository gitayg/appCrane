import { useEffect, useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { isSafeRedirect } from '../utils/safeRedirect'

/**
 * v2.7.8: the cc_token cookie is now httpOnly and set entirely by the
 * server — on the password-login response, the set-password response, and
 * the OIDC/SAML callback redirects. The SPA no longer writes it (it can't
 * read an httpOnly cookie anyway); AdminApp re-establishes it on load via
 * POST /api/identity/refresh-cookie. So there's no client-side setAuthCookie.
 */

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
      // Relative, not origin-prefixed: v2.38.0 validates this server-side and
      // an absolute URL — even our own origin — is refused, which silently
      // dropped the deep link and fell back to /launch anyway.
      || '/launch'
    window.location.href = '/api/auth/oidc/start?redirect=' + encodeURIComponent(redirect)
  }
  function startSaml() {
    const redirect = new URLSearchParams(window.location.search).get('redirect')
      // Relative, not origin-prefixed: v2.38.0 validates this server-side and
      // an absolute URL — even our own origin — is refused, which silently
      // dropped the deep link and fell back to /launch anyway.
      || '/launch'
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
      // cc_token cookie was already set httpOnly by the SSO callback redirect.
      //
      // Scrub the token from the address bar BEFORE navigating anywhere.
      // Referrer-Policy is strict-origin-when-cross-origin, so a SAME-ORIGIN
      // hop sends the FULL current URL as Referer — and tenant apps are served
      // same-origin at /<slug>. Following a deep link with ?oidc_token= still
      // in the URL hands that app's container a live platform session token in
      // its access logs, which an attacker can harvest by deploying an app and
      // sending victims /login?redirect=/theirapp/.
      //
      // This was unreachable until v2.38.0: the SSO callbacks only ever
      // forwarded absolute `http…` values, which isSafeRedirect rejects, so the
      // scrubbing else-branch always ran. Restoring relative deep links made
      // the other branch live, so the scrub has to precede both.
      const url = new URL(window.location.href)
      url.searchParams.delete('oidc_token')
      window.history.replaceState({}, '', url.pathname + url.search + url.hash)

      const redirect = params.get('redirect')
      // v2.35.0: `//attacker.com` passes startsWith('/') — see safeRedirect.ts.
      if (isSafeRedirect(redirect)) {
        window.location.replace(redirect as string)
      } else {
        url.searchParams.delete('redirect')
        window.location.replace(url.pathname + url.search + url.hash)
      }
    }
  }, [])

  function postLoginRedirect() {
    const redirect = new URLSearchParams(window.location.search).get('redirect')
    if (isSafeRedirect(redirect)) {
      window.location.replace(redirect as string)
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
      // cc_token cookie was already set httpOnly on the login response.
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
