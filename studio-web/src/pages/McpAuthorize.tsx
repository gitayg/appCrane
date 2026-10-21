import { useEffect, useState, type CSSProperties } from 'react'
import { adminApi, ApiError } from '../adminApi'
import { useMe } from '../hooks/useMe'
import { PasswordInput } from '../components/secret/PasswordInput'

interface AuthRequest {
  client_name: string
  client_verified: boolean
  redirect_uri: string
  redirect_host: string | null
  loopback: boolean
  scope: string
  read_only_requested: boolean
  expires_at: string
  access: { role: string | null; lines_full: string[]; lines_read_only: string[]; lifetime_days: number }
  reauth: { required: boolean; reason: 'api_key' | 'view_as' | 'stale_session' | null; has_password: boolean; fresh_minutes: number }
}

const card: CSSProperties = {
  maxWidth: 480, margin: '48px auto', padding: 24, background: 'var(--surface)',
  border: '1px solid var(--border)', borderRadius: 12, boxShadow: 'var(--shadow)',
}

/**
 * MCP OAuth consent screen (/mcp/authorize?request=...). /oauth/authorize
 * validated the client and its redirect URI and sends the signed-in user here;
 * the decision goes to POST /api/oauth/authorize-requests/:id and the browser
 * then follows the returned redirect back to the client.
 */
export function McpAuthorize() {
  const me = useMe()
  const id = new URLSearchParams(window.location.search).get('request') || ''
  const [req, setReq] = useState<AuthRequest | null>(null)
  const [error, setError] = useState('')
  const [readOnly, setReadOnly] = useState(false)
  const [busy, setBusy] = useState(false)
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (!id) { setError('This page needs a connection request. Start again from the app.'); return }
    adminApi.get<AuthRequest>(`/api/oauth/authorize-requests/${encodeURIComponent(id)}`)
      .then(r => { setReq(r); setReadOnly(r.read_only_requested) })
      .catch(e => setError(e?.message || 'Could not load the connection request'))
  }, [id])

  const decide = async (decision: 'approve' | 'deny') => {
    setBusy(true)
    setError('')
    try {
      const r = await adminApi.post<{ redirect_to: string }>(
        `/api/oauth/authorize-requests/${encodeURIComponent(id)}`,
        decision === 'approve' ? { decision, read_only: readOnly, ...(password ? { password } : {}) } : { decision },
      )
      window.location.assign(r.redirect_to)
    } catch (e) {
      if (e instanceof ApiError && e.code === 'REAUTH_REQUIRED' && req) setReq({ ...req, reauth: { ...req.reauth, required: true } })
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  // Sign in again: end this session and come back to the same request.
  const signInAgain = async () => {
    try { await adminApi.post('/api/identity/logout', {}) } catch (_) { /* the session may already be gone */ }
    try { localStorage.removeItem('cc_identity_token') } catch (_) { /* storage blocked */ }
    window.location.assign(`/login?redirect=${encodeURIComponent(window.location.pathname + window.location.search)}`)
  }

  if (error && !req) {
    return <div style={card}><h1 style={{ fontSize: '1.15rem', marginTop: 0 }}>Connection request</h1><p role="alert">{error}</p></div>
  }
  if (!req) return <div style={card}>Loading...</div>

  const effectiveReadOnly = req.read_only_requested || readOnly
  const lines = effectiveReadOnly ? req.access.lines_read_only : req.access.lines_full
  const r = req.reauth
  return (
    <div style={card}>
      <h1 style={{ fontSize: '1.15rem', marginTop: 0 }}>Connect {req.client_name} to AppCrane?</h1>
      {!req.client_verified && (
        <p role="note" style={{ fontSize: '.8rem', margin: '0 0 10px', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--yellow-text, #a16207)', color: 'var(--yellow-text, #a16207)' }}>
          <strong>Unverified app.</strong> Anyone can register an app under any name, so "{req.client_name}" is only what it calls
          itself. Check where it returns to below before you approve.
        </p>
      )}
      <p style={{ fontSize: '.88rem', margin: '0 0 6px' }}>
        It sends you back to <strong style={{ fontFamily: 'monospace', fontSize: '1rem', wordBreak: 'break-all' }}>{req.redirect_host || req.redirect_uri}</strong>
      </p>
      <p style={{ fontSize: '.75rem', fontFamily: 'monospace', color: 'var(--dim)', wordBreak: 'break-all', margin: '0 0 12px' }}>{req.redirect_uri}</p>
      <p style={{ fontSize: '.88rem', margin: '0 0 4px' }}>
        If you approve, it can act as <strong>{me?.user?.name || 'you'}</strong>{req.access.role === 'platform_admin' ? ', a platform admin,' : ''} with
        {effectiveReadOnly ? ' read-only (mcp:read)' : ' read and change (mcp)'} access to:
      </p>
      <ul style={{ fontSize: '.85rem', margin: '0 0 12px', paddingLeft: 20 }}>
        {lines.map(l => <li key={l} style={{ margin: '3px 0' }}>{l}</li>)}
      </ul>
      {req.loopback && (
        <p role="note" style={{ fontSize: '.8rem', color: 'var(--yellow-text, #a16207)' }}>
          This app returns to a program on your own computer ({req.redirect_host}). Approve only if you just started
          this connection yourself, for example from Claude Code.
        </p>
      )}
      {!req.read_only_requested && (
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '.85rem', margin: '12px 0' }}>
          <input type="checkbox" checked={readOnly} onChange={e => setReadOnly(e.target.checked)} />
          Read-only: allow reading, refuse every change and every plaintext secret (deploys, env vars, access, secret values, container files)
        </label>
      )}
      {r.required && (
        <div role="note" style={{ fontSize: '.82rem', margin: '12px 0', padding: '8px 10px', borderRadius: 6, background: 'var(--surface2)' }}>
          {r.reason === 'api_key' ? (
            <p style={{ margin: 0 }}>You are signed in with an API key, which cannot approve a connection. Sign in with your password or SSO to approve.</p>
          ) : r.reason === 'view_as' ? (
            <p style={{ margin: 0 }}>You are viewing AppCrane as another role. Stop viewing as before you approve.</p>
          ) : (
            <p style={{ margin: '0 0 6px' }}>Confirm it is you: approving needs a sign-in from the last {r.fresh_minutes} minutes.</p>
          )}
          {r.reason === 'stale_session' && r.has_password && (
            <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              Password
              <PasswordInput label="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} style={{ flex: 1 }} />
            </label>
          )}
          {r.reason !== 'view_as' && (
            <button type="button" className="btn btn-xs" style={{ marginTop: 6 }} onClick={signInAgain} disabled={busy}>Sign in again</button>
          )}
        </div>
      )}
      {error && <p role="alert" style={{ color: 'var(--red)', fontSize: '.82rem' }}>{error}</p>}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
        <button type="button" className="btn" onClick={() => decide('deny')} disabled={busy}>Deny</button>
        <button type="button" className="btn btn-primary" onClick={() => decide('approve')}
          disabled={busy || (r.required && !(r.reason === 'stale_session' && r.has_password && password))}>Approve</button>
      </div>
    </div>
  )
}
