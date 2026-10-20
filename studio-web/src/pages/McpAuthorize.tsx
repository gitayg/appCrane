import { useEffect, useState, type CSSProperties } from 'react'
import { adminApi } from '../adminApi'
import { useMe } from '../hooks/useMe'

interface AuthRequest {
  client_name: string
  redirect_uri: string
  redirect_host: string | null
  loopback: boolean
  scope: string
  read_only_requested: boolean
  expires_at: string
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
        decision === 'approve' ? { decision, read_only: readOnly } : { decision },
      )
      window.location.assign(r.redirect_to)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  if (error && !req) {
    return <div style={card}><h1 style={{ fontSize: '1.15rem', marginTop: 0 }}>Connection request</h1><p role="alert">{error}</p></div>
  }
  if (!req) return <div style={card}>Loading...</div>

  return (
    <div style={card}>
      <h1 style={{ fontSize: '1.15rem', marginTop: 0 }}>Connect {req.client_name} to AppCrane?</h1>
      <p style={{ fontSize: '.88rem' }}>
        <strong>{req.client_name}</strong> wants to use AppCrane's MCP tools as
        {' '}<strong>{me?.user?.name || 'you'}</strong>, on the apps you own.
      </p>
      <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '.85rem', margin: '12px 0' }}>
        <dt style={{ color: 'var(--dim)' }}>Returns to</dt>
        <dd style={{ margin: 0, fontFamily: 'monospace', wordBreak: 'break-all' }}>{req.redirect_host || req.redirect_uri}</dd>
        <dt style={{ color: 'var(--dim)' }}>Access</dt>
        <dd style={{ margin: 0 }}>{req.read_only_requested ? 'Read-only (mcp:read)' : 'Read and change (mcp)'}</dd>
      </dl>
      {req.loopback && (
        <p role="note" style={{ fontSize: '.8rem', color: 'var(--yellow-text, #a16207)' }}>
          This app returns to a program on your own computer ({req.redirect_host}). Approve only if you just started
          this connection yourself, for example from Claude Code.
        </p>
      )}
      {!req.read_only_requested && (
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '.85rem', margin: '12px 0' }}>
          <input type="checkbox" checked={readOnly} onChange={e => setReadOnly(e.target.checked)} />
          Read-only: allow reading, refuse every change (deploys, env vars, access)
        </label>
      )}
      {error && <p role="alert" style={{ color: 'var(--red)', fontSize: '.82rem' }}>{error}</p>}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
        <button type="button" className="btn" onClick={() => decide('deny')} disabled={busy}>Deny</button>
        <button type="button" className="btn btn-primary" onClick={() => decide('approve')} disabled={busy}>Approve</button>
      </div>
    </div>
  )
}
