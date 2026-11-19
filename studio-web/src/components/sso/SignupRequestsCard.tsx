import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

interface SignupRequest {
  id: number
  email: string
  name: string | null
  status: 'pending' | 'approved' | 'denied'
  requested_at: string
  last_seen_at: string
  decided_by_name: string | null
}

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

/** Settings → Security: people who signed in through SSO from outside the allowed list. */
export function SignupRequestsCard() {
  const [status, setStatus] = useState<SignupRequest['status']>('pending')
  const [rows, setRows] = useState<SignupRequest[] | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState<number | null>(null)

  function load(s = status) {
    adminApi.get<{ requests: SignupRequest[] }>(`/api/auth/oidc/signup-requests?status=${s}`)
      .then(r => setRows(r?.requests ?? []))
      .catch(e => setMsg(String(e?.message || e)))
  }
  useEffect(() => { load(status) }, [status])

  async function decide(r: SignupRequest, action: 'approve' | 'deny') {
    setBusy(r.id)
    setMsg('')
    try {
      await adminApi.post(`/api/auth/oidc/signup-requests/${r.id}/${action}`, {})
      setMsg(action === 'approve' ? `${r.email} can now sign in.` : `${r.email} was declined.`)
      load()
    } catch (e) {
      setMsg((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="setting-card">
      <h3>Sign-up requests</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        People who signed in with SSO but are not on the "Join without approval" list. Approving creates their
        account with the user role; they sign in again to get in.
      </p>
      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        {(['pending', 'approved', 'denied'] as const).map(s => (
          <button key={s} className={s === status ? 'btn btn-accent' : 'btn'} onClick={() => setStatus(s)}>
            {s[0].toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      {rows && rows.length === 0 && <p style={dim}>No {status} requests.</p>}
      {rows && rows.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                <th style={{ padding: '4px 8px' }}>Email</th>
                <th style={{ padding: '4px 8px' }}>Name</th>
                <th style={{ padding: '4px 8px' }}>Requested</th>
                <th style={{ padding: '4px 8px' }}>{status === 'pending' ? '' : 'Decided by'}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}>{r.email}</td>
                  <td style={{ padding: '6px 8px' }}>{r.name || ''}</td>
                  <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>{serverDate(r.requested_at).toLocaleString()}</td>
                  <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                    {r.status !== 'approved' && (
                      <button className="btn btn-accent" disabled={busy === r.id} onClick={() => decide(r, 'approve')}>Approve</button>
                    )}
                    {r.status === 'pending' && (
                      <button className="btn" style={{ marginLeft: 6 }} disabled={busy === r.id} onClick={() => decide(r, 'deny')}>Deny</button>
                    )}
                    {r.status !== 'pending' && <span style={{ ...dim, marginLeft: 6 }}>{r.decided_by_name || ''}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {msg && <p style={{ ...dim, marginTop: 8 }}>{msg}</p>}
    </div>
  )
}
