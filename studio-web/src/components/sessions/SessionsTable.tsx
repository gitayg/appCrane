import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

// Sign-in sessions from GET {base} (routes/userSessions.js): the caller's own
// (/api/me/sessions) or, for a platform admin, someone else's
// (/api/users/:id/sessions). DELETE {base}/:id revokes one.
export interface Session {
  id: string
  scope: 'platform' | 'app'
  app: { slug: string; name: string; env: string } | null
  parent_id: string | null
  created_at: string
  last_seen_at: string | null
  expires_at: string
  current: boolean
}

const th = { textAlign: 'left' as const, color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }
const td = { padding: '4px 8px' }
const when = (v: string | null) => (v ? serverDate(v).toLocaleString() : '')

export function SessionsTable({ base, onSignedOut, reloadKey = 0 }: { base: string; onSignedOut?: () => void; reloadKey?: number }) {
  const [sessions, setSessions] = useState<Session[] | null>(null)
  const [error, setError] = useState('')

  function load() {
    adminApi.get<{ sessions: Session[] }>(base)
      .then(r => { setSessions(r.sessions); setError('') })
      .catch(e => { setSessions([]); setError(e instanceof Error ? e.message : 'Request failed') })
  }
  useEffect(load, [base, reloadKey])

  async function revoke(s: Session) {
    const what = s.current ? 'This signs you out here.' : 'That browser has to sign in again.'
    if (!window.confirm(`Revoke this session? ${what}`)) return
    try {
      const r = await adminApi.del<{ signed_out?: boolean }>(`${base}/${encodeURIComponent(s.id)}`)
      if (r?.signed_out && onSignedOut) { onSignedOut(); return }
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed')
    }
  }

  if (sessions === null) return <div style={{ color: 'var(--dim)' }}>Loading...</div>
  return (
    <>
      {error && <div style={{ color: 'var(--red)', fontSize: '.82rem' }}>{error}</div>}
      {sessions.length === 0 && !error && <div style={{ color: 'var(--dim)' }}>No active sessions.</div>}
      {sessions.length > 0 && (
        <table style={{ width: '100%', fontSize: '.84rem', borderCollapse: 'collapse' }}>
          <thead><tr><th style={th}>Where</th><th style={th}>Signed in</th><th style={th}>Last seen</th><th style={th}>Expires</th><th /></tr></thead>
          <tbody>
            {sessions.map(s => (
              <tr key={s.id}>
                <td style={td}>
                  {s.scope === 'app' && s.app ? `${s.app.name}${s.app.env === 'sandbox' ? ' (sandbox)' : ''}` : 'AppCrane'}
                  {s.current && <span style={{ marginLeft: 6, fontSize: '.74rem', color: 'var(--accent)' }}>this browser</span>}
                </td>
                <td style={td}>{when(s.created_at)}</td>
                <td style={td}>{when(s.last_seen_at)}</td>
                <td style={td}>{when(s.expires_at)}</td>
                <td style={{ ...td, textAlign: 'right' }}>
                  <button type="button" className="btn btn-xs" onClick={() => revoke(s)}>{s.current ? 'Sign out' : 'Revoke'}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}
