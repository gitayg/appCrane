import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { SessionsTable } from './SessionsTable'

// Users page (platform admin): see and end a user's sign-in sessions.
// GET/DELETE /api/users/:id/sessions[/:sid] are platform-admin only and audited.
export function UserSessionsButton({ userId, userName }: { userId: number; userName: string }) {
  const [open, setOpen] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [msg, setMsg] = useState('')
  const base = `/api/users/${userId}/sessions`

  async function revokeAll() {
    if (!window.confirm(`Sign ${userName} out everywhere? Every session ends now.`)) return
    try {
      const r = await adminApi.del<{ revoked: number }>(base)
      setMsg(`Ended ${r.revoked} session(s).`)
      setReloadKey(k => k + 1)
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Request failed')
    }
  }

  return (
    <>
      <button type="button" className="btn btn-xs" onClick={() => { setMsg(''); setOpen(true) }} title="See and end this user's sign-in sessions">Sessions</button>
      {open && (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onClick={() => setOpen(false)}
        >
          <div className="setting-card" style={{ width: 'min(760px, 92vw)', maxHeight: '80vh', overflow: 'auto' }} onClick={e => e.stopPropagation()}>
            <h3>Sessions of {userName}</h3>
            <SessionsTable base={base} reloadKey={reloadKey} />
            {msg && <div style={{ marginTop: 8, fontSize: '.82rem', color: 'var(--dim)' }}>{msg}</div>}
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 12 }}>
              <button type="button" className="btn btn-red btn-sm" onClick={revokeAll}>Sign out everywhere</button>
              <button type="button" className="btn btn-sm" onClick={() => setOpen(false)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
