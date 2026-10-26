import { useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

interface Props {
  user: { id: number; name: string; role: string; api_key_expires_at?: string | null; api_key_expired?: number | boolean }
  onRotated: () => void
}

// Users page: when a user's API key expires, and an admin Rotate
// (POST /api/users/:id/regenerate-key). Platform admins' keys are rotated by
// their owner (Settings > Account) or `crane regenerate-key` on the server.
export function UserApiKeyCell({ user, onRotated }: Props) {
  const [busy, setBusy] = useState(false)
  const [shown, setShown] = useState<string | null>(null)
  const ms = user.api_key_expires_at ? serverDate(user.api_key_expires_at).getTime() : NaN
  const expired = !!user.api_key_expired || (Number.isFinite(ms) && ms <= Date.now())
  const soon = !expired && Number.isFinite(ms) && ms - Date.now() <= 14 * 86_400_000

  async function rotate() {
    if (!confirm(`Rotate ${user.name}'s API key?\n\nThe current key stops working immediately and their dashboard sessions are signed out. The new key is shown once.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ api_key?: string }>(`/api/users/${user.id}/regenerate-key?confirm=true`, {})
      if (!r.api_key) throw new Error('Server returned no key')
      setShown(r.api_key)
      onRotated()
    } catch (e) {
      alert('Rotate failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  return (
    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center', whiteSpace: 'nowrap' }}>
      <span
        style={{ fontSize: '0.8rem', color: expired ? 'var(--red)' : soon ? 'var(--yellow)' : 'var(--dim)' }}
        title={Number.isFinite(ms) ? serverDate(user.api_key_expires_at!).toLocaleString() : 'No expiry recorded'}
      >
        {Number.isFinite(ms) ? `${expired ? 'expired' : 'expires'} ${serverDate(user.api_key_expires_at!).toLocaleDateString()}` : 'no key'}
      </span>
      {user.role !== 'platform_admin' && (
        <button className="btn btn-xs" onClick={rotate} disabled={busy}>Rotate</button>
      )}
      {shown && (
        <div onClick={() => setShown(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div onClick={e => e.stopPropagation()} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 24, maxWidth: 560, width: '92%', whiteSpace: 'normal' }}>
            <h3 style={{ margin: '0 0 8px' }}>New API key for {user.name}</h3>
            <code style={{ display: 'block', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', fontFamily: 'monospace', wordBreak: 'break-all', userSelect: 'all' }}>{shown}</code>
            <p style={{ fontSize: '.8rem', color: 'var(--yellow)', margin: '10px 0' }}>Shown once. Send it to the user over a secure channel; the old key no longer works.</p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button className="btn" onClick={() => navigator.clipboard.writeText(shown).catch(() => {})}>Copy</button>
              <button className="btn" onClick={() => setShown(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </span>
  )
}
