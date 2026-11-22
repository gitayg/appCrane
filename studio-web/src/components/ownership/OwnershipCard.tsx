import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { REASON_LABEL, personLabel, type Ownership } from './types'

interface Props {
  slug: string
  reload?: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

// The app's owners, whether it is orphaned, and the nomination workflow.
// The server decides who may nominate (can_nominate) or assign (can_assign).
export function OwnershipCard({ slug, reload = 0, onMsg }: Props) {
  const [data, setData] = useState<Ownership | null>(null)
  const [email, setEmail] = useState('')
  const [note, setNote] = useState('')
  const [stepDown, setStepDown] = useState(false)
  const [busy, setBusy] = useState(false)
  const base = `/api/apps/${encodeURIComponent(slug)}`

  const load = useCallback(() => {
    adminApi.get<Ownership>(`${base}/ownership`).then(setData).catch(() => setData(null))
  }, [base])

  useEffect(() => { load() }, [load, reload])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setBusy(true)
    try {
      await fn()
      onMsg({ text: ok, ok: true })
      setEmail('')
      setNote('')
      setStepDown(false)
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!data) return null
  const pending = data.pending_transfer
  const isOwner = data.viewer_role === 'owner'

  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>Ownership</h3>
      {data.orphaned ? (
        <div style={{ padding: '8px 10px', borderRadius: 6, background: 'rgba(245,158,11,.12)', color: 'var(--yellow, #f59e0b)', marginBottom: 10 }}>
          <strong>No owner.</strong>{' '}
          {REASON_LABEL[data.orphan?.detail?.reason || 'no-owner'] || 'No active owner'}
          {data.orphan ? `, since ${serverDate(data.orphan.orphaned_at).toLocaleString()}` : ''}.
          {' '}The app keeps running; it needs a named owner.
        </div>
      ) : (
        <div style={{ marginBottom: 10 }}>
          Owner{data.owners.length > 1 ? 's' : ''}: {data.owners.map(o => personLabel(o)).join(', ')}
        </div>
      )}

      {pending && (
        <div style={{ fontSize: '.85rem', marginBottom: 10 }}>
          Waiting for <strong>{personLabel(pending.nominee)}</strong> to accept
          {pending.nominated_by ? ` (nominated by ${personLabel(pending.nominated_by)})` : ''}, until {serverDate(pending.expires_at).toLocaleDateString()}.
          {' '}
          <button className="btn btn-xs" disabled={busy}
            onClick={() => run(() => adminApi.post(`${base}/owner-transfers/${pending.id}/cancel`), 'Nomination cancelled.')}>
            Cancel nomination
          </button>
        </div>
      )}

      {(data.can_nominate || data.can_assign) && !pending && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <input className="input" type="email" placeholder="New owner's e-mail address" value={email}
            onChange={e => setEmail(e.target.value)} disabled={busy} />
          {data.can_nominate && (
            <input className="input" placeholder="Note for them (optional)" value={note} maxLength={500}
              onChange={e => setNote(e.target.value)} disabled={busy} />
          )}
          {isOwner && (
            <label style={{ fontSize: '.85rem' }}>
              <input type="checkbox" checked={stepDown} onChange={e => setStepDown(e.target.checked)} disabled={busy} />
              {' '}Step down to admin when they accept
            </label>
          )}
          <div style={{ display: 'flex', gap: 6 }}>
            {data.can_nominate && (
              <button className="btn btn-sm" disabled={busy || !email.trim()}
                onClick={() => run(() => adminApi.post(`${base}/owner-transfers`, { email: email.trim(), note: note.trim() || undefined, step_down: stepDown || undefined }),
                  'Nomination sent. They will get an e-mail and accept in the dashboard.')}>
                Nominate owner
              </button>
            )}
            {data.can_assign && (
              <button className="btn btn-sm" disabled={busy || !email.trim()}
                onClick={() => {
                  if (!window.confirm(`Make ${email.trim()} an owner of this app now, without asking them?`)) return
                  run(() => adminApi.post(`${base}/owner`, { email: email.trim() }), 'Owner assigned.')
                }}>
                Assign now
              </button>
            )}
          </div>
          <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>
            The nominee accepts or declines on the Owner requests page. Platform admins can assign directly.
          </div>
        </div>
      )}
    </div>
  )
}
