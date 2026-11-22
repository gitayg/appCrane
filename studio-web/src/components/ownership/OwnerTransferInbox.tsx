import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { personLabel, type OwnerTransfer } from './types'

// Nominations waiting for the signed-in person's answer.
export function OwnerTransferInbox({ hideWhenEmpty = false }: { hideWhenEmpty?: boolean }) {
  const [items, setItems] = useState<OwnerTransfer[] | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = useCallback(() => {
    adminApi.get<{ transfers: OwnerTransfer[] }>('/api/owner-transfers/mine')
      .then(d => setItems(d.transfers))
      .catch(e => { setItems([]); setMsg({ text: (e as Error).message, ok: false }) })
  }, [])
  useEffect(() => { load() }, [load])

  async function answer(t: OwnerTransfer, accept: boolean) {
    if (accept && !window.confirm(`Become an owner of ${t.app_name || t.app_slug}? Owners have full control of the app, including who has access.`)) return
    setBusy(t.id)
    setMsg(null)
    try {
      await adminApi.post(`/api/owner-transfers/${t.id}/${accept ? 'accept' : 'decline'}`)
      setMsg({ text: accept ? `You now own ${t.app_name || t.app_slug}.` : 'Nomination declined.', ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(null)
    }
  }

  if (items === null) return null
  if (hideWhenEmpty && items.length === 0) return null
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>Owner requests</h3>
      {msg && <div style={{ marginBottom: 8, color: msg.ok ? 'var(--green)' : 'var(--red)' }}>{msg.text}</div>}
      {items.length === 0 ? (
        <div style={{ color: 'var(--dim)' }}>Nobody has asked you to own an app.</div>
      ) : items.map(t => (
        <div key={t.id} style={{ borderTop: '1px solid var(--border)', padding: '10px 0' }}>
          <div>
            <strong>{t.app_name || t.app_slug}</strong>
            {t.kind === 'orphan' ? ' has no owner.' : ' is being handed over.'}
            {' '}{personLabel(t.nominated_by)} asked you to own it.
          </div>
          {t.note && <div style={{ fontSize: '.85rem', marginTop: 4 }}>Note: {t.note}</div>}
          <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 4 }}>
            Open until {serverDate(t.expires_at).toLocaleString()}
          </div>
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            <button className="btn btn-sm btn-accent" disabled={busy === t.id} onClick={() => answer(t, true)}>Accept</button>
            <button className="btn btn-sm" disabled={busy === t.id} onClick={() => answer(t, false)}>Decline</button>
          </div>
        </div>
      ))}
    </div>
  )
}
