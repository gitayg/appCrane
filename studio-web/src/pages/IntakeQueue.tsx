import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { ClassificationBadge } from '../components/intake/ClassificationBadge'
import type { IntakeRow } from '../components/intake/types'

type Status = 'pending' | 'approved' | 'rejected' | 'all'

/** Platform admins: apps waiting for security approval before production. */
export function IntakeQueue() {
  const [status, setStatus] = useState<Status>('pending')
  const [items, setItems] = useState<IntakeRow[] | null>(null)
  const [comments, setComments] = useState<Record<number, string>>({})
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = useCallback(() => {
    adminApi.get<{ items: IntakeRow[] }>(`/api/intake/queue?status=${status}`)
      .then(r => setItems(r.items))
      .catch(e => setMsg({ text: (e as Error).message, ok: false }))
  }, [status])
  useEffect(() => { setItems(null); load() }, [load])

  async function review(row: IntakeRow, decision: 'approve' | 'reject') {
    try {
      await adminApi.post(`/api/apps/${encodeURIComponent(row.slug || '')}/intake/review`, { decision, comment: comments[row.app_id] || '' })
      setMsg({ text: `${row.name || row.slug}: ${decision === 'approve' ? 'approved' : 'rejected'}`, ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    }
  }

  return (
    <div>
      <h2 style={{ margin: 0 }}>App intake</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
        New apps answer an intake. Classifications that need approval stay sandbox-only until a platform admin approves them here.
      </p>
      <div style={{ display: 'flex', gap: 6, margin: '8px 0 12px' }}>
        {(['pending', 'approved', 'rejected', 'all'] as Status[]).map(s => (
          <button key={s} className={`btn btn-sm${s === status ? '' : ' btn-dim'}`} onClick={() => setStatus(s)}>{s}</button>
        ))}
      </div>
      {msg && <div style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', marginBottom: 8 }}>{msg.text}</div>}
      {items === null ? 'Loading...' : items.length === 0 ? <span style={{ color: 'var(--dim)' }}>Nothing here.</span> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {items.map(row => (
            <div key={row.app_id} className="am-card">
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <b>{row.name || row.slug}</b>
                <span className="am-mono" style={{ color: 'var(--dim)' }}>{row.slug}</span>
                <ClassificationBadge level={row.data_classification} />
                <span style={{ fontSize: '.75rem', color: 'var(--dim)' }}>{row.status}{row.grandfathered ? ' (grandfathered)' : ''}</span>
              </div>
              <div style={{ fontSize: '.8rem', marginTop: 6, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '2px 10px' }}>
                <span style={{ color: 'var(--dim)' }}>Purpose</span><span>{row.purpose || '-'}</span>
                <span style={{ color: 'var(--dim)' }}>Personal data</span><span>{row.personal_data ? 'yes' : 'no'}</span>
                <span style={{ color: 'var(--dim)' }}>Integrations</span><span>{row.external_integrations || '-'}</span>
                <span style={{ color: 'var(--dim)' }}>Access</span><span>{row.access_notes || '-'}</span>
                <span style={{ color: 'var(--dim)' }}>Submitted</span><span>{row.submitted_at}{row.submitted_by_name ? ` by ${row.submitted_by_name}` : ''}</span>
                {row.review_comment && <><span style={{ color: 'var(--dim)' }}>Review</span><span>{row.review_comment}{row.reviewed_by_name ? ` (${row.reviewed_by_name})` : ''}</span></>}
              </div>
              {row.status !== 'approved' || status === 'all' ? (
                <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                  <input className="am-input" style={{ flex: 1, minWidth: 180 }} placeholder="Comment (required to reject)"
                    value={comments[row.app_id] || ''} onChange={e => setComments(c => ({ ...c, [row.app_id]: e.target.value }))} />
                  {row.status !== 'approved' && <button className="btn btn-sm" onClick={() => review(row, 'approve')}>Approve</button>}
                  {row.status !== 'rejected' && <button className="btn btn-sm btn-dim" onClick={() => review(row, 'reject')}>Reject</button>}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
