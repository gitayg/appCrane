import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import type { Decision, Review, ReviewItem } from './types'

const APP_ROLES = ['owner', 'admin', 'user']

const day = (ts: string | null) => (ts ? serverDate(ts).toLocaleDateString() : 'never')

function DecisionBadge({ item }: { item: ReviewItem }) {
  if (!item.decision) return <span className="badge" style={{ color: 'var(--orange)' }}>To review</span>
  const label = item.decision === 'keep' ? 'Kept' : item.decision === 'remove' ? 'Removed' : `Changed to ${item.new_role}`
  return (
    <span className="badge" style={{ color: item.decision === 'keep' ? 'var(--green)' : 'var(--accent)' }}
      title={item.decided_by_name ? `${item.decided_by_name}, ${day(item.decided_at)}` : undefined}>
      {label}
    </span>
  )
}

function ItemRow({ item, canDecide, onDecided }: { item: ReviewItem; canDecide: boolean; onDecided: () => void }) {
  const [role, setRole] = useState(APP_ROLES.find(r => r !== item.role) || 'user')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const isApp = item.role !== 'platform_admin'

  async function decide(decision: Decision) {
    if (decision === 'remove' && !window.confirm(`Remove ${item.user_name || 'this person'}'s ${item.role} access now?`)) return
    setBusy(true)
    setError('')
    try {
      await adminApi.post(`/api/access-reviews/items/${item.id}/decision`, decision === 'change' ? { decision, new_role: role } : { decision })
      onDecided()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <tr style={{ borderTop: '1px solid var(--border)' }}>
      <td style={{ padding: 6 }}>
        <div>{item.user_name || `#${item.user_id}`}</div>
        <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>{item.user_email}</div>
      </td>
      <td style={{ padding: 6 }}>{item.role}</td>
      <td style={{ padding: 6 }}>
        {item.granted_via === 'scim'
          ? <span className="badge" title={item.scim_message || undefined}>Identity provider group</span>
          : 'Direct'}
      </td>
      <td style={{ padding: 6 }}>{day(item.last_access_at)}</td>
      <td style={{ padding: 6 }}>
        {item.decision || !canDecide ? <DecisionBadge item={item} /> : (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <button className="btn" disabled={busy} onClick={() => decide('keep')}>Keep</button>
            {item.scim_managed ? (
              <span style={{ fontSize: '.75rem', color: 'var(--dim)' }}>Managed by your identity provider</span>
            ) : (
              <>
                <button className="btn" disabled={busy} onClick={() => decide('remove')}>Remove</button>
                {isApp && (
                  <>
                    <select value={role} onChange={e => setRole(e.target.value)} disabled={busy} aria-label="New role">
                      {APP_ROLES.filter(r => r !== item.role).map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button className="btn" disabled={busy} onClick={() => decide('change')}>Change role</button>
                  </>
                )}
              </>
            )}
          </div>
        )}
        {error && <div style={{ color: 'var(--red)', fontSize: '.75rem' }}>{error}</div>}
      </td>
    </tr>
  )
}

export function ReviewCard({ review, onChange }: { review: Review; onChange: () => void }) {
  const left = review.items.filter(i => !i.decision).length
  const title = review.kind === 'platform' ? 'Platform admins' : review.app_name || review.app_slug
  return (
    <div className="card" style={{ marginBottom: 16, padding: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
        <div>
          <b>{title}</b>
          {review.data_classification && <span className="badge" style={{ marginLeft: 8 }}>{review.data_classification}</span>}
          <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>
            {review.campaign.name} | due {day(review.campaign.due_at)} | reviewers: {review.reviewers.map(r => r.name).join(', ')}
          </div>
        </div>
        <div style={{ fontSize: '.85rem', color: left ? 'var(--orange)' : 'var(--green)' }}>
          {review.campaign.status === 'closed' ? 'Closed' : left ? `${left} left to review` : 'Done'}
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse', marginTop: 8 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
              <th style={{ padding: 6 }}>Person</th>
              <th style={{ padding: 6 }}>Role</th>
              <th style={{ padding: 6 }}>Granted</th>
              <th style={{ padding: 6 }}>Last access</th>
              <th style={{ padding: 6 }}>Decision</th>
            </tr>
          </thead>
          <tbody>
            {review.items.map(i => <ItemRow key={i.id} item={i} canDecide={review.can_decide} onDecided={onChange} />)}
          </tbody>
        </table>
      </div>
    </div>
  )
}
