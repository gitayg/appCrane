import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { ReviewCard } from '../components/accessReviews/ReviewCard'
import type { Review } from '../components/accessReviews/types'

/** My reviews: the access reviews assigned to me (as an app owner, or as a platform admin). */
export function AccessReviews() {
  const [reviews, setReviews] = useState<Review[] | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    adminApi.get<{ reviews: Review[] }>('/api/access-reviews/mine')
      .then(r => { setReviews(r.reviews); setError('') })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => { load() }, [load])

  const open = (reviews || []).filter(r => r.campaign.status === 'open')
  const closed = (reviews || []).filter(r => r.campaign.status === 'closed')

  return (
    <div>
      <h3>My access reviews</h3>
      <p className="settings-hint">
        Confirm who should keep access to your apps. Keep leaves a role as it is; Remove and Change role take effect at once
        and are recorded in the audit log. Access that comes from an identity provider group is changed in the identity provider.
      </p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      {reviews === null && !error && <p style={{ color: 'var(--dim)' }}>Loading...</p>}
      {reviews && !reviews.length && <p style={{ color: 'var(--dim)' }}>No access reviews are assigned to you.</p>}
      {open.map(r => <ReviewCard key={r.id} review={r} onChange={load} />)}
      {closed.length > 0 && (
        <details>
          <summary style={{ cursor: 'pointer', margin: '12px 0' }}>Past reviews ({closed.length})</summary>
          {closed.map(r => <ReviewCard key={r.id} review={r} onChange={load} />)}
        </details>
      )}
    </div>
  )
}
