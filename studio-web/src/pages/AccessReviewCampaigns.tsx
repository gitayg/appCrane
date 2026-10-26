import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import { PolicyCard } from '../components/accessReviews/PolicyCard'
import { ReviewCard } from '../components/accessReviews/ReviewCard'
import { downloadExport, type Campaign, type Review } from '../components/accessReviews/types'

const day = (ts: string | null) => (ts ? serverDate(ts).toLocaleDateString() : '')

function Exports({ id }: { id: number }) {
  const [error, setError] = useState('')
  const get = (format: 'csv' | 'json') => downloadExport(`/api/access-reviews/campaigns/${id}/report${format === 'csv' ? '?format=csv' : ''}`, `access-review-${id}.${format}`)
    .catch(e => setError(e instanceof Error ? e.message : String(e)))
  return (
    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
      <button className="btn" onClick={() => get('csv')}>CSV</button>
      <button className="btn" onClick={() => get('json')}>JSON</button>
      {error && <span style={{ color: 'var(--red)', fontSize: '.75rem' }}>{error}</span>}
    </span>
  )
}

function CampaignDetail({ id }: { id: number }) {
  const [data, setData] = useState<{ campaign: Campaign; reviews: Review[] } | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(() => {
    adminApi.get<{ campaign: Campaign; reviews: Review[] }>(`/api/access-reviews/campaigns/${id}`)
      .then(r => { setData(r); setError('') })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [id])
  useEffect(() => { load() }, [load])

  async function close() {
    if (!window.confirm('Close this campaign? Unreviewed access stays as it is and is reported as unreviewed.')) return
    try { await adminApi.post(`/api/access-reviews/campaigns/${id}/close`); load() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  if (error) return <p style={{ color: 'var(--red)' }}>{error}</p>
  if (!data) return <p style={{ color: 'var(--dim)' }}>Loading...</p>
  const c = data.campaign
  return (
    <div>
      <p><Link to="/access-reviews/campaigns">All campaigns</Link></p>
      <h3>{c.name}</h3>
      <p className="settings-hint">
        {c.status === 'open' ? 'Open' : `Closed ${day(c.closed_at)}`} | started {day(c.started_at)} | due {day(c.due_at)} | grace until {day(c.grace_until)}
        {' | '}{c.decided} of {c.items} reviewed, {c.removed} removed, {c.changed} changed
      </p>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <Exports id={c.id} />
        {c.status === 'open' && <button className="btn" onClick={close}>Close campaign</button>}
      </div>
      {data.reviews.map(r => <ReviewCard key={r.id} review={r} onChange={load} />)}
    </div>
  )
}

/** Platform admin: access-review policy, campaigns, and each campaign's report. */
export function AccessReviewCampaigns() {
  const { id } = useParams()
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(() => {
    adminApi.get<{ campaigns: Campaign[] }>('/api/access-reviews/campaigns')
      .then(r => { setCampaigns(r.campaigns); setError('') })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])
  useEffect(() => { if (!id) load() }, [id, load])

  if (id) return <CampaignDetail id={Number(id)} />

  async function start() {
    try { await adminApi.post('/api/access-reviews/campaigns', { scope: 'default' }); load() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  return (
    <div>
      <h3>Access review campaigns</h3>
      <p className="settings-hint">
        Each campaign asks every app's owners to confirm who has access, and platform admins to confirm each other.
        Reviewers are e-mailed at the start and before the due date; overdue campaigns are escalated to platform admins.
      </p>
      <PolicyCard />
      <button className="btn" onClick={start} style={{ marginBottom: 12 }}>Start a campaign now</button>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      {campaigns && !campaigns.length && <p style={{ color: 'var(--dim)' }}>No campaigns yet.</p>}
      {campaigns && campaigns.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                <th style={{ padding: 6 }}>Campaign</th>
                <th style={{ padding: 6 }}>Status</th>
                <th style={{ padding: 6 }}>Due</th>
                <th style={{ padding: 6 }}>Reviewed</th>
                <th style={{ padding: 6 }}>Report</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map(c => (
                <tr key={c.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: 6 }}><Link to={`/access-reviews/campaigns/${c.id}`}>{c.name}</Link></td>
                  <td style={{ padding: 6 }}>{c.status}{c.escalated_at && c.status === 'open' ? ' (overdue)' : ''}</td>
                  <td style={{ padding: 6 }}>{day(c.due_at)}</td>
                  <td style={{ padding: 6 }}>{c.decided} / {c.items}</td>
                  <td style={{ padding: 6 }}><Exports id={c.id} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
