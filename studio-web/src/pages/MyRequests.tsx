import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'

// v2.16.0: personal "My Requests" view — every signed-in user can see the
// requests they submitted and delete their own. Backed by the requester-scoped
// GET /api/enhancements/my and POST /api/enhancements/:id/delete (the server
// authorizes deletes to the row's own user_id). This is deliberately separate
// from the app-triage list at /requests (owners/admins) — same split the API
// keeps between /my and /owned.

interface MyRequest {
  id: number
  app_slug: string | null
  message: string
  created_at: string
  status: string | null
}

const IN_PROGRESS = new Set([
  'selected', 'planning', 'pending_user_review_plan', 'plan_approved',
  'coding', 'pushing', 'building', 'in_progress',
])

function statusPill(status: string | null): { label: string; fg: string; bg: string; border: string } {
  if (status === 'no_changes_needed') return { label: "Won't do", fg: '#a1a1aa', bg: 'var(--surface2)', border: 'var(--border)' }
  if (status === 'done' || status === 'merged' || status === 'sandbox_ready')
    return { label: 'Done', fg: '#22c55e', bg: 'rgba(34,197,94,.15)', border: 'rgba(34,197,94,.4)' }
  if (status && IN_PROGRESS.has(status)) return { label: 'In progress', fg: '#3b82f6', bg: 'rgba(59,130,246,.15)', border: 'rgba(59,130,246,.4)' }
  return { label: 'New', fg: '#f97316', bg: 'rgba(249,115,22,.15)', border: 'rgba(249,115,22,.4)' }
}

function fmtDate(s: string): string {
  if (!s) return '—'
  const d = new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z')
  if (isNaN(d.getTime())) return s
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function MyRequests() {
  const [requests, setRequests] = useState<MyRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    adminApi.get<{ requests: MyRequest[] }>('/api/enhancements/my')
      .then(r => setRequests(r.requests || []))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load your requests'))
      .finally(() => setLoading(false))
  }, [])

  async function remove(id: number) {
    if (!confirm('Delete this request? This cannot be undone.')) return
    try {
      await adminApi.post(`/api/enhancements/${id}/delete`)
      setRequests(rs => rs.filter(r => r.id !== id))
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Delete failed'
      alert(`Delete failed: ${msg}`)
    }
  }

  return (
    <div className="container" style={{ maxWidth: 1100 }}>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', margin: '0 0 14px' }}>
        Requests you've submitted. You can delete any of your own (unless it's actively being worked on).
      </p>
      {error && (
        <div className="req-table-wrap" style={{ padding: 16, color: '#fca5a5' }}>⚠️ {error}</div>
      )}
      {!error && (
        <div className="req-table-wrap">
          <table className="req-table">
            <colgroup>
              <col style={{ width: 70 }} />
              <col style={{ width: 150 }} />
              <col style={{ width: 130 }} />
              <col />
              <col style={{ width: 120 }} />
              <col style={{ width: 44 }} />
            </colgroup>
            <thead>
              <tr>
                <th>#</th>
                <th>App</th>
                <th>Date</th>
                <th>Message</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {requests.map(r => {
                const pill = statusPill(r.status)
                return (
                  <tr key={r.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: '.78rem', color: 'var(--dim)' }}>
                      #{String(r.id).padStart(4, '0')}
                    </td>
                    <td>
                      {r.app_slug
                        ? <span className="app-pill" style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 7px', fontSize: '.75rem', color: 'var(--dim)' }}>{r.app_slug}</span>
                        : '—'}
                    </td>
                    <td style={{ fontSize: '.78rem', color: 'var(--dim)', whiteSpace: 'nowrap' }}>{fmtDate(r.created_at)}</td>
                    <td style={{ fontSize: '.82rem', wordBreak: 'break-word' }}>{r.message}</td>
                    <td>
                      <span style={{ fontSize: '.72rem', fontWeight: 600, padding: '2px 8px', borderRadius: 4, color: pill.fg, background: pill.bg, border: `1px solid ${pill.border}`, whiteSpace: 'nowrap' }}>
                        {pill.label}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-xs btn-red"
                        style={{ padding: '2px 7px' }}
                        onClick={() => remove(r.id)}
                        title="Delete this request"
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                )
              })}
              {!loading && requests.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ color: 'var(--dim)', textAlign: 'center', padding: 24 }}>
                    You haven't submitted any requests yet.
                  </td>
                </tr>
              )}
              {loading && (
                <tr>
                  <td colSpan={6} style={{ color: 'var(--dim)', textAlign: 'center', padding: 24 }}>Loading…</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
