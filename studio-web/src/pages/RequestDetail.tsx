import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { adminApi, ApiError } from '../adminApi'
import { coderSessionHref } from '../components/coder/SendToCoderBar'

type Bucket = 'triage' | 'in_progress' | 'shipped' | 'validated'

interface RequestRow {
  id: number
  app_slug: string | null
  app_name: string | null
  user_name: string | null
  message: string
  created_at: string
  status: string | null
  bucket: Bucket
  validated_at: string | null
  done_note: string | null
  fix_version: string | null
  branch_name: string | null
  pr_url: string | null
  coder_session_id: string | null
  /** Opened by the dependency scan: the message is the advisory. */
  dependency_scan: boolean
}

const BUCKET_LABELS: Record<Bucket, string> = {
  triage: 'Triage', in_progress: 'In Progress', shipped: 'Shipped', validated: 'Validated',
}

function fmtDate(str?: string | null): string {
  return str ? new Date(str).toLocaleString() : '—'
}

/**
 * One request on its own page (/requests/:id). The dependency digest links
 * here, and so does every row of the Requests list. GET /api/enhancements/:id
 * answers the same 404 for an unknown id and one this user may not see.
 */
export function RequestDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [row, setRow] = useState<RequestRow | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setRow(null)
    setError(null)
    adminApi.get<{ request: RequestRow }>(`/api/enhancements/${encodeURIComponent(id || '')}`)
      .then(r => { if (alive) setRow(r.request) })
      .catch(e => {
        if (!alive) return
        setError(e instanceof ApiError && e.status === 404
          ? 'No such request, or it isn’t one you can see.'
          : e instanceof Error ? e.message : String(e))
      })
    return () => { alive = false }
  }, [id])

  const closed = row && (row.status === 'done' || row.status === 'no_changes_needed')
  const label = (k: string) => <div style={{ fontSize: '.72rem', color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '.04em' }}>{k}</div>

  return (
    <div className="container" style={{ maxWidth: 900 }}>
      <p style={{ margin: '0 0 14px' }}>
        <Link to="/requests" style={{ color: 'var(--accent)', fontSize: '.85rem' }}>← All requests</Link>
      </p>
      {error && <div className="req-table-wrap" style={{ padding: 16, color: '#fca5a5' }}>⚠️ {error}</div>}
      {!error && !row && <div style={{ color: 'var(--dim)' }}>Loading…</div>}
      {row && (
        <div className="req-table-wrap" style={{ padding: 18, display: 'grid', gap: 16 }}>
          <h2 style={{ margin: 0, fontSize: '1.05rem' }}>
            Request #{String(row.id).padStart(4, '0')}
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
            <div>{label('App')}{row.app_slug === '_platform' ? 'AppCrane Platform' : (row.app_name || row.app_slug || '—')}</div>
            <div>{label('Status')}{row.status === 'no_changes_needed' ? 'Won’t do' : BUCKET_LABELS[row.bucket]}</div>
            <div>{label('Filed by')}{row.user_name || '—'}</div>
            <div>{label('Filed')}{fmtDate(row.created_at)}</div>
            {row.validated_at && <div>{label('Validated')}{fmtDate(row.validated_at)}</div>}
            {row.fix_version && <div>{label('Fixed in')}<code>{row.fix_version}</code></div>}
            {row.pr_url && <div>{label('Pull request')}<a href={row.pr_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>PR ↗</a></div>}
          </div>
          <div>
            {label(row.dependency_scan ? 'Advisory' : 'Request')}
            {/* Rendered as text (React escapes it); pre-wrap keeps its lines. */}
            <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '.88rem', marginTop: 4 }}>{row.message}</div>
          </div>
          {row.done_note && closed && (
            <div>
              {label(row.status === 'no_changes_needed' ? 'Note' : 'What was done')}
              <div style={{ whiteSpace: 'pre-wrap', marginTop: 4, padding: '6px 8px', borderLeft: '2px solid var(--border)', color: 'var(--dim)' }}>{row.done_note}</div>
            </div>
          )}
          {row.coder_session_id && row.app_slug && (
            <div>
              {label('Coder session')}
              <a href={coderSessionHref(row.app_slug, row.coder_session_id)}
                 onClick={ev => { ev.preventDefault(); navigate(coderSessionHref(row.app_slug as string, row.coder_session_id as string)) }}
                 style={{ color: 'var(--accent)' }}>Open the session this request went to ↗</a>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
