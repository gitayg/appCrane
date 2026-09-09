import { useState, useEffect, useMemo, useCallback } from 'react'
import { adminApi } from '../adminApi'

// Row shape of GET /api/audit — `al.*` from the audit_log table plus the
// joined display columns. Mirrors server/routes/logs.js: the per-app variant
// (GET /api/apps/:slug/audit) selects `al.*, u.name as user_name`, and the
// cross-app one adds `a.slug as app_slug, a.name as app_name`. The joined
// columns are optional here so a row that arrives without them (a LEFT JOIN
// miss, or the per-app endpoint's narrower select) still renders.
export interface AuditEntry {
  id: number
  user_id: number | null
  app_id: number | null
  action: string
  detail: string | null
  created_at: string
  actor_kind?: string | null
  user_name?: string | null
  app_slug?: string | null
  app_name?: string | null
}

// Rows written by the server carry SQLite's `datetime('now')` format
// ("YYYY-MM-DD HH:MM:SS", UTC, no zone marker). Handing that straight to
// `new Date()` makes the browser read it as local time and shifts every
// timestamp by the UTC offset — same correction Layout.tsx applies.
function formatWhen(raw: string): string {
  if (!raw) return '-'
  const iso = raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z'
  const d = new Date(iso)
  return isNaN(d.getTime()) ? raw : d.toLocaleString()
}

function formatDetail(raw: string | null): string {
  if (!raw) return ''
  try {
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed === 'object' && parsed.method) {
      return `${parsed.method} ${parsed.path ?? ''}`
    }
    const str = JSON.stringify(parsed)
    return str.length > 80 ? str.slice(0, 80) + '...' : str
  } catch {
    return raw.length > 80 ? raw.slice(0, 80) + '...' : raw
  }
}

// Sentinel for the app filter: platform-level entries have app_id === null and
// therefore no slug to key an <option> on.
const PLATFORM = '__platform__'

const LIMIT = 200

export function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [appFilter, setAppFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')

  const load = useCallback(() => {
    setLoading(true)
    adminApi.get<{ entries?: AuditEntry[] }>(`/api/audit?limit=${LIMIT}`)
      .then(data => {
        setEntries(Array.isArray(data?.entries) ? data.entries : [])
        setError(null)
      })
      .catch((e: unknown) => {
        // A caller with no auditable apps gets an empty list, not a 403 — so a
        // rejection here is a real failure. Report it in place and leave the
        // rest of the SPA alone.
        setEntries([])
        setError(e instanceof Error ? e.message : 'Could not load the audit log')
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const appOptions = useMemo(() => {
    const seen = new Map<string, string>()
    for (const e of entries) {
      if (e.app_slug) seen.set(e.app_slug, e.app_name || e.app_slug)
      else if (e.app_id == null) seen.set(PLATFORM, 'Platform (no app)')
    }
    return [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [entries])

  const actionOptions = useMemo(
    () => [...new Set(entries.map(e => e.action).filter(Boolean))].sort(),
    [entries],
  )

  const visible = useMemo(() => entries.filter(e => {
    if (appFilter === PLATFORM) { if (e.app_id != null) return false }
    else if (appFilter && e.app_slug !== appFilter) return false
    if (actionFilter && e.action !== actionFilter) return false
    return true
  }), [entries, appFilter, actionFilter])

  return (
    <div className="container">
      <h2>Audit</h2>
      <p style={{ color: 'var(--dim)', marginTop: -6 }}>
        Every audited action across the apps you can see, newest first.
      </p>

      <div className="filter-row">
        <select value={appFilter} onChange={e => setAppFilter(e.target.value)} aria-label="Filter by app">
          <option value="">All apps</option>
          {appOptions.map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>

        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} aria-label="Filter by action">
          <option value="">All actions</option>
          {actionOptions.map(a => <option key={a} value={a}>{a}</option>)}
        </select>

        <button className="btn" onClick={load} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>

        {!loading && !error && entries.length > 0 && (
          <span style={{ color: 'var(--dim)', fontSize: '.82rem' }}>
            {visible.length === entries.length
              ? `${entries.length} entries`
              : `${visible.length} of ${entries.length} entries`}
          </span>
        )}
      </div>

      {error && (
        <div style={{
          padding: '10px 12px', borderRadius: 6, marginBottom: 12,
          background: 'rgba(239,68,68,.10)', border: '1px solid var(--red)', color: 'var(--red)',
        }}>
          {error}
        </div>
      )}

      {!error && !loading && entries.length === 0 && (
        <div style={{ color: 'var(--dim)', padding: '20px 0' }}>
          There are no audit entries you can see.
        </div>
      )}

      {!error && entries.length > 0 && visible.length === 0 && (
        <div style={{ color: 'var(--dim)', padding: '20px 0' }}>
          No entries match these filters.
        </div>
      )}

      {visible.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>App</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(e => (
              <tr key={e.id}>
                <td style={{ whiteSpace: 'nowrap', color: 'var(--dim)', fontFamily: 'monospace', fontSize: '.8rem' }}>
                  {formatWhen(e.created_at)}
                </td>
                <td>{e.user_name || 'Unattributed'}</td>
                <td><span className="tag">{e.action}</span></td>
                <td style={{ fontFamily: 'monospace', fontSize: '.8rem' }}>
                  {e.app_slug || (e.app_id == null ? 'platform' : '-')}
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: '.8rem', color: 'var(--dim)' }}>
                  {formatDetail(e.detail)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
