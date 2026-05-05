import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'

interface AuditEntry {
  created_at: string
  user_name: string
  app_slug: string
  action: string
  detail: string
}

/** Inspect detail JSON for hints about which key class made the call. */
function keyClassBadge(detail: string, action: string): { label: string; bg: string; fg: string } | null {
  // app-scoped key auth shows up via the request path which our middleware
  // logs into detail; personal MCP key likewise. Fall back to action prefix.
  if (!action.startsWith('mcp.')) return null
  try {
    const parsed = JSON.parse(detail)
    const path = (parsed?.path || '') as string
    // Best-effort heuristic until we add explicit key_class to audit_log:
    // mcp.* calls always come from the MCP route. The key class is hinted
    // by the args.slug pattern (app-scoped key always pre-binds slug).
    if (parsed?.args && parsed?.args.slug) {
      // could be either app-scoped or personal — without a column we can't
      // distinguish here. Show generic 'mcp' badge.
      return { label: 'mcp', bg: 'rgba(59,130,246,.12)', fg: 'var(--accent)' }
    }
  } catch {}
  return { label: 'mcp', bg: 'rgba(59,130,246,.12)', fg: 'var(--accent)' }
}

interface App {
  slug: string
  name: string
}

function formatDetail(raw: string): string {
  try {
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed === 'object' && parsed.method) {
      return `${parsed.method} ${parsed.path ?? ''}`
    }
    const str = JSON.stringify(parsed)
    return str.length > 60 ? str.slice(0, 60) + '…' : str
  } catch {
    return raw.length > 60 ? raw.slice(0, 60) + '…' : raw
  }
}

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [apps, setApps] = useState<App[]>([])
  const [appFilter, setAppFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [limit, setLimit] = useState(50)

  useEffect(() => {
    adminApi.get<{ apps: App[] }>('/api/apps').then(d => setApps(d.apps || [])).catch(() => {})
  }, [])

  useEffect(() => {
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    if (appFilter) params.set('app', appFilter)
    if (actionFilter) params.set('action', actionFilter)
    adminApi.get<{ entries: AuditEntry[]; total: number }>(`/api/audit?${params}`)
      .then(data => {
        setEntries(data.entries ?? [])
        setTotal(data.total ?? 0)
      })
      .catch(() => {})
  }, [appFilter, actionFilter, limit])

  return (
    <div className="container">
      <h2>Audit Log</h2>

      <div className="filter-row" style={{ flexWrap: 'wrap', gap: 8 }}>
        <select value={appFilter} onChange={e => setAppFilter(e.target.value)}>
          <option value="">All apps</option>
          {apps.map(a => (
            <option key={a.slug} value={a.slug}>{a.name}</option>
          ))}
        </select>

        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)}>
          <option value="">All actions</option>
          <option value="mcp.">MCP only (mcp.*)</option>
          <option value="deploy">Deploys</option>
          <option value="env-set">Env var writes</option>
          <option value="app-key">App-key changes</option>
          <option value="user-mcp-key">User MCP key changes</option>
          <option value="app-set-role">Role changes</option>
        </select>

        <select value={limit} onChange={e => setLimit(Number(e.target.value))}>
          {[20, 50, 100, 200].map(n => (
            <option key={n} value={n}>{n} entries</option>
          ))}
        </select>
      </div>

      {entries.length === 0 ? (
        <div style={{ color: 'var(--dim)', padding: '20px 0' }}>No audit entries</div>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>App</th>
                <th>Action</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i}>
                  <td style={{ whiteSpace: 'nowrap', color: 'var(--dim)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td>{e.user_name}</td>
                  <td>{e.app_slug || '-'}</td>
                  <td>
                    <span className="tag">{e.action}</span>
                    {(() => {
                      const b = keyClassBadge(e.detail, e.action)
                      return b ? (
                        <span style={{
                          marginLeft: 6, padding: '2px 6px', borderRadius: 3,
                          fontSize: '.65rem', fontWeight: 600, letterSpacing: '.3px',
                          textTransform: 'uppercase',
                          background: b.bg, color: b.fg, border: `1px solid ${b.fg}33`,
                        }}>{b.label}</span>
                      ) : null
                    })()}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--dim)' }}>
                    {formatDetail(e.detail)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: 10, fontSize: '0.82rem', color: 'var(--dim)' }}>
            {entries.length} of {total} entries
          </div>
        </>
      )}
    </div>
  )
}
