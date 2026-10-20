import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

interface Connection {
  id: number
  client_name: string
  redirect_hosts: string[]
  scope: string
  read_only: boolean
  created_at: string
  last_used_at: string | null
}

/**
 * MCP clients connected by browser sign-in (OAuth) instead of a pasted key,
 * with a Revoke button per connection. Backed by /api/oauth/connections.
 */
export function OAuthConnections({ endpoint }: { endpoint: string }) {
  const [rows, setRows] = useState<Connection[] | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    adminApi.get<{ connections: Connection[] }>('/api/oauth/connections')
      .then(r => setRows(r.connections || []))
      .catch(e => setError(e?.message || 'Failed to load connected apps'))
  }, [])
  useEffect(load, [load])

  const revoke = async (c: Connection) => {
    if (!window.confirm(`Revoke ${c.client_name}? It loses access immediately and has to be approved again.`)) return
    try {
      await adminApi.del(`/api/oauth/connections/${c.id}`)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const code = { fontFamily: 'monospace', fontSize: '.78rem' }
  return (
    <div className="setting-card">
      <h3>Connected apps (sign in with AppCrane)</h3>
      <p style={{ marginBottom: 8 }}>
        MCP clients that support OAuth (Claude.ai connectors, Claude Code) can connect with a browser sign-in instead
        of a key. Add <code style={code}>{endpoint}</code> with no key; your browser opens, you sign in and approve.
        The connection reaches the same apps a personal key does, and you can make it read-only when you approve.
      </p>
      <pre style={{ ...code, background: 'var(--surface2)', padding: '8px 10px', borderRadius: 6, overflowX: 'auto', margin: '0 0 12px' }}>
        {`claude mcp add --transport http appcrane ${endpoint}`}
      </pre>
      {error && <div role="alert" style={{ color: 'var(--red)', fontSize: '.8rem', marginBottom: 8 }}>{error}</div>}
      {rows === null ? null : rows.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.82rem', margin: 0 }}>No connected apps.</p>
      ) : (
        <table style={{ width: '100%', fontSize: '.82rem', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
              <th style={{ padding: '4px 6px' }}>App</th>
              <th style={{ padding: '4px 6px' }}>Returns to</th>
              <th style={{ padding: '4px 6px' }}>Access</th>
              <th style={{ padding: '4px 6px' }}>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map(c => (
              <tr key={c.id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '6px' }}>{c.client_name}</td>
                <td style={{ padding: '6px', ...code }}>{c.redirect_hosts.join(', ')}</td>
                <td style={{ padding: '6px' }}>{c.read_only ? 'Read-only' : 'Full'}</td>
                <td style={{ padding: '6px' }}>{c.last_used_at || 'never'}</td>
                <td style={{ padding: '6px', textAlign: 'right' }}>
                  <button type="button" className="btn btn-xs btn-danger" onClick={() => revoke(c)}>Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
