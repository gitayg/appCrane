import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import { useMe } from '../hooks/useMe'

// Every user's personal MCP keys, for a platform admin (server/routes/adminMcpKeys.js).
// Rendered on the MCP tab; renders nothing for anyone else, so it fires no
// admin-only fetch for them.

interface AdminMcpKey {
  id: number
  owner: { id: number; name: string | null; email: string | null }
  label: string | null
  purpose: string | null
  read_only: boolean
  app_scope: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
  coder_session: boolean
}

const th = { textAlign: 'left' as const, color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }
const td = { padding: '4px 8px' }
const dim = { ...td, color: 'var(--dim)', fontSize: '.78rem' }
const UNUSED_DAYS = 30

export function AdminMcpKeysCard() {
  const me = useMe()
  if (me?.user?.role !== 'platform_admin') return null
  return <AdminMcpKeysTable />
}

function AdminMcpKeysTable() {
  const [keys, setKeys] = useState<AdminMcpKey[] | null>(null)
  const [showAll, setShowAll] = useState(false)
  const [busy, setBusy] = useState(false)

  function load(all = showAll) {
    adminApi.get<{ keys: AdminMcpKey[] }>(`/api/admin/mcp-keys?status=${all ? 'all' : 'live'}`)
      .then(r => setKeys(r.keys ?? []))
      .catch(() => setKeys([]))
  }
  useEffect(() => { load(showAll) }, [showAll])

  async function revoke(k: AdminMcpKey) {
    const owner = k.owner.name || k.owner.email || `user #${k.owner.id}`
    if (!confirm(`Revoke ${owner}'s key "${k.label || `#${k.id}`}"?\n\nIt stops working immediately. This cannot be undone.`)) return
    setBusy(true)
    try {
      await adminApi.del(`/api/admin/mcp-keys/${k.id}`)
    } catch (e) {
      alert('Revoke failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
      load()
    }
  }

  async function revokeUnused() {
    setBusy(true)
    try {
      const preview = await adminApi.post<{ count: number }>('/api/admin/mcp-keys/revoke-unused', { days: UNUSED_DAYS, dry_run: true })
      if (!preview.count) { alert(`No key has gone unused for ${UNUSED_DAYS} days or more.`); return }
      if (!confirm(`Revoke ${preview.count} key${preview.count === 1 ? '' : 's'} not used in the last ${UNUSED_DAYS} days (never-used keys count from when they were created)?\n\nCoder session keys are not included. This cannot be undone.`)) return
      const r = await adminApi.post<{ count: number }>('/api/admin/mcp-keys/revoke-unused', { days: UNUSED_DAYS, dry_run: false })
      alert(`Revoked ${r.count} key${r.count === 1 ? '' : 's'}.`)
    } catch (e) {
      alert('Revoke failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
      load()
    }
  }

  const list = keys ?? []
  const neverUsed = list.filter(k => !k.revoked_at && !k.last_used_at).length

  return (
    <div className="setting-card">
      <h3>MCP keys (all users)</h3>
      <p style={{ marginBottom: 10 }}>
        Every personal MCP key on this AppCrane. Revoking one stops it at once; the owner can create a new one.
        {keys && <> {list.length} shown, <strong style={{ color: neverUsed ? 'var(--yellow)' : undefined }}>{neverUsed} never used</strong>.</>}
      </p>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
        <label style={{ fontSize: '.82rem', display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} />
          Include revoked and expired
        </label>
        <button className="btn btn-xs btn-red" onClick={revokeUnused} disabled={busy}>Revoke unused {UNUSED_DAYS}+ days</button>
      </div>
      {keys === null ? <p style={{ color: 'var(--dim)' }}>Loading…</p> : list.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No keys.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '.8rem' }}>
            <thead>
              <tr>
                <th style={th}>Owner</th><th style={th}>Label</th><th style={th}>Created</th>
                <th style={th}>Last used</th><th style={th}>Expires</th><th style={th}>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {list.map(k => {
                const revoked = !!k.revoked_at
                const expiresMs = k.expires_at ? serverDate(k.expires_at).getTime() : NaN
                const expired = !revoked && Number.isFinite(expiresMs) && expiresMs <= Date.now()
                return (
                  <tr key={k.id} style={{ opacity: revoked || expired ? 0.5 : 1 }}>
                    <td style={td}>
                      {k.owner.name || `user #${k.owner.id}`}
                      {k.owner.email && <div style={{ color: 'var(--dim)', fontSize: '.72rem' }}>{k.owner.email}</div>}
                    </td>
                    <td style={td}>
                      {k.label || <span style={{ color: 'var(--dim)' }}>(no label)</span>}
                      {k.purpose && <Tag>{k.purpose}</Tag>}
                      {k.coder_session && <Tag>coder session</Tag>}
                      {k.read_only && <Tag>read-only</Tag>}
                      {k.app_scope && <Tag>{k.app_scope}</Tag>}
                    </td>
                    <td style={dim}>{serverDate(k.created_at).toLocaleDateString()}</td>
                    <td style={k.last_used_at ? dim : { ...td, fontSize: '.78rem', color: 'var(--yellow)', fontWeight: 600 }}>
                      {k.last_used_at ? serverDate(k.last_used_at).toLocaleString() : 'never'}
                    </td>
                    <td style={{ ...dim, color: expired ? 'var(--red)' : 'var(--dim)' }}>
                      {k.expires_at ? serverDate(k.expires_at).toLocaleDateString() : 'never'}
                    </td>
                    <td style={{ ...td, fontSize: '.78rem' }}>
                      {revoked ? <span style={{ color: 'var(--red)' }}>revoked</span>
                        : expired ? <span style={{ color: 'var(--red)' }}>expired</span>
                          : <span style={{ color: 'var(--green)' }}>active</span>}
                    </td>
                    <td style={{ ...td, textAlign: 'right' }}>
                      {!revoked && <button className="btn btn-xs btn-red" onClick={() => revoke(k)} disabled={busy}>Revoke</button>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Tag({ children }: { children: string }) {
  return (
    <span style={{ marginLeft: 6, fontSize: '.66rem', letterSpacing: '.3px', textTransform: 'uppercase', color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: 3, padding: '0 4px' }}>
      {children}
    </span>
  )
}
