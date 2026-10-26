import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Settings > Security (platform admin): every user's MCP OAuth connections with
// Revoke, who may register an MCP client, and approval of registered clients.
// Backed by /api/oauth/admin/* (server/routes/oauthAdmin.js).

interface Grant {
  id: number
  client_name: string
  redirect_hosts: string[]
  read_only: boolean
  created_at: string
  last_used_at: string | null
  expires_at: string
  client_approved: boolean
  user: { id: number; name: string; email: string | null }
}

interface Client {
  client_id: string
  client_name: string
  redirect_uris: string[]
  created_at: string
  approved_at: string | null
  live_grants: number
}

interface Policy { mode: 'open' | 'allowlist' | 'approval'; redirect_hosts: string[]; default_redirect_hosts: string[] }

const MODES: { value: Policy['mode']; label: string }[] = [
  { value: 'allowlist', label: 'Allowlisted return hosts (loopback for Claude Code, plus the hosts below)' },
  { value: 'approval', label: 'A platform admin approves each new client' },
  { value: 'open', label: 'Open: any app may register (the MCP default)' },
]

const cell = { padding: '6px' }
const mono = { fontFamily: 'monospace', fontSize: '.78rem' }

export function OAuthAdminCard() {
  const [grants, setGrants] = useState<Grant[] | null>(null)
  const [clients, setClients] = useState<Client[]>([])
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [hosts, setHosts] = useState('')
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<{ grants: Grant[] }>('/api/oauth/admin/grants').then(r => setGrants(r.grants)).catch(e => setMsg({ text: (e as Error).message, ok: false }))
    adminApi.get<{ clients: Client[] }>('/api/oauth/admin/clients').then(r => setClients(r.clients)).catch(() => {})
    adminApi.get<Policy>('/api/oauth/admin/policy').then(p => { setPolicy(p); setHosts(p.redirect_hosts.join('\n')) }).catch(() => {})
  }, [])
  useEffect(load, [load])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    setMsg(null)
    try { await fn(); setMsg({ text: ok, ok: true }); load() } catch (e) { setMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }

  const revoke = (g: Grant) => {
    if (!window.confirm(`Revoke ${g.client_name} for ${g.user.name}? It loses access immediately.`)) return
    run(() => adminApi.del(`/api/oauth/admin/grants/${g.id}`), 'Connection revoked')
  }
  const savePolicy = (mode: Policy['mode']) => run(
    () => adminApi.put('/api/oauth/admin/policy', { mode, redirect_hosts: hosts.split(/[\s,]+/).filter(Boolean) }),
    'MCP client policy saved',
  )
  const approve = (c: Client, approved: boolean) => run(
    () => adminApi.post(`/api/oauth/admin/clients/${encodeURIComponent(c.client_id)}/approval`, { approved }),
    approved ? 'Client approved' : 'Approval withdrawn; its connections were ended',
  )

  return (
    <div className="setting-card">
      <h3>MCP OAuth connections</h3>
      <p style={{ marginBottom: 8 }}>
        Apps people connected with "sign in with AppCrane". Each acts as the person who approved it, with their role,
        until it expires or is revoked. Changing a password, rotating an API key or demoting a platform admin ends
        that person's connections.
      </p>
      {msg && <div role={msg.ok ? 'status' : 'alert'} style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.8rem', marginBottom: 8 }}>{msg.text}</div>}
      {grants === null ? null : grants.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.82rem' }}>No live connections.</p>
      ) : (
        <table style={{ width: '100%', fontSize: '.82rem', borderCollapse: 'collapse', marginBottom: 16 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
              <th style={cell}>User</th><th style={cell}>App</th><th style={cell}>Returns to</th>
              <th style={cell}>Access</th><th style={cell}>Last used</th><th style={cell}>Expires</th><th />
            </tr>
          </thead>
          <tbody>
            {grants.map(g => (
              <tr key={g.id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={cell}>{g.user.name}</td>
                <td style={cell}>{g.client_name}{!g.client_approved && <span style={{ color: 'var(--dim)' }}> (unverified)</span>}</td>
                <td style={{ ...cell, ...mono }}>{g.redirect_hosts.join(', ')}</td>
                <td style={cell}>{g.read_only ? 'Read-only' : 'Full'}</td>
                <td style={cell}>{g.last_used_at || 'never'}</td>
                <td style={cell}>{g.expires_at.slice(0, 10)}</td>
                <td style={{ ...cell, textAlign: 'right' }}>
                  <button type="button" className="btn btn-xs btn-danger" onClick={() => revoke(g)} disabled={busy}>Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {policy && (
        <>
          <h4 style={{ margin: '8px 0 4px' }}>Who may register an MCP client</h4>
          {MODES.map(m => (
            <label key={m.value} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '.85rem', margin: '4px 0' }}>
              <input type="radio" name="oauth-dcr-mode" checked={policy.mode === m.value} onChange={() => setPolicy({ ...policy, mode: m.value })} />
              {m.label}
            </label>
          ))}
          <label style={{ display: 'block', fontSize: '.82rem', margin: '8px 0 4px' }}>
            Allowed https return hosts, one per line (default: {policy.default_redirect_hosts.join(', ')})
            <textarea value={hosts} onChange={e => setHosts(e.target.value)} rows={3} style={{ width: '100%', ...mono }} />
          </label>
          <button type="button" className="btn btn-xs" onClick={() => savePolicy(policy.mode)} disabled={busy}>Save policy</button>
        </>
      )}

      {clients.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Registered clients</h4>
          <table style={{ width: '100%', fontSize: '.82rem', borderCollapse: 'collapse' }}>
            <tbody>
              {clients.map(c => (
                <tr key={c.client_id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={cell}>{c.client_name}</td>
                  <td style={{ ...cell, ...mono, wordBreak: 'break-all' }}>{c.redirect_uris.join(' ')}</td>
                  <td style={cell}>{c.live_grants} live</td>
                  <td style={{ ...cell, textAlign: 'right' }}>
                    {c.approved_at
                      ? <button type="button" className="btn btn-xs" onClick={() => approve(c, false)} disabled={busy}>Withdraw approval</button>
                      : <button type="button" className="btn btn-xs" onClick={() => approve(c, true)} disabled={busy}>Approve</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
