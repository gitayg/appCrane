import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Settings > Security (platform admin): the API key expiry window and the
// "MCP: OAuth only" toggle. Backed by GET/PUT /api/api-key-policy
// (server/routes/apiKeys.js).

interface Policy {
  max_age_days: number
  max_age_default_days: number
  max_age_min_days: number
  max_age_max_days: number
  mcp_oauth_only: boolean
  mcp_oauth_only_exempt_user_ids: number[]
  exempt_users?: { id: number; name: string; email: string | null }[]
}

interface UserRow { id: number; name: string; email: string | null }

export function McpAuthPolicyCard() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [days, setDays] = useState('')
  const [users, setUsers] = useState<UserRow[]>([])
  const [pick, setPick] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  useEffect(() => {
    adminApi.get<Policy>('/api/api-key-policy').then(p => { setPolicy(p); setDays(String(p.max_age_days)) }).catch(e => setMsg({ text: (e as Error).message, ok: false }))
    adminApi.get<{ users: UserRow[] }>('/api/users').then(r => setUsers(r.users ?? [])).catch(() => {})
  }, [])

  async function save(body: Partial<Policy>, ok: string) {
    setBusy(true)
    setMsg(null)
    try {
      const p = await adminApi.put<Policy>('/api/api-key-policy', body)
      setPolicy(prev => ({ ...(prev as Policy), ...p }))
      setDays(String(p.max_age_days))
      setMsg({ text: ok, ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!policy) return msg ? <div className="setting-card"><h3>API keys and MCP sign-in</h3><p style={{ color: 'var(--red)' }}>{msg.text}</p></div> : null

  const exempt = policy.mcp_oauth_only_exempt_user_ids
  const nameOf = (id: number) => users.find(u => u.id === id)?.name || policy.exempt_users?.find(u => u.id === id)?.name || `user #${id}`

  return (
    <div className="setting-card">
      <h3>API keys and MCP sign-in</h3>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
        API keys expire after
        <input className="editable" type="number" min={policy.max_age_min_days} max={policy.max_age_max_days}
          value={days} onChange={e => setDays(e.target.value)} style={{ width: 80 }} />
        days
        <button className="btn btn-xs" disabled={busy || Number(days) === policy.max_age_days}
          onClick={() => save({ max_age_days: Number(days) }, `Keys issued or rotated from now on expire after ${days} days.`)}>Save</button>
      </label>
      <p className="settings-hint">
        User API keys, personal MCP keys and Crew agent tokens. {policy.max_age_min_days} to {policy.max_age_max_days} days, default {policy.max_age_default_days}.
        A change applies to keys created or rotated after it; existing keys keep their date. Owners get an e-mail 14 and 3 days before expiry.
      </p>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 16, cursor: busy ? 'wait' : 'pointer' }}>
        <input type="checkbox" checked={policy.mcp_oauth_only} disabled={busy}
          onChange={e => save({ mcp_oauth_only: e.target.checked }, e.target.checked ? 'MCP now accepts OAuth sign-in only.' : 'MCP accepts API keys again.')} />
        MCP: OAuth only
      </label>
      <p className="settings-hint">
        When on, POST /api/mcp refuses API keys (dhk_user_, dhk_admin_, dhk_mcp_) with a 401 that tells MCP clients to sign in with OAuth.
        The coder's own per-turn keys keep working, and REST API keys are not affected.
      </p>

      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: '.85rem', marginBottom: 4 }}>Allowed to keep using API keys for automation:</div>
        {exempt.length === 0 && <div className="settings-hint">Nobody.</div>}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {exempt.map(id => (
            <span key={id} className="tag" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
              {nameOf(id)}
              <button className="btn btn-xs" disabled={busy} aria-label={`Remove ${nameOf(id)}`}
                onClick={() => save({ mcp_oauth_only_exempt_user_ids: exempt.filter(x => x !== id) }, 'Exception removed.')}>x</button>
            </span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
          <select className="editable" value={pick} onChange={e => setPick(e.target.value)}>
            <option value="">Add a user...</option>
            {users.filter(u => !exempt.includes(u.id)).map(u => <option key={u.id} value={u.id}>{u.name}{u.email ? ` (${u.email})` : ''}</option>)}
          </select>
          <button className="btn btn-xs" disabled={busy || !pick}
            onClick={() => { const id = Number(pick); setPick(''); save({ mcp_oauth_only_exempt_user_ids: [...exempt, id] }, 'Exception added.') }}>Add</button>
        </div>
      </div>

      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.8rem', marginTop: 10 }}>{msg.text}</p>}
    </div>
  )
}
