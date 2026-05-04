import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'

interface AgentUser {
  id: number
  name: string
  email: string
  kind?: 'human' | 'agent'
  created_at?: string
  assigned_apps?: string | null
}

interface NewKeyResult {
  name: string
  email: string
  key: string
  rotated?: boolean
}

export function Agents() {
  const [agents, setAgents] = useState<AgentUser[]>([])
  const [busy, setBusy] = useState(false)
  const [newKey, setNewKey] = useState<NewKeyResult | null>(null)
  const [copied, setCopied] = useState(false)

  const load = () =>
    adminApi.get<{ users: AgentUser[] }>('/api/users')
      .then(d => setAgents((d.users ?? []).filter(u => u.kind === 'agent')))
      .catch(() => {})

  useEffect(() => { load() }, [])

  async function generateKey() {
    if (busy) return
    const ts = Date.now()
    const defaultName = `agent-${ts}`
    const nameInput = prompt('Name for this agent (used in audit logs):', defaultName)
    if (nameInput === null) return // cancelled
    const name = (nameInput.trim() || defaultName)
    const email = `${name.toLowerCase().replace(/[^a-z0-9-]+/g, '-')}-${ts}@appcrane`
    setBusy(true)
    try {
      const r = await adminApi.post<{ key?: string; api_key?: string }>('/api/users', {
        name, email, role: 'user', kind: 'agent',
      })
      const key = r?.key ?? r?.api_key ?? ''
      if (!key) throw new Error('Server returned no key')
      setNewKey({ name, email, key })
      setCopied(false)
      load()
    } catch (e) {
      alert('Failed to create key: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function deleteAgent(id: number) {
    if (!confirm('Delete this app agent? Its API key will stop working immediately.')) return
    await adminApi.del(`/api/users/${id}`).catch(() => {})
    load()
  }

  async function rotateKey(agent: AgentUser) {
    if (!confirm(`Rotate the API key for "${agent.name}"?\n\nThe current key will stop working immediately. Anything using it must be updated with the new key.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ api_key?: string }>(`/api/users/${agent.id}/regenerate-key?confirm=true`, {})
      const key = r?.api_key ?? ''
      if (!key) throw new Error('Server returned no key')
      setNewKey({ name: agent.name, email: agent.email, key, rotated: true })
      setCopied(false)
      load()
    } catch (e) {
      alert('Rotate failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  function copyKey() {
    if (!newKey) return
    navigator.clipboard.writeText(newKey.key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>App Agents</h2>
        <button
          className="btn btn-accent"
          onClick={generateKey}
          disabled={busy}
          style={{ marginLeft: 'auto' }}
        >
          {busy ? 'Creating…' : '+ New API Key'}
        </button>
      </div>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginTop: -8, marginBottom: 16 }}>
        API-key identities for agents and external integrations. Each key is shown once on creation —
        save it somewhere safe. Assign apps to a key from <a href="/applications" style={{ color: 'var(--accent)' }}>/applications</a> if it should be scoped.
      </p>

      {agents.length === 0 ? (
        <div className="setting-card">
          <p style={{ color: 'var(--dim)', fontSize: '.88rem', margin: 0 }}>
            No app agents yet. Click <strong>+ New API Key</strong> to create one.
          </p>
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Assigned apps</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {agents.map(a => (
              <tr key={a.id}>
                <td style={{ fontFamily: 'monospace', fontSize: '.8rem' }}>{a.id}</td>
                <td>{a.name}</td>
                <td>{a.email}</td>
                <td style={{ color: a.assigned_apps ? 'var(--text)' : 'var(--dim)', fontSize: '.82rem' }}>
                  {a.assigned_apps || 'unused'}
                </td>
                <td style={{ color: 'var(--dim)', fontSize: '.8rem' }}>
                  {a.created_at ? new Date(a.created_at).toLocaleDateString() : ''}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                    <button
                      className="btn btn-xs"
                      onClick={() => rotateKey(a)}
                      disabled={busy}
                      title="Issue a new API key for this agent. The old key stops working immediately."
                    >
                      Rotate key
                    </button>
                    <button className="btn btn-red btn-xs" onClick={() => deleteAgent(a.id)}>Delete</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {newKey && (
        <div
          onClick={() => setNewKey(null)}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
            backdropFilter: 'blur(2px)',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 12, padding: 28, maxWidth: 580, width: '92%',
              boxShadow: '0 24px 64px rgba(0,0,0,.5)',
            }}
          >
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>
              ✓ {newKey.rotated ? 'Key rotated' : 'Agent created'}
            </h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              <strong style={{ color: 'var(--text)' }}>{newKey.name}</strong> · {newKey.email}
            </p>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>API key</span>
                <button className="btn btn-accent" onClick={copyKey} style={{ fontSize: '.78rem', padding: '4px 14px' }}>
                  {copied ? '✓ Copied' : 'Copy key'}
                </button>
              </div>
              <code
                onClick={copyKey}
                style={{
                  display: 'block', background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '12px 14px', fontFamily: 'monospace',
                  fontSize: '.85rem', wordBreak: 'break-all', cursor: 'pointer',
                  fontWeight: 700, userSelect: 'all',
                }}
              >
                {newKey.key}
              </code>
            </div>

            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)',
              border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Copy it now and store it safely.
            </div>

            <p style={{ fontSize: '.8rem', color: 'var(--dim)', marginBottom: 16 }}>
              Use it in your agent's environment, e.g.:
              <br />
              <code style={{ fontFamily: 'monospace', color: 'var(--text)' }}>
                APPCRANE_API_KEY={newKey.key.slice(0, 20)}…
              </code>
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setNewKey(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
