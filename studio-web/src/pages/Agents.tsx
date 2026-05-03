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

export function Agents() {
  const [agents, setAgents] = useState<AgentUser[]>([])

  const load = () =>
    adminApi.get<{ users: AgentUser[] }>('/api/users')
      .then(d => setAgents((d.users ?? []).filter(u => u.kind === 'agent')))
      .catch(() => {})

  useEffect(() => { load() }, [])

  async function deleteAgent(id: number) {
    if (!confirm('Delete this app agent? Its API key will stop working immediately.')) return
    await adminApi.del(`/api/users/${id}`).catch(() => {})
    load()
  }

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>App Agents</h2>
      </div>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginTop: -8, marginBottom: 12 }}>
        API-key identities created from <a href="/applications" style={{ color: 'var(--accent)' }}>/applications</a> via &ldquo;+ New App Agent&rdquo;.
        These have no profile to edit — manage them here.
      </p>
      {agents.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No app agents.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Assigned apps</th>
              <th>Created</th>
              <th>Delete</th>
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
                  <button className="btn btn-red btn-xs" onClick={() => deleteAgent(a.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
