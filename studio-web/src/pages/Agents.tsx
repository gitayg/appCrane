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
  // MCP-key issuance modal — separate from legacy `newKey` so they can't
  // collide when the operator runs both flows in quick succession.
  const [mcpKeyModal, setMcpKeyModal] = useState<{
    open: boolean
    userName?: string
    userEmail?: string
    apiKey?: string
    setupCmd?: string
    copiedKey?: boolean
    copiedCmd?: boolean
  }>({ open: false })

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

  /**
   * Issue an MCP-only (`dhk_mcp_*`) key for this agent on behalf of the
   * admin — same admin endpoint that Users.tsx uses. The legacy key flow
   * (`dhk_admin_*` / `dhk_user_*`) above stays for CI/REST consumers; the
   * MCP key here is the recommended option for Claude Code agents.
   */
  async function issueMcpKey(agent: AgentUser) {
    if (!confirm(`Issue an MCP key for ${agent.name}?\n\nThe key will be shown once. You'll need to send it to whoever runs the agent via a secure channel.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{
        api_key?: string
        target?: { name: string; email: string }
      }>(`/api/users/${agent.id}/mcp-keys`, { label: `admin-issued-${new Date().toISOString().slice(0, 10)}` })
      if (!r?.api_key) throw new Error('Server returned no key')
      const origin = typeof window !== 'undefined' ? window.location.origin : 'https://your-appcrane-host'
      const setupCmd =
        `claude mcp add --transport http appcrane ${origin}/api/mcp \\\n` +
        `  --header "X-API-Key: ${r.api_key}" \\\n` +
        `  --header "X-Github-Token: <YOUR_GITHUB_PAT>"`
      setMcpKeyModal({
        open: true,
        userName: r.target?.name || agent.name,
        userEmail: r.target?.email || agent.email,
        apiKey: r.api_key,
        setupCmd,
      })
    } catch (e) {
      alert('Could not issue MCP key: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
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
        API-key identities for agents and external integrations. Two key types per agent:
        the <strong>+ MCP key</strong> button (per row) issues a <code style={{ fontFamily: 'monospace' }}>dhk_mcp_*</code> scoped key — recommended for Claude Code / Cursor / Cline (restricted to <code style={{ fontFamily: 'monospace' }}>/api/mcp</code>);
        the <strong>+ New API Key</strong> button (top right) creates a legacy <code style={{ fontFamily: 'monospace' }}>dhk_admin_* / dhk_user_*</code> key for CI/CD and REST consumers.
        Keys are shown once on creation. Assign apps to an agent from <a href="/applications" style={{ color: 'var(--accent)' }}>/applications</a> if it should be scoped.
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
                      onClick={() => issueMcpKey(a)}
                      disabled={busy}
                      title="Issue an MCP-scoped key (dhk_mcp_*). Recommended for Claude Code / Cursor / Cline agents — restricted to /api/mcp endpoints, smaller blast radius if leaked."
                    >
                      + MCP key
                    </button>
                    <button
                      className="btn btn-xs"
                      onClick={() => rotateKey(a)}
                      disabled={busy}
                      title="Rotate the legacy API key (dhk_admin_* / dhk_user_*). For CI/REST consumers; not recommended for new MCP setups."
                    >
                      Rotate legacy key
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

      {mcpKeyModal.open && (
        <div
          onClick={() => setMcpKeyModal({ open: false })}
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
              borderRadius: 12, padding: 28, maxWidth: 720, width: '94%',
              boxShadow: '0 24px 64px rgba(0,0,0,.5)',
            }}
          >
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>
              ✓ MCP key issued
            </h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              For <strong style={{ color: 'var(--text)' }}>{mcpKeyModal.userName}</strong>
              {mcpKeyModal.userEmail ? <> · {mcpKeyModal.userEmail}</> : null}
            </p>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>API key</span>
                <button
                  className="btn btn-xs"
                  onClick={() => {
                    if (mcpKeyModal.apiKey) {
                      navigator.clipboard.writeText(mcpKeyModal.apiKey).then(() => {
                        setMcpKeyModal(s => ({ ...s, copiedKey: true }))
                        setTimeout(() => setMcpKeyModal(s => ({ ...s, copiedKey: false })), 1800)
                      })
                    }
                  }}
                >
                  {mcpKeyModal.copiedKey ? '✓ Copied' : 'Copy key'}
                </button>
              </div>
              <code
                style={{
                  display: 'block', background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace',
                  fontSize: '.82rem', wordBreak: 'break-all', userSelect: 'all',
                }}
              >
                {mcpKeyModal.apiKey}
              </code>
            </div>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>Setup command (paste-ready)</span>
                <button
                  className="btn btn-xs"
                  onClick={() => {
                    if (mcpKeyModal.setupCmd) {
                      navigator.clipboard.writeText(mcpKeyModal.setupCmd).then(() => {
                        setMcpKeyModal(s => ({ ...s, copiedCmd: true }))
                        setTimeout(() => setMcpKeyModal(s => ({ ...s, copiedCmd: false })), 1800)
                      })
                    }
                  }}
                >
                  {mcpKeyModal.copiedCmd ? '✓ Copied' : 'Copy command'}
                </button>
              </div>
              <pre
                style={{
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace',
                  fontSize: '.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  userSelect: 'all', margin: 0,
                }}
              >
                {mcpKeyModal.setupCmd}
              </pre>
              <p style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6, marginBottom: 0 }}>
                The recipient replaces <code style={{ fontFamily: 'monospace' }}>&lt;YOUR_GITHUB_PAT&gt;</code> with their own GitHub PAT before running.
              </p>
            </div>

            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)',
              border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow, #f59e0b)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Send it via a secure channel (encrypted message, password manager, etc.).
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setMcpKeyModal({ open: false })}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
