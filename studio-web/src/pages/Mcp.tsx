import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'

type McpTool = {
  name: string
  description: string
  inputSchema: {
    type: string
    properties?: Record<string, { type?: string; enum?: string[]; description?: string }>
    required?: string[]
  }
  requiredRole: string
}

type McpCatalog = {
  server: { name: string; version: string }
  instructions: string
  tools: McpTool[]
  endpoint: string
}

type McpConnection = {
  server: { name: string; version: string }
  endpoint: string
  transport: string
  auth: string
}

type ConnStatus = 'checking' | 'connected' | 'unreachable'

interface UserMcpKey {
  id: number
  label: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
}

interface CreatedKey {
  id: number
  label: string | null
  api_key: string
  rotated?: boolean
}

function CopyBtn({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const onCopy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    })
  }
  return (
    <button
      onClick={onCopy}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
      style={{
        background: 'var(--surface2)', border: '1px solid var(--border)',
        color: copied ? 'var(--green)' : 'var(--dim)', borderRadius: 4,
        padding: '2px 8px', fontSize: '.7rem', fontFamily: 'inherit',
        cursor: 'pointer', whiteSpace: 'nowrap', display: 'inline-flex',
        alignItems: 'center', gap: 4, transition: 'all .14s ease',
      }}>
      {copied ? '✓' : '⧉'} {copied ? 'Copied' : label}
    </button>
  )
}

function CopyValue({ value }: { value: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span style={{ fontFamily: 'monospace' }}>{value}</span>
      <CopyBtn value={value} />
    </span>
  )
}

function CopyableCodeBlock({ code, fontSize = '.8rem' }: { code: string; fontSize?: string }) {
  return (
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', top: 6, right: 6, zIndex: 1 }}>
        <CopyBtn value={code} />
      </div>
      <pre style={{
        background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
        padding: '14px 56px 14px 14px', fontFamily: 'monospace', fontSize, lineHeight: 1.6,
        overflowX: 'auto', whiteSpace: 'pre-wrap', margin: 0,
      }}>{code}</pre>
    </div>
  )
}

function StatusPill({ status }: { status: ConnStatus }) {
  const cfg: Record<ConnStatus, { bg: string; fg: string; border: string; label: string }> = {
    checking:    { bg: 'var(--surface2)', fg: 'var(--dim)',   border: 'var(--border)', label: 'checking…' },
    connected:   { bg: '#22c55e18',       fg: 'var(--green)', border: '#22c55e44',     label: 'connected' },
    unreachable: { bg: '#ef444418',       fg: 'var(--red)',   border: '#ef444444',     label: 'unreachable' },
  }
  const c = cfg[status]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 12px',
      borderRadius: 999, fontSize: '.75rem', fontWeight: 600,
      background: c.bg, color: c.fg, border: `1px solid ${c.border}`,
    }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'currentColor' }} />
      {c.label}
    </span>
  )
}

function PersonalKeyCard({ endpoint }: { endpoint: string }) {
  const [keys, setKeys] = useState<UserMcpKey[] | null>(null)
  const [accessibleCount, setAccessibleCount] = useState<number>(0)
  const [isAdmin, setIsAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [draftLabel, setDraftLabel] = useState('')
  const [created, setCreated] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)

  function load() {
    adminApi.get<{ keys: UserMcpKey[]; accessible_app_count: number; is_admin: boolean }>('/api/me/mcp-keys')
      .then(r => {
        setKeys(r.keys ?? [])
        setAccessibleCount(r.accessible_app_count ?? 0)
        setIsAdmin(!!r.is_admin)
      })
      .catch(() => setKeys([]))
  }

  useEffect(() => { load() }, [])

  async function createKey() {
    if (busy) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ key?: UserMcpKey; api_key?: string; accessible_app_count?: number; is_admin?: boolean }>(
        '/api/me/mcp-keys', { label: draftLabel.trim() || null },
      )
      const apiKey = r?.api_key ?? ''
      if (!apiKey) throw new Error('Server returned no key')
      setCreated({ id: r.key!.id, label: r.key!.label, api_key: apiKey })
      setCopied(false)
      setDraftLabel('')
      if (typeof r.accessible_app_count === 'number') setAccessibleCount(r.accessible_app_count)
      if (typeof r.is_admin === 'boolean') setIsAdmin(r.is_admin)
      load()
    } catch (e) {
      alert('Create failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function rotateKey(k: UserMcpKey) {
    if (!confirm(`Rotate key "${k.label || `#${k.id}`}"?\n\nThe current value stops working immediately.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ key?: UserMcpKey; api_key?: string }>(
        `/api/me/mcp-keys/${k.id}/rotate`, {},
      )
      const apiKey = r?.api_key ?? ''
      if (!apiKey) throw new Error('Server returned no key')
      setCreated({ id: k.id, label: k.label, api_key: apiKey, rotated: true })
      setCopied(false)
      load()
    } catch (e) {
      alert('Rotate failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function revokeKey(k: UserMcpKey) {
    if (!confirm(`Revoke key "${k.label || `#${k.id}`}"?\n\nThe key stops working immediately. This cannot be undone.`)) return
    await adminApi.del(`/api/me/mcp-keys/${k.id}`).catch(e => alert('Revoke failed: ' + e.message))
    load()
  }

  function copyKey() {
    if (!created) return
    navigator.clipboard.writeText(created.api_key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  const activeKeys = (keys ?? []).filter(k => !k.revoked_at)

  return (
    <div className="setting-card">
      <h3>Your MCP key</h3>
      <p>
        {isAdmin ? (
          <>
            A personal MCP key for your AppCrane admin account. Grants access to{' '}
            <strong>all {accessibleCount} app{accessibleCount === 1 ? '' : 's'}</strong> — admins
            see everything regardless of per-app role.
          </>
        ) : (
          <>
            A personal MCP key that grants access to <strong>every app where you're an Owner</strong> —
            currently <strong>{accessibleCount}</strong> app{accessibleCount === 1 ? '' : 's'}.
            Resolved dynamically: gain Owner access on a new app and your key picks it up immediately;
            lose Owner role and the corresponding tools disappear next call.
          </>
        )}
      </p>

      {keys && keys.length > 0 && (
        <table style={{ width: '100%', fontSize: '.8rem', marginBottom: 12 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Label</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Created</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Last used</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {keys.map(k => {
              const revoked = !!k.revoked_at
              return (
                <tr key={k.id} style={{ opacity: revoked ? 0.5 : 1 }}>
                  <td style={{ padding: '4px 8px' }}>{k.label || <span style={{ color: 'var(--dim)' }}>(no label)</span>}</td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)', fontSize: '.78rem' }}>{new Date(k.created_at).toLocaleDateString()}</td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)', fontSize: '.78rem' }}>
                    {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'never'}
                  </td>
                  <td style={{ padding: '4px 8px', fontSize: '.78rem' }}>
                    {revoked ? <span style={{ color: 'var(--red)' }}>revoked</span> : <span style={{ color: 'var(--green)' }}>active</span>}
                  </td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>
                    {!revoked && (
                      <span style={{ display: 'inline-flex', gap: 4 }}>
                        <button className="btn btn-xs" onClick={() => rotateKey(k)} disabled={busy}>Rotate</button>
                        <button className="btn btn-xs btn-red" onClick={() => revokeKey(k)} disabled={busy}>Revoke</button>
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          value={draftLabel}
          onChange={e => setDraftLabel(e.target.value)}
          placeholder="Optional label (e.g. macbook-air, work-laptop)"
          style={{
            flex: 1, minWidth: 180, padding: '6px 10px', fontSize: '.85rem',
            background: 'var(--bg)', border: '1px solid var(--border)',
            borderRadius: 6, color: 'var(--text)',
          }}
        />
        <button className="btn btn-accent" onClick={createKey} disabled={busy}>
          {busy ? 'Creating…' : (activeKeys.length > 0 ? '+ Another key' : 'Generate my MCP key')}
        </button>
      </div>
      {!isAdmin && accessibleCount === 0 && (
        <p style={{ marginTop: 12, fontSize: '.78rem', color: 'var(--yellow)', padding: '8px 12px', background: 'rgba(234,179,8,.06)', borderRadius: 6 }}>
          ⚠ You're not an Owner of any app yet. The key will authenticate but tools/list will be empty.
          Ask an admin to assign you Owner role on an app first.
        </p>
      )}

      {/* Created modal */}
      {created && (
        <div onClick={() => setCreated(null)} style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 12, padding: 28, maxWidth: 600, width: '92%',
          }}>
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>
              ✓ {created.rotated ? 'Key rotated' : 'Key created'}
            </h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              <strong style={{ color: 'var(--text)' }}>{created.label || `#${created.id}`}</strong> · personal · all your owned apps
            </p>
            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>API key</span>
                <button className="btn btn-accent" onClick={copyKey} style={{ fontSize: '.78rem', padding: '4px 14px' }}>
                  {copied ? '✓ Copied' : 'Copy key'}
                </button>
              </div>
              <code onClick={copyKey} style={{
                display: 'block', background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '12px 14px', fontFamily: 'monospace',
                fontSize: '.85rem', wordBreak: 'break-all', cursor: 'pointer',
                fontWeight: 700, userSelect: 'all',
              }}>
                {created.api_key}
              </code>
            </div>
            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)',
              border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Copy it now.
            </div>
            <div style={{ marginBottom: 16 }}>
              <p style={{ fontSize: '.78rem', color: 'var(--dim)', marginBottom: 6 }}>Connect with Claude Code:</p>
              <CopyableCodeBlock code={`claude mcp add --transport http appcrane ${endpoint} \\\n  --header "X-API-Key: ${created.api_key}"`} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setCreated(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export function Mcp() {
  const [catalog, setCatalog] = useState<McpCatalog | null>(null)
  const [connection, setConnection] = useState<McpConnection | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [connStatus, setConnStatus] = useState<ConnStatus>('checking')
  const [latencyMs, setLatencyMs] = useState<number | null>(null)

  useEffect(() => {
    // Public connection info — works for any authed user (admin or not).
    adminApi.get<McpConnection>('/api/mcp/connection')
      .then(setConnection)
      .catch(e => setError(e?.message || 'Failed to load MCP connection info'))

    // Admin-only catalog — silently no-op for non-admins
    adminApi.get<McpCatalog>('/api/mcp/catalog').then(setCatalog).catch(() => {})

    let cancelled = false
    function ping() {
      const t0 = performance.now()
      adminApi.post<{ jsonrpc?: string; result?: unknown; error?: { message?: string } }>(
        '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'ping' },
      )
        .then(r => {
          if (cancelled) return
          if (r && r.error) { setConnStatus('unreachable'); return }
          setConnStatus('connected')
          setLatencyMs(Math.round(performance.now() - t0))
        })
        .catch(() => { if (!cancelled) setConnStatus('unreachable') })
    }
    ping()
    const iv = setInterval(ping, 30000)
    return () => { cancelled = true; clearInterval(iv) }
  }, [])

  if (error) {
    return (
      <div className="container">
        <h2 style={{ marginBottom: 8 }}>MCP</h2>
        <div className="setting-card" style={{ borderColor: '#ef444444' }}>
          <h3 style={{ color: 'var(--red)' }}>MCP unavailable</h3>
          <p>{error}</p>
        </div>
      </div>
    )
  }
  if (!connection) {
    return (
      <div className="container">
        <h2 style={{ marginBottom: 8 }}>MCP</h2>
        <div className="setting-card"><p>Loading…</p></div>
      </div>
    )
  }

  const endpoint = window.location.origin + (connection.endpoint || '/api/mcp')
  const isAdmin = !!catalog

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>MCP</h2>
        <StatusPill status={connStatus} />
        {connStatus === 'connected' && latencyMs != null && (
          <span style={{ color: 'var(--dim)', fontSize: '.78rem', fontFamily: 'monospace' }}>
            {latencyMs}ms{isAdmin && catalog ? ` · ${catalog.tools.length} tools` : ''}
          </span>
        )}
      </div>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 16, maxWidth: 740 }}>
        The Model Context Protocol lets any compatible AI agent (Claude Code, Cursor, Continue, Cline, Zed, …)
        discover and use AppCrane tools. AppCrane handles <strong>deploys, env vars, logs, and requests</strong>;
        for <strong>code, PRs, and issues</strong> install GitHub's official MCP alongside.
      </p>

      <PersonalKeyCard endpoint={endpoint} />

      <div className="setting-card">
        <h3>Setup (Claude Code)</h3>
        <p style={{ marginBottom: 10 }}>
          <strong>One MCP, both surfaces.</strong> AppCrane proxies <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>github_*</code> tools to a per-user GitHub MCP container
          spawned on demand. You only register one MCP in your client; AppCrane handles the rest.
        </p>
        <p style={{ marginBottom: 8 }}>
          <strong style={{ color: 'var(--accent)' }}>Setup.</strong> Run this in your terminal — both your AppCrane key (from the card above)
          and your GitHub PAT (with <code style={{ fontFamily: 'monospace', fontSize: '.78rem', background: 'var(--surface2)', padding: '1px 5px', borderRadius: 3 }}>repo</code> scope):
        </p>
        <CopyableCodeBlock code={`claude mcp add --transport http appcrane ${endpoint} \\\n  --header "X-API-Key: <your-appcrane-mcp-key>" \\\n  --header "X-Github-Token: <your-github-pat>"`} />
        <p style={{ marginTop: 10, marginBottom: 0, fontSize: '.78rem', color: 'var(--dim)' }}>
          Verify: <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>claude mcp list</code> — you should see <strong>appcrane</strong>.
          The first <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>github_*</code> tool call spawns your container (1-2s cold start);
          subsequent calls are instant. Idle containers are reaped automatically (default: 10 minutes).
        </p>
      </div>

      <div className="setting-card">
        <h3>Connection</h3>
        <p>The endpoint info baked into your MCP client config:</p>
        <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '.85rem', margin: '8px 0 0' }}>
          <dt style={{ color: 'var(--dim)' }}>Endpoint</dt>
          <dd style={{ margin: 0 }}><CopyValue value={endpoint} /></dd>
          <dt style={{ color: 'var(--dim)' }}>Transport</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>HTTP (POST, JSON-RPC 2.0)</dd>
          <dt style={{ color: 'var(--dim)' }}>Auth</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>X-API-Key header</dd>
          <dt style={{ color: 'var(--dim)' }}>Server</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>{connection.server.name} v{connection.server.version}</dd>
        </dl>
      </div>

      {isAdmin && catalog && (
        <>
          <div className="setting-card">
            <h3>Server instructions</h3>
            <p>The system prompt every agent receives on connect. (Admin-only view.)</p>
            <CopyableCodeBlock code={catalog.instructions} fontSize=".78rem" />
          </div>

          <div className="setting-card">
            <h3>Available tools <span style={{ fontWeight: 400, color: 'var(--dim)', fontSize: '.82rem' }}>
              ({catalog.tools.length})
            </span></h3>
            <p>What the agent can do. Each tool's description guides the AI's decision to invoke it.</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {catalog.tools.map(t => {
                const isAdminTool = t.requiredRole === 'admin'
                return (
                  <div key={t.name} style={{
                    background: 'var(--bg)', border: '1px solid var(--border)',
                    borderRadius: 8, padding: 14,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
                      <span style={{
                        fontFamily: 'monospace', fontWeight: 700, fontSize: '.85rem', color: 'var(--accent)',
                      }}>{t.name}</span>
                      <CopyBtn value={t.name} label="" />
                      <span style={{
                        fontSize: '.65rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.4px',
                        padding: '2px 7px', borderRadius: 3,
                        color: isAdminTool ? 'var(--red)' : 'var(--green)',
                        border: `1px solid ${isAdminTool ? '#ef444444' : '#22c55e44'}`,
                        background: isAdminTool ? '#ef444410' : '#22c55e10',
                      }}>{t.requiredRole}</span>
                    </div>
                    <div style={{ color: 'var(--dim)', fontSize: '.82rem', lineHeight: 1.55, marginBottom: 6 }}>
                      {t.description}
                    </div>
                    {t.inputSchema?.properties && Object.keys(t.inputSchema.properties).length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                        {Object.keys(t.inputSchema.properties).map(k => {
                          const p = t.inputSchema.properties![k]
                          const required = (t.inputSchema.required || []).indexOf(k) !== -1
                          const typeStr = p.enum ? p.enum.join('|') : (p.type || 'any')
                          return (
                            <span key={k} title={p.description || ''} style={{
                              fontFamily: 'monospace', fontSize: '.72rem',
                              background: 'var(--surface2)',
                              border: `1px solid ${required ? 'var(--accent)' : 'var(--border)'}`,
                              color: required ? 'var(--accent)' : 'var(--text)',
                              padding: '2px 8px', borderRadius: 3,
                            }}>{k}: {typeStr}{required ? '' : '?'}</span>
                          )
                        })}
                      </div>
                    )
                    }
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
