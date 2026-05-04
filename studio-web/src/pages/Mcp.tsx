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

type ConnStatus = 'checking' | 'connected' | 'unreachable'

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

export function Mcp() {
  const [catalog, setCatalog] = useState<McpCatalog | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [connStatus, setConnStatus] = useState<ConnStatus>('checking')
  const [latencyMs, setLatencyMs] = useState<number | null>(null)

  useEffect(() => {
    adminApi.get<McpCatalog>('/api/mcp/catalog')
      .then(setCatalog)
      .catch(e => setError(e?.message || 'Failed to load MCP catalog'))

    // Live ping using the same auth header path as adminApi.
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
    const iv = setInterval(ping, 30000) // re-ping every 30s
    return () => { cancelled = true; clearInterval(iv) }
  }, [])

  if (error) {
    return (
      <div className="container">
        <h2 style={{ marginBottom: 8 }}>MCP</h2>
        <div className="setting-card" style={{ borderColor: '#ef444444' }}>
          <h3 style={{ color: 'var(--red)' }}>MCP catalog unavailable</h3>
          <p>{error}</p>
        </div>
      </div>
    )
  }
  if (!catalog) {
    return (
      <div className="container">
        <h2 style={{ marginBottom: 8 }}>MCP</h2>
        <div className="setting-card"><p>Loading…</p></div>
      </div>
    )
  }

  const endpoint = window.location.origin + (catalog.endpoint || '/api/mcp')

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>MCP</h2>
        <StatusPill status={connStatus} />
        {connStatus === 'connected' && latencyMs != null && (
          <span style={{ color: 'var(--dim)', fontSize: '.78rem', fontFamily: 'monospace' }}>
            {latencyMs}ms · {catalog.tools.length} tools
          </span>
        )}
      </div>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 16, maxWidth: 740 }}>
        The Model Context Protocol lets any compatible AI agent (Claude Code, Cursor, Continue, Cline, Zed, …)
        discover and use AppCrane tools. AppCrane handles <strong>deploys, env vars, logs, and requests</strong>;
        for <strong>code, PRs, and issues</strong> install GitHub's official MCP alongside.
      </p>

      <div className="setting-card">
        <h3>Connection</h3>
        <p>Use these values when configuring an MCP client.</p>
        <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '.85rem', margin: '8px 0' }}>
          <dt style={{ color: 'var(--dim)' }}>Endpoint</dt>
          <dd style={{ margin: 0 }}><CopyValue value={endpoint} /></dd>
          <dt style={{ color: 'var(--dim)' }}>Transport</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>HTTP (POST, JSON-RPC 2.0)</dd>
          <dt style={{ color: 'var(--dim)' }}>Auth</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>X-API-Key header (per-user)</dd>
          <dt style={{ color: 'var(--dim)' }}>Server</dt>
          <dd style={{ margin: 0, fontFamily: 'monospace' }}>{catalog.server.name} v{catalog.server.version}</dd>
        </dl>
      </div>

      <div className="setting-card">
        <h3>Quick setup (Claude Code)</h3>
        <p style={{ marginBottom: 8 }}>
          <strong style={{ color: 'var(--accent)' }}>Step 1.</strong> Connect AppCrane MCP — substitute your AppCrane API key:
        </p>
        <CopyableCodeBlock code={`claude mcp add --transport http appcrane ${endpoint} \\\n  --header "X-API-Key: <your-appcrane-api-key>"`} />
        <p style={{ marginTop: 16, marginBottom: 8 }}>
          <strong style={{ color: 'var(--accent)' }}>Step 2.</strong> Connect GitHub MCP (so the agent can read code, open PRs, manage issues) —
          substitute a GitHub PAT with <code style={{ fontFamily: 'monospace', fontSize: '.78rem', background: 'var(--surface2)', padding: '1px 5px', borderRadius: 3 }}>repo</code> scope:
        </p>
        <CopyableCodeBlock code={`claude mcp add github docker run -i --rm \\\n  -e GITHUB_PERSONAL_ACCESS_TOKEN=<your-github-pat> \\\n  ghcr.io/github/github-mcp-server`} />
        <p style={{ marginTop: 10, fontSize: '.78rem', color: 'var(--dim)' }}>
          No Docker? Use the npm form: <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>claude mcp add github npx -- -y @modelcontextprotocol/server-github</code>
          {' '}with <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>GITHUB_PERSONAL_ACCESS_TOKEN</code> in your env.
        </p>
        <p style={{ marginTop: 10, marginBottom: 0, fontSize: '.78rem', color: 'var(--dim)' }}>
          Verify both: <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>claude mcp list</code> — you should see <strong>appcrane</strong> and <strong>github</strong>.
        </p>
      </div>

      <div className="setting-card">
        <h3>Server instructions</h3>
        <p>The system prompt every agent receives on connect. It tells the agent how to use AppCrane tools.</p>
        <CopyableCodeBlock code={catalog.instructions} fontSize=".78rem" />
      </div>

      <div className="setting-card">
        <h3>Available tools <span style={{ fontWeight: 400, color: 'var(--dim)', fontSize: '.82rem' }}>
          ({catalog.tools.length})
        </span></h3>
        <p>What the agent can do. Each tool's description guides the AI's decision to invoke it.</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {catalog.tools.map(t => {
            const isAdmin = t.requiredRole === 'admin'
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
                    color: isAdmin ? 'var(--red)' : 'var(--green)',
                    border: `1px solid ${isAdmin ? '#ef444444' : '#22c55e44'}`,
                    background: isAdmin ? '#ef444410' : '#22c55e10',
                  }}>{isAdmin ? 'admin only' : 'any user'}</span>
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
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
