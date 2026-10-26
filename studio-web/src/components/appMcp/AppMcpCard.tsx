import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// The app's own MCP server (GET /api/mcp/apps/:slug/tools): its URL, a
// copyable `claude mcp add` line, and the tools deployhub.json `mcp` declares,
// marked with whether the viewer's role may call each one. Renders nothing
// when the app declares no tools in this environment or the viewer has no
// access to the app.

type EnvName = 'production' | 'sandbox'

interface Tool { name: string; description: string; method: string; path: string; roles: string[]; readOnly: boolean; allowed: boolean }
interface EnvInfo { url: string; mode: 'tools' | 'proxy'; mcp_path: string | null; claude_command: string; tool_list: Tool[] }
interface Resp { role: string; envs: Record<EnvName, EnvInfo | null> }

interface Props {
  slug: string
  env: EnvName
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

export function AppMcpCard({ slug, env, reload, onMsg }: Props) {
  const [info, setInfo] = useState<EnvInfo | null>(null)
  const [role, setRole] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await fetch(`/api/mcp/apps/${encodeURIComponent(slug)}/tools`, { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 404) { setInfo(null); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      setInfo((body as Resp).envs[env])
      setRole((body as Resp).role)
    } catch (e) {
      setError((e as Error).message || 'Cannot load MCP tools')
    }
  }, [slug, env])

  useEffect(() => { void load() }, [load, reload])

  if (error) {
    return (
      <>
        <h2 className="am-h2">MCP tools</h2>
        <div className="am-card"><span style={{ color: 'var(--red)' }}>{error}</span></div>
      </>
    )
  }
  if (!info) return null

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      onMsg({ text: 'Copied', ok: true })
    } catch {
      onMsg({ text: 'Copy failed: select the text and copy it', ok: false })
    }
  }

  return (
    <>
      <h2 className="am-h2">MCP tools</h2>
      <div className="am-card">
        <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 8 }}>
          Agents can use this app in {env} as an MCP server. Every call acts as the person connected: AppCrane checks their
          role on the app and the access rules, and the app receives their signed identity. Your role here: {role}.
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 6 }}>
          <code className="am-mono" style={{ wordBreak: 'break-all' }}>{info.url}</code>
          <button className="btn btn-sm btn-dim" onClick={() => void copy(info.url)}>Copy URL</button>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
          <code className="am-mono" style={{ wordBreak: 'break-all' }}>{info.claude_command}</code>
          <button className="btn btn-sm btn-dim" onClick={() => void copy(info.claude_command)}>Copy</button>
        </div>
        {info.mode === 'proxy' ? (
          <span style={{ color: 'var(--dim)' }}>
            The app serves its own MCP tools at <span className="am-mono">{info.mcp_path}</span>; AppCrane forwards to it.
          </span>
        ) : (
          <table>
            <thead><tr><th>Tool</th><th>Request</th><th>Roles</th><th>You</th></tr></thead>
            <tbody>
              {info.tool_list.map(t => (
                <tr key={t.name} title={t.description}>
                  <td className="am-mono">{t.name}{t.readOnly ? ' (read-only)' : ''}</td>
                  <td className="am-mono">{t.method} {t.path}</td>
                  <td>{t.roles.join(', ')}</td>
                  <td>{t.allowed ? 'can call' : 'cannot call'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
