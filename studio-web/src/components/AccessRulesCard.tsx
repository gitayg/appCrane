import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Path role rules for one environment (/api/apps/:slug/access-rules). The gate
// refuses a request whose path matches a rule unless the person's role on the
// app reaches it. deployhub.json rules are shown read-only (the next deploy
// replaces them); the dashboard rules are edited here and apply at once. Both
// sets apply together and the strictest matching rule wins.
//
// Owners, admins and platform admins only: 403 and 404 render nothing.

type EnvName = 'production' | 'sandbox'

interface Rule { path: string; methods?: string[]; roles: string[] }
interface EnvRules { manifest: Rule[]; dashboard: Rule[] }
interface ListResp { rules: Record<EnvName, EnvRules> }

interface Props {
  slug: string
  env: EnvName
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

const EXAMPLE = '[\n  { "path": "/admin/*", "roles": ["admin"] },\n  { "path": "/api/settings", "methods": ["PUT", "POST"], "roles": ["admin"] }\n]'

export function AccessRulesCard({ slug, env, reload, onMsg }: Props) {
  const [rules, setRules] = useState<EnvRules | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await fetch(`/api/apps/${encodeURIComponent(slug)}/access-rules`, { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 404) { setHidden(true); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      setHidden(false)
      setRules((body as ListResp).rules[env])
    } catch (e) {
      setError((e as Error).message || 'Cannot load access rules')
    }
  }, [slug, env])

  useEffect(() => { setDraft(null); void load() }, [load, reload])

  if (hidden) return null

  async function save() {
    if (draft === null) return
    let parsed: unknown
    try {
      parsed = JSON.parse(draft.trim() || '[]')
    } catch (e) {
      onMsg({ text: `Not valid JSON: ${(e as Error).message}`, ok: false })
      return
    }
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${encodeURIComponent(slug)}/access-rules/${env}`, { rules: parsed })
      onMsg({ text: `Access rules saved for ${env}`, ok: true })
      setDraft(null)
      void load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  const table = (list: Rule[]) => (
    <table>
      <thead><tr><th>Path</th><th>Methods</th><th>Roles</th></tr></thead>
      <tbody>
        {list.map((r, i) => (
          <tr key={`${i}/${r.path}`}>
            <td className="am-mono">{r.path}</td>
            <td className="am-mono">{r.methods?.join(', ') || 'all'}</td>
            <td>{r.roles.join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  return (
    <>
      <h2 className="am-h2">Access rules</h2>
      <div className="am-card">
        <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 8 }}>
          Paths in {env} that need more than access to the app. A listed role also admits the roles above it
          (viewer, user, admin, owner). Every matching rule applies and the strictest wins; other paths are open to everyone with access.
        </div>
        {error ? (
          <span style={{ color: 'var(--red)' }}>{error}</span>
        ) : rules === null ? 'Loading...' : (
          <>
            <div style={{ fontWeight: 600, margin: '4px 0' }}>From deployhub.json</div>
            {rules.manifest.length ? table(rules.manifest) : <span style={{ color: 'var(--dim)' }}>None</span>}
            <div style={{ fontWeight: 600, margin: '12px 0 4px' }}>Set here</div>
            {draft === null ? (
              <>
                {rules.dashboard.length ? table(rules.dashboard) : <span style={{ color: 'var(--dim)' }}>None</span>}
                <div style={{ marginTop: 8 }}>
                  <button
                    className="btn btn-sm btn-dim"
                    onClick={() => setDraft(rules.dashboard.length ? JSON.stringify(rules.dashboard, null, 2) : '')}
                  >Edit</button>
                </div>
              </>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <textarea
                  className="am-input am-mono"
                  rows={10}
                  spellCheck={false}
                  placeholder={EXAMPLE}
                  value={draft}
                  onChange={e => setDraft(e.target.value)}
                />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-sm" disabled={busy} onClick={save}>Save</button>
                  <button className="btn btn-sm btn-dim" onClick={() => setDraft(null)}>Cancel</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  )
}
