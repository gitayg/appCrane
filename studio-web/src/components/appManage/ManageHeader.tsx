import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../../adminApi'
import { appOpenUrl } from '../../lib/appLinks'
import { GithubSettingsModal } from './GithubSettingsModal'
import { errText } from './format'
import type { ManageCtx } from './types'

const CODE_SOURCE: Record<string, string> = {
  crane_hosted: 'Crane-hosted repo',
  managed_github: 'Managed (GitHub)',
  github_app: 'GitHub App',
  github_token: 'GitHub token',
  github_public: 'Public GitHub',
}

export function ManageHeader({ ctx }: { ctx: ManageCtx }) {
  const { app, slug, detail } = ctx
  const [menu, setMenu] = useState(false)
  const [github, setGithub] = useState(false)
  const [iconUrl, setIconUrl] = useState<string | null>(app.has_icon ? `/api/apps/${slug}/icon?v=${Date.now()}` : null)
  const fileRef = useRef<HTMLInputElement | null>(null)
  const menuRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!menu) return
    const close = (e: MouseEvent) => { if (!menuRef.current?.contains(e.target as Node)) setMenu(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [menu])

  const owners = app.owners?.length ? app.owners : app.owner ? [app.owner] : []
  const hook = detail?.webhook
  const autoDeploy = !hook ? 'off' : [hook.auto_deploy_sandbox ? 'sandbox' : null, hook.auto_deploy_prod ? 'production' : null].filter(Boolean).join(' + ') || 'off'
  const gitSource = app.github_url || app.source_type === 'github' || app.source_type === 'managed'
  const openUrl = appOpenUrl(app, 'production')
  const prodDown = app.production?.health?.status === 'down'

  async function uploadIcon(file: File) {
    const fd = new FormData()
    fd.append('icon', file)
    try {
      const r = await fetch(`/api/apps/${slug}/icon`, { method: 'POST', headers: adminApi.authHeaders(), body: fd })
      if (!r.ok) throw new Error(`Icon upload failed (HTTP ${r.status})`)
      setIconUrl(URL.createObjectURL(file))
      ctx.onMsg({ text: 'Icon updated', ok: true })
    } catch (e) {
      ctx.onMsg({ text: errText(e), ok: false })
    }
  }

  async function deleteApp() {
    setMenu(false)
    if (!confirm(`Delete "${app.name}"?`)) return
    if (!confirm(`This is irreversible. Really delete "${app.name}"?`)) return
    try {
      await adminApi.del(`/api/apps/${slug}?confirm=true`)
      window.location.assign('/applications')
    } catch (e) {
      ctx.onMsg({ text: errText(e), ok: false })
    }
  }

  return (
    <div className="am2-head">
      <button className="am2-icon" onClick={() => fileRef.current?.click()} title="Upload icon" aria-label="Upload app icon">
        {iconUrl ? <img src={iconUrl} alt="" /> : app.name.charAt(0).toUpperCase()}
      </button>
      <input ref={fileRef} type="file" accept="image/*" hidden onChange={e => { const f = e.target.files?.[0]; if (f) void uploadIcon(f) }} />
      <div className="am2-title">
        <h1>{app.name}</h1>
        <div className="am2-summary">
          {owners.length
            ? <span title={owners.map(o => o.email ? `${o.name} (${o.email})` : o.name).join('\n')}>Owner: {owners.map(o => o.name).join(', ')}</span>
            : <span className="am2-pill warn" title="No owner assigned. Set one on the Overview tab (Ownership).">No owner</span>}
          <span className="sep">·</span>
          <span>{gitSource ? (app.github_url ? 'GitHub connected' : (CODE_SOURCE[app.code_source || ''] || 'Git source')) : 'No GitHub repository'}</span>
          {app.code_source && app.github_url && CODE_SOURCE[app.code_source] && <span className="am2-dim">({CODE_SOURCE[app.code_source]})</span>}
          <span className="sep">·</span>
          <span>Auto-deploy {autoDeploy}</span>
        </div>
      </div>
      <div className="am2-head-actions" ref={menuRef}>
        {prodDown
          ? <span className="btn btn-sm" aria-disabled="true" title="Production is down">Open app</span>
          : <a className="btn btn-sm btn-accent" href={openUrl} target="_blank" rel="noreferrer">Open app</a>}
        <button className="btn btn-sm" aria-haspopup="menu" aria-expanded={menu} aria-label="More actions" onClick={() => setMenu(m => !m)}>⋯</button>
        {menu && (
          <div className="am2-menu" role="menu">
            <button role="menuitem" onClick={() => { setMenu(false); setGithub(true) }}>GitHub settings…</button>
            {app.github_url && <a role="menuitem" href={app.github_url} target="_blank" rel="noreferrer">Open repository ↗</a>}
            <hr />
            <button role="menuitem" className="danger" onClick={deleteApp}>Delete app…</button>
          </div>
        )}
      </div>
      {github && <GithubSettingsModal ctx={ctx} onClose={() => setGithub(false)} />}
    </div>
  )
}
