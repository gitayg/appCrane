import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { appOpenUrl } from '../../lib/appLinks'
import { AppMcpCard } from '../appMcp/AppMcpCard'
import { EnvTable, type EnvRow } from './EnvTable'
import { IngressModal, publishesPort } from './IngressModal'
import { healthOf } from './OverviewTab'
import { errText } from './format'
import { ENVS, type ManageCtx, type ManagedApp } from './types'

type PutRes = { app?: ManagedApp; error?: { message?: string } }

/** Addresses and doors: URL, ingress, custom domain and its redirects, embedders, SSO bypass, the app's MCP server. */
export function NetworkTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, app, isPlatformAdmin } = ctx
  const [ingress, setIngress] = useState(false)

  async function put(body: Record<string, unknown>): Promise<PutRes | null> {
    try {
      const r = await adminApi.put<PutRes>(`/api/apps/${slug}`, body)
      if (r?.error) { ctx.onMsg({ text: 'Failed: ' + (r.error.message || 'unknown'), ok: false }); return null }
      return r
    } catch (e) { ctx.onMsg({ text: 'Failed: ' + errText(e), ok: false }); return null }
  }

  async function setFrameAncestors() {
    const help = "Allowed embedders (CSP frame-ancestors syntax).\n\nExamples:\n  'self'                              (default, only same origin)\n  'self' https://portal.example.com   (also allow one external portal)\n  'self' https://*.example.com        (any example.com subdomain)\n\nLeave blank to reset to default."
    const val = prompt(help, app.frame_ancestors ?? '')
    if (val === null) return
    if (await put({ frame_ancestors: val.trim() || null })) ctx.patchApp({ frame_ancestors: val.trim() || null })
  }

  async function setBypass() {
    const current = (Array.isArray(app.auth_bypass_paths) ? app.auth_bypass_paths : []).join(', ')
    const help = "Path prefixes that bypass SSO on this app (comma- or newline-separated).\n\nEach prefix must:\n  - start with '/' (e.g. /ws/local-runner)\n  - not overlap /api, /admin, /login, /portal, /health, /__crashed\n  - not contain '..', '//', or whitespace\n\nRequests under these prefixes reach your app with NO X-AppCrane-* identity\nheaders. Your app must authenticate them itself (e.g. token in query string).\nCaddy logs these paths with the query string redacted.\n\nLeave blank to clear all bypass paths."
    const val = prompt(help, current)
    if (val === null) return
    const list = val.split(/[,\n]/).map(s => s.trim()).filter(Boolean)
    if (await put({ auth_bypass_paths: list })) ctx.patchApp({ auth_bypass_paths: list.length ? list : null })
  }

  async function setDomain() {
    const help = "Custom domain for this app (served at the root of that domain).\n\ne.g. myapp.example.com\n\nThe app is served there with NO topbar and, unless \"Require AppCrane sign-in\" is on, NO AppCrane sign-in: it does its own. Maps to PRODUCTION. Point the domain's DNS at this host; Caddy provisions HTTPS. The /" + slug + " address on AppCrane stays for ops.\n\nIf you CHANGE the domain, the old one is kept automatically as a 301 redirect.\n\nLeave blank to remove the custom domain."
    const val = prompt(help, app.domain ?? '')
    if (val === null) return
    const next = val.trim() || null
    if (next === (app.domain ?? null)) return
    const r = await put({ domain: next })
    if (r) { ctx.patchApp({ domain: next, domain_aliases: r.app?.domain_aliases ?? app.domain_aliases }); ctx.refresh() }
  }

  async function setDomainAuth(on: boolean) {
    if (await put({ custom_domain_auth: on ? 1 : 0 })) ctx.patchApp({ custom_domain_auth: on ? 1 : 0 })
  }

  async function addAlias() {
    const v = prompt(`Old domain that should 301-redirect to ${app.domain} (path preserved):`, '')
    if (!v?.trim()) return
    try {
      const r = await adminApi.post<{ alias?: { id: number; domain: string; source: string; created_at: string }; error?: { message?: string } }>(`/api/apps/${slug}/domain-aliases`, { domain: v.trim() })
      if (r?.error) return ctx.onMsg({ text: 'Failed: ' + (r.error.message || 'unknown'), ok: false })
      if (r?.alias) { const a = r.alias; ctx.patchApp({ domain_aliases: [...(app.domain_aliases || []).filter(x => x.id !== a.id), a] }) }
    } catch (e) { ctx.onMsg({ text: 'Failed: ' + errText(e), ok: false }) }
  }

  async function removeAlias(id: number, domain: string) {
    if (!confirm(`Stop redirecting ${domain}?`)) return
    try { await adminApi.del(`/api/apps/${slug}/domain-aliases/${id}`); ctx.patchApp({ domain_aliases: (app.domain_aliases || []).filter(a => a.id !== id) }) }
    catch (e) { ctx.onMsg({ text: 'Failed: ' + errText(e), ok: false }) }
  }

  const published = publishesPort(app.ingress_type)
  const bypass = Array.isArray(app.auth_bypass_paths) ? app.auth_bypass_paths : []
  const rows: EnvRow[] = [
    { key: 'url', label: 'URL', production: <a className="am2-mono" href={appOpenUrl(app, 'production')} target="_blank" rel="noreferrer">{appOpenUrl(app, 'production')}</a>, sandbox: app.sandbox_visible === false ? undefined : <a className="am2-mono" href={appOpenUrl(app, 'sandbox')} target="_blank" rel="noreferrer">{appOpenUrl(app, 'sandbox')}</a> },
    {
      key: 'ingress', label: 'Ingress',
      production: (
        <span className="am2-row">
          <span className={'am2-pill' + (published ? ' bad' : '')}>{app.ingress_type || 'http'}</span>
          {published && <span className="am2-mono">host :{app.public_port ?? '—'} → container :{app.ingress_type === 'dual' ? (app.data_plane_port ?? '—') : 3000}</span>}
          {app.publish_drift && app.publish_applied === false && <span className="am2-pill warn" title={app.publish_drift.message}>Not applied yet</span>}
          {!published && !!app.pending_port_release && <span className="am2-pill warn">:{app.pending_port_release} still open until restart</span>}
          <button className="btn btn-xs" onClick={() => setIngress(true)}>{isPlatformAdmin ? 'Change…' : 'Details…'}</button>
        </span>
      ),
      sandbox: published && app.sandbox_public_port
        ? <span className="am2-row"><span className="am2-pill bad">published</span><span className="am2-mono">host :{app.sandbox_public_port}</span></span>
        : <span className="am2-dim">Not published</span>,
    },
    {
      key: 'domain', label: 'Custom domain',
      production: (
        <div style={{ display: 'grid', gap: 6 }}>
          <span className="am2-row">
            {app.domain ? <span className="am2-mono">{app.domain}</span> : <span className="am2-dim">None</span>}
            <button className="btn btn-xs" onClick={setDomain}>{app.domain ? 'Change…' : 'Set…'}</button>
          </span>
          {app.domain && (
            <label className="am2-row am2-small" title={`When on, visitors to ${app.domain} sign in with AppCrane before they reach the app.`}>
              <input type="checkbox" checked={!!app.custom_domain_auth} onChange={e => setDomainAuth(e.target.checked)} /> Require AppCrane sign-in on the custom domain
            </label>
          )}
        </div>
      ),
      sandbox: <span className="am2-dim">A custom domain serves production</span>,
    },
    ...(app.domain ? [{
      key: 'aliases', label: 'Redirects',
      production: (
        <div style={{ display: 'grid', gap: 4 }}>
          {(app.domain_aliases || []).map(a => (
            <span key={a.id} className="am2-row"><span className="am2-mono">{a.domain}</span>{a.source === 'auto' && <span className="am2-dim am2-small">(auto)</span>}<button className="btn btn-xs" onClick={() => removeAlias(a.id, a.domain)} aria-label={`Remove redirect ${a.domain}`}>✕</button></span>
          ))}
          <span><button className="btn btn-xs" onClick={addAlias}>Add redirect…</button></span>
        </div>
      ),
      sandbox: undefined,
    }] : []),
    {
      key: 'embed', label: 'Allowed embedders',
      both: <span className="am2-row"><span className="am2-mono">{app.frame_ancestors || "'self' (default)"}</span><button className="btn btn-xs" onClick={setFrameAncestors}>Change…</button></span>,
    },
    {
      key: 'bypass', label: 'SSO bypass paths',
      both: (
        <span className="am2-row">
          {bypass.length ? bypass.map(p => <code key={p} className="am2-mono am2-pill warn">{p}</code>) : <span className="am2-dim">None</span>}
          <button className="btn btn-xs" onClick={setBypass} title="Path prefixes that bypass SSO (advanced: the app must authenticate them itself)">Change…</button>
        </span>
      ),
    },
    {
      key: 'mcp', label: 'App MCP server',
      production: <AppMcpCard slug={slug} env="production" reload={ctx.reload} onMsg={ctx.onMsg} />,
      sandbox: app.sandbox_visible === false ? undefined : <AppMcpCard slug={slug} env="sandbox" reload={ctx.reload} onMsg={ctx.onMsg} />,
    },
  ]

  return (
    <>
      <EnvTable caption="Network" rows={rows} dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))} />
      {ingress && <IngressModal app={app} isPlatformAdmin={isPlatformAdmin} onClose={() => setIngress(false)} onSaved={ctx.patchApp} />}
    </>
  )
}
