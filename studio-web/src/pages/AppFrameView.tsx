import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { adminApi } from '../adminApi'

/**
 * Inline app view (v2.13.0). Renders a single app at /launch/:slug, hosted by
 * the <crane-app-topbar> custom element (env switch, per-env version, back,
 * refresh, fold). This is where the launcher's tile/sidebar click lands now
 * that the app list lives in the main nav (Layout). A bare /launch with no
 * slug shows a "select an app" placeholder.
 *
 * The ask/request/bug drawers from the full-screen FrameOverlay are not hosted
 * here — those stay on the Applications manage path.
 */

interface AppRow {
  slug:        string
  name:        string
  has_icon?:   boolean
  app_role?:   'admin' | 'owner' | 'user' | 'viewer' | 'none'
  github_url?: string
  production?: { health?: { status: string }; deploy?: { version?: string } }
  sandbox?:    { health?: { status: string }; deploy?: { version?: string } }
}

interface Stage {
  slug: string
  name: string
  hasIcon: boolean
  hasGithub: boolean
  env: 'production' | 'sandbox'
  url: string
  prodUrl: string
  sandUrl: string
  prodVersion: string
  sandVersion: string
}

function buildStage(app: AppRow): Stage {
  const prodUrl = `/${app.slug}`
  const sandUrl = `/${app.slug}-sandbox`
  const prodOk = app.production?.health?.status === 'healthy'
  const sandOk = app.sandbox?.health?.status === 'healthy'
  const useSand = !prodOk && sandOk
  return {
    slug: app.slug,
    name: app.name,
    hasIcon: !!app.has_icon,
    hasGithub: !!app.github_url,
    env: useSand ? 'sandbox' : 'production',
    url: useSand ? sandUrl : prodUrl,
    prodUrl, sandUrl,
    prodVersion: app.production?.deploy?.version || '',
    sandVersion: app.sandbox?.deploy?.version || '',
  }
}

export function AppFrameView() {
  const { slug } = useParams<{ slug: string }>()
  const [stage, setStage] = useState<Stage | null>(null)
  const [status, setStatus] = useState<'loading' | 'ready' | 'notfound' | 'empty'>('empty')
  const [folded, setFolded] = useState(false)
  const topbarRef = useRef<HTMLElement>(null)

  // Resolve the slug → app row → stage. /api/apps is already access-filtered
  // server-side, so a slug missing from the list means no access / no app.
  useEffect(() => {
    if (!slug) { setStage(null); setStatus('empty'); return }
    let cancelled = false
    setStatus('loading')
    setFolded(false)
    adminApi.get<{ apps: AppRow[] }>('/api/apps')
      .then(r => {
        if (cancelled) return
        const app = (r?.apps || []).find(a => a.slug === slug)
        if (!app) { setStage(null); setStatus('notfound'); return }
        setStage(buildStage(app))
        setStatus('ready')
      })
      .catch(() => { if (!cancelled) { setStage(null); setStatus('notfound') } })
    return () => { cancelled = true }
  }, [slug])

  // The topbar is a Custom Element firing CustomEvents (not React synthetic).
  useEffect(() => {
    const el = topbarRef.current
    if (!el || !stage) return

    const onBack = () => { window.location.href = '/launch' }
    const onRefresh = () => {
      setStage(s => (s ? { ...s, url: '' } : s))
      setTimeout(() => setStage(s => {
        if (!s) return s
        const base = s.env === 'sandbox' ? s.sandUrl : s.prodUrl
        const sep = base.includes('?') ? '&' : '?'
        return { ...s, url: `${base}${sep}_ts=${Date.now()}` }
      }), 0)
    }
    const onEnv = (e: Event) => {
      const env = (e as CustomEvent<{ env: 'production' | 'sandbox' }>).detail.env
      setStage(s => (s ? { ...s, env, url: env === 'sandbox' ? s.sandUrl : s.prodUrl } : s))
    }
    const onFold = (e: Event) => setFolded((e as CustomEvent<{ folded: boolean }>).detail.folded)

    el.addEventListener('crane-back',        onBack)
    el.addEventListener('crane-refresh',     onRefresh)
    el.addEventListener('crane-env-change',  onEnv)
    el.addEventListener('crane-fold-toggle', onFold)
    return () => {
      el.removeEventListener('crane-back',        onBack)
      el.removeEventListener('crane-refresh',     onRefresh)
      el.removeEventListener('crane-env-change',  onEnv)
      el.removeEventListener('crane-fold-toggle', onFold)
    }
  }, [stage?.slug])

  if (status === 'ready' && stage) {
    return (
      <div className="lstage-frame">
        <crane-app-topbar
          ref={topbarRef}
          app-name={stage.name}
          app-icon-url={stage.hasIcon ? `/api/apps/${stage.slug}/icon` : ''}
          app-slug={stage.slug}
          prod-version={stage.prodVersion}
          sand-version={stage.sandVersion}
          prod-url={stage.prodUrl}
          sand-url={stage.sandUrl}
          env={stage.env}
          current-url={stage.url}
          {...(folded ? { folded: '' } : {})}
        />
        {stage.url && <iframe className="lstage-iframe" src={stage.url} title={stage.name} />}
      </div>
    )
  }

  return (
    <div className="lstage-empty">
      <div className="lstage-empty-inner">
        <div className="lstage-empty-glyph">🚀</div>
        <h3>
          {status === 'loading' ? 'Opening…'
            : status === 'notfound' ? 'App not found'
            : 'Select an app'}
        </h3>
        <p>
          {status === 'notfound'
            ? 'It may not exist, or you may not have access to it.'
            : 'Pick an app from the sidebar to open it here.'}
        </p>
      </div>
    </div>
  )
}
