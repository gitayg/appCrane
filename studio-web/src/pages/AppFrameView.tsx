import { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { adminApi } from '../adminApi'
import { usePeek, type PeekCtx } from '../hooks/usePeek'
import { RequestModal } from '../components/runtime-topbar/RequestModal'
import { Icon } from '../components/icons'

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
  const navigate = useNavigate()
  const [stage, setStage] = useState<Stage | null>(null)
  const [status, setStatus] = useState<'loading' | 'ready' | 'notfound' | 'empty'>('empty')
  const [folded, setFolded] = useState(false)
  const [refreshNonce, setRefreshNonce] = useState(0)
  const topbarRef = useRef<HTMLElement>(null)
  const iframeRef = useRef<HTMLIFrameElement>(null)

  // v2.14.1: point-and-click Request flow (restored from the old launcher
  // frame). Click "Request" → pick an element in the app → describe the change.
  const peek = usePeek(iframeRef)
  const [requestCtx, setRequestCtx] = useState<PeekCtx | null>(null)
  useEffect(() => {
    if (peek.ctx) { setRequestCtx(peek.ctx); peek.clear() }
  }, [peek.ctx]) // eslint-disable-line react-hooks/exhaustive-deps

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

    const onBack = () => navigate('/launch')
    const onRefresh = () => {
      // Cache-bust the URL (new _ts) so the keyed iframe fully remounts and the
      // app's HTML is refetched — picking up a new deploy's content-hashed
      // assets. Also re-check the live version (below).
      setRefreshNonce(n => n + 1)
      setStage(s => {
        if (!s) return s
        const base = s.env === 'sandbox' ? s.sandUrl : s.prodUrl
        const sep = base.includes('?') ? '&' : '?'
        return { ...s, url: `${base}${sep}_ts=${Date.now()}` }
      })
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

  // v2.14.1: the topbar opens with the deploy-record version from /api/apps.
  // Re-fetch the app's LIVE version (its health endpoint) on open, env switch,
  // and every Refresh — so after a redeploy the pill matches what's running.
  useEffect(() => {
    if (!stage?.slug) return
    const s = stage.slug
    const env = stage.env
    adminApi.get<{ version?: string }>(`/api/apps/${encodeURIComponent(s)}/live-version/${env}`)
      .then(r => {
        if (!r?.version) return
        setStage(prev => {
          if (!prev || prev.slug !== s) return prev
          return env === 'sandbox' ? { ...prev, sandVersion: r.version! } : { ...prev, prodVersion: r.version! }
        })
      })
      .catch(() => {})
  }, [stage?.slug, stage?.env, refreshNonce])

  if (status === 'ready' && stage) {
    return (
      <>
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
        >
          <span slot="actions" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            {stage.hasGithub && (
              <button
                type="button"
                className={'crane-topbar-btn' + (peek.active || requestCtx ? ' active' : '')}
                onClick={() => {
                  if (requestCtx) { setRequestCtx(null); return }
                  if (peek.active) { peek.stop(); return }
                  peek.start()
                }}
                title={peek.active
                  ? 'Click an element in the app, then describe the change. Esc to cancel.'
                  : 'Point at an element to request an enhancement'}
              ><Icon.Lightbulb size={14} /> {peek.active ? 'Pick…' : 'Request'}</button>
            )}
          </span>
        </crane-app-topbar>
        {stage.url && <iframe key={stage.url} ref={iframeRef} className="lstage-iframe" src={stage.url} title={stage.name} />}
      </div>
      {requestCtx && (
        <RequestModal
          slug={stage.slug}
          appName={stage.name}
          peekCtx={requestCtx}
          onClose={() => setRequestCtx(null)}
        />
      )}
      </>
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
