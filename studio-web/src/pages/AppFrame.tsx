import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'
import { usePeek, type PeekCtx } from '../hooks/usePeek'
import { RequestModal } from '../components/runtime-topbar/RequestModal'
import { Icon } from '../components/icons'

/**
 * One app rendered inline, hosted by the <crane-app-topbar> element (env switch,
 * per-env version, refresh, fold) + point-and-click Request flow. Takes the slug
 * as a prop and stays mounted while hidden (display toggled by `active`) so the
 * app tabs keep their iframes — and their state — alive when you switch away.
 * Back closes the tab.
 */

interface AppRow {
  slug:        string
  name:        string
  has_icon?:   boolean
  github_url?: string
  production?: { health?: { status: string }; deploy?: { version?: string; status?: string } }
  sandbox?:    { health?: { status: string }; deploy?: { version?: string; status?: string } }
}

interface Stage {
  slug: string; name: string; hasIcon: boolean; hasGithub: boolean
  env: 'production' | 'sandbox'
  url: string; prodUrl: string; sandUrl: string; prodVersion: string; sandVersion: string
}

function buildStage(app: AppRow): Stage {
  const prodUrl = `/${app.slug}`
  const sandUrl = `/${app.slug}-sandbox`
  const prodOk = app.production?.health?.status === 'healthy'
  const sandOk = app.sandbox?.health?.status === 'healthy'
  // v2.32.1: deployment presence decides first, health only breaks ties.
  // Health is 'unknown' whenever an app has no health-check row — the common
  // case — so keying solely off `healthy` sent a sandbox-only app to
  // production (unknown !== healthy on both sides ⇒ production), opening a URL
  // with nothing behind it. Prefer production, but fall back to sandbox when
  // production has no live deployment at all, or when production is failing
  // while sandbox is passing.
  const prodLive = app.production?.deploy?.status === 'live'
  const sandLive = app.sandbox?.deploy?.status === 'live'
  const useSand = sandLive && (!prodLive || (!prodOk && sandOk))
  return {
    slug: app.slug, name: app.name, hasIcon: !!app.has_icon, hasGithub: !!app.github_url,
    env: useSand ? 'sandbox' : 'production',
    url: useSand ? sandUrl : prodUrl,
    prodUrl, sandUrl,
    prodVersion: app.production?.deploy?.version || '',
    sandVersion: app.sandbox?.deploy?.version || '',
  }
}

interface Props {
  slug: string
  active: boolean
  onClose: () => void
}

export function AppFrame({ slug, active, onClose }: Props) {
  const [stage, setStage] = useState<Stage | null>(null)
  const [status, setStatus] = useState<'loading' | 'ready' | 'notfound'>('loading')
  const [folded, setFolded] = useState(false)
  const [refreshNonce, setRefreshNonce] = useState(0)
  const topbarRef = useRef<HTMLElement>(null)
  const iframeRef = useRef<HTMLIFrameElement>(null)

  const peek = usePeek(iframeRef)
  const [requestCtx, setRequestCtx] = useState<PeekCtx | null>(null)
  useEffect(() => {
    if (peek.ctx) { setRequestCtx(peek.ctx); peek.clear() }
  }, [peek.ctx]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let cancelled = false
    setStatus('loading')
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

  useEffect(() => {
    const el = topbarRef.current
    if (!el || !stage) return

    const onBack = () => onClose()
    const onRefresh = () => {
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
  }, [stage?.slug, onClose])

  // Re-check the app's LIVE versions on open, env switch, and every refresh.
  //
  // v2.31.2: probe BOTH envs, not just the active one. The topbar renders the
  // production and sandbox version chips side by side, but their initial values
  // come from the deploy RECORD (`app.*.deploy.version` — what AppCrane last
  // recorded shipping), which disagrees with what the container is actually
  // serving after a rollback, a restart onto an older image, or a partly-failed
  // deploy. Probing only the active env left the other chip showing the stale
  // record until you clicked its tab — at which point the number visibly
  // changed, which reads as the UI contradicting itself.
  useEffect(() => {
    if (!stage?.slug) return
    const s = stage.slug
    let cancelled = false

    const probe = (env: 'production' | 'sandbox') =>
      adminApi.get<{ version?: string }>(`/api/apps/${encodeURIComponent(s)}/live-version/${env}`)
        .then(r => {
          // No version means that env isn't deployed or isn't answering — keep
          // the recorded value rather than blanking a chip that was readable.
          if (cancelled || !r?.version) return
          setStage(prev => {
            if (!prev || prev.slug !== s) return prev
            return env === 'sandbox'
              ? { ...prev, sandVersion: r.version! }
              : { ...prev, prodVersion: r.version! }
          })
        })
        .catch(() => {})

    probe('production')
    probe('sandbox')
    return () => { cancelled = true }
  }, [stage?.slug, stage?.env, refreshNonce])

  return (
    <div className="lstage-frame" style={{ display: active ? 'flex' : 'none' }}>
      {status === 'ready' && stage ? (
        <>
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
          {active && requestCtx && (
            <RequestModal slug={stage.slug} appName={stage.name} peekCtx={requestCtx} onClose={() => setRequestCtx(null)} />
          )}
        </>
      ) : (
        <div className="lstage-empty">
          <div className="lstage-empty-inner">
            <div className="lstage-empty-glyph">🚀</div>
            <h3>{status === 'notfound' ? 'App not found' : 'Opening…'}</h3>
            {status === 'notfound' && <p>It may not exist, or you may not have access to it.</p>}
          </div>
        </div>
      )}
    </div>
  )
}
