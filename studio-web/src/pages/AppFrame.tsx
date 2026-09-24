import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'
import { usePeek, type PeekCtx } from '../hooks/usePeek'
import { RequestModal } from '../components/runtime-topbar/RequestModal'
import { CoderPanel } from '../components/coder/CoderPanel'
import { coderApi, type CoderAvailability } from '../components/coder/api'
import { Icon } from '../components/icons'
import { EnvActionMenu, type EnvMenuState } from '../components/EnvActionMenu'

/**
 * One app rendered inline, hosted by the <crane-app-topbar> element (env switch,
 * per-env version, refresh, fold) + point-and-click Request flow. Takes the slug
 * as a prop and stays mounted while hidden (display toggled by `active`) so the
 * app tabs keep their iframes — and their state — alive when you switch away.
 * Back closes the tab.
 */

interface AppRow {
  slug:         string
  name:         string
  has_icon?:    boolean
  github_url?:  string
  // Where this app's code lives. /api/apps serves both columns verbatim —
  // withoutSecretColumns strips only *_encrypted — so the coder's eligibility
  // is decided from the app list the frame already loads, with no second call.
  source_type?:  string | null
  repo_backend?: string | null
  /** This caller's role on this app: 'admin' | 'owner' | 'user' | 'viewer' | 'none'. */
  app_role?:     string
  production?: { health?: { status: string }; deploy?: { version?: string; status?: string } }
  sandbox?:    { health?: { status: string }; deploy?: { version?: string; status?: string } }
}

interface Stage {
  slug: string; name: string; hasIcon: boolean; hasGithub: boolean
  /** managed + repo_backend 'local' — the only shape /api/coder will accept. */
  craneHosted: boolean
  /** admin/owner here, i.e. the bar coder.js's requireAppAdmin enforces on release. */
  canRelease: boolean
  /** The app-scoped half of who may promote. The server's rule is
   *  `isAdmin(user) || roleForUserOnApp(...) === 'owner'` (deploy.js:287), so a
   *  platform admin qualifies too — that half is `platformAdmin` below, fetched
   *  once from /api/me, because the app payload carries no global role. */
  isOwner: boolean
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
    // Same predicate as server/services/managedRepo.js usesLocalRepo(): a NULL
    // repo_backend on a managed app means its repo is on GitHub, not here.
    craneHosted: app.source_type === 'managed' && app.repo_backend === 'local',
    canRelease: app.app_role === 'admin' || app.app_role === 'owner',
    isOwner: app.app_role === 'owner',
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
  const [envMenu, setEnvMenu] = useState<EnvMenuState | null>(null)
  // Mirrors deploy.js's isAdmin() half. Without it a platform admin — who the
  // server WILL let promote — is shown no menu at all.
  const [platformAdmin, setPlatformAdmin] = useState(false)
  const [envNotice, setEnvNotice] = useState<string | null>(null)
  // Whether the coder can run here, and if not, every reason why. Fetched per
  // app rather than inferred from the app row: the credential half depends on
  // the SIGNED-IN user's own Claude token, which the app row cannot know.
  const [coderAvail, setCoderAvail] = useState<CoderAvailability | null>(null)

  useEffect(() => {
    if (!stage?.slug) return
    let alive = true
    setCoderAvail(null)
    coderApi.availability(stage.slug)
      .then(a => { if (alive) setCoderAvail(a) })
      // An unanswerable availability check must not look like "available":
      // report it as a gap, so the panel still explains rather than starting a
      // session blind.
      .catch(e => {
        if (alive) setCoderAvail({
          available: false, can_release: false,
          gaps: [{
            code: 'AVAILABILITY_UNKNOWN',
            title: "Couldn't check whether the coder can run here",
            detail: e instanceof Error ? e.message : String(e),
            fix: 'Reload the page. If it keeps happening, this is worth reporting.',
          }],
        })
      })
    return () => { alive = false }
  }, [stage?.slug])

  useEffect(() => {
    let alive = true
    adminApi.get<{ user?: { role?: string } }>('/api/me')
      .then(r => { if (alive) setPlatformAdmin(r?.user?.role === 'admin' || r?.user?.role === 'platform_admin') })
      .catch(() => { /* not fatal: the menu just stays hidden */ })
    return () => { alive = false }
  }, [])
  const [refreshNonce, setRefreshNonce] = useState(0)
  const topbarRef = useRef<HTMLElement>(null)
  const iframeRef = useRef<HTMLIFrameElement>(null)

  // One picker, two consumers. usePeek has a single `ctx`, so whoever started
  // the pick has to be recorded — otherwise a pick meant for the coder prompt
  // also pops the Request modal.
  const peek = usePeek(iframeRef)
  const [peekFor, setPeekFor] = useState<'request' | 'coder'>('request')
  const [requestCtx, setRequestCtx] = useState<PeekCtx | null>(null)
  const [coderCtx, setCoderCtx] = useState<PeekCtx | null>(null)
  const [coderOpen, setCoderOpen] = useState(false)
  useEffect(() => {
    if (!peek.ctx) return
    if (peekFor === 'coder') setCoderCtx(peek.ctx)
    else setRequestCtx(peek.ctx)
    peek.clear()
  }, [peek.ctx]) // eslint-disable-line react-hooks/exhaustive-deps

  const startRequestPick = () => { setPeekFor('request'); peek.start() }
  const startCoderPick   = () => { setPeekFor('coder');   peek.start() }

  // The panel is docked, not overlaid: the iframe shrinks by exactly this many
  // pixels (--frame-dock-width) so the app stays visible and usable while the
  // conversation is about it.
  const CODER_DOCK_WIDTH = 460
  const dockWidth = coderOpen ? CODER_DOCK_WIDTH : 0

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
      // The coder lives on the Sandbox tab. Leaving it closes the panel; a turn
      // in progress keeps running on the server and is there when you return.
      if (env !== 'sandbox') setCoderOpen(false)
    }
    const onFold = (e: Event) => setFolded((e as CustomEvent<{ folded: boolean }>).detail.folded)
    // preventDefault is the element's signal that we rendered a menu; without
    // it the bar leaves the browser's own context menu alone, which is what a
    // non-owner should still get.
    const onEnvMenu = (e: Event) => {
      const ev = e as CustomEvent<{ env: 'production' | 'sandbox'; x: number; y: number }>
      if (!stage?.isOwner && !platformAdmin) return
      ev.preventDefault()
      setEnvMenu({ env: ev.detail.env, x: ev.detail.x, y: ev.detail.y })
    }

    el.addEventListener('crane-back',        onBack)
    el.addEventListener('crane-refresh',     onRefresh)
    el.addEventListener('crane-env-change',  onEnv)
    el.addEventListener('crane-fold-toggle', onFold)
    el.addEventListener('crane-env-menu',    onEnvMenu)
    return () => {
      el.removeEventListener('crane-back',        onBack)
      el.removeEventListener('crane-refresh',     onRefresh)
      el.removeEventListener('crane-env-change',  onEnv)
      el.removeEventListener('crane-fold-toggle', onFold)
      el.removeEventListener('crane-env-menu',    onEnvMenu)
    }
  }, [stage?.slug, stage?.isOwner, platformAdmin, onClose])

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
    <div
      className="lstage-frame"
      style={{
        display: active ? 'flex' : 'none',
        ['--frame-dock-width' as string]: `${dockWidth}px`,
      } as React.CSSProperties}
    >
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
                  className={'crane-topbar-btn' + ((peek.active && peekFor === 'request') || requestCtx ? ' active' : '')}
                  onClick={() => {
                    if (requestCtx) { setRequestCtx(null); return }
                    if (peek.active) { peek.stop(); return }
                    startRequestPick()
                  }}
                  title={peek.active
                    ? 'Click an element in the app, then describe the change. Esc to cancel.'
                    : 'Point at an element to request an enhancement'}
                ><Icon.Lightbulb size={14} /> {peek.active && peekFor === 'request' ? 'Pick…' : 'Request'}</button>
              )}
              {/* Shown on the Sandbox tab only: the coder's work is reviewed and
                  released there, never on production. On every app, not only
                  Crane-hosted ones, so users learn it exists and what it would
                  take; unavailable, it is muted and opens an explanation of
                  every gap instead of a chat. */}
              {stage.env === 'sandbox' && (
              <button
                type="button"
                className={'crane-topbar-btn'
                  + (coderOpen ? ' active' : '')
                  + (coderAvail && !coderAvail.available ? ' crane-topbar-btn--muted' : '')}
                onClick={() => setCoderOpen(o => !o)}
                title={coderAvail && !coderAvail.available
                  ? `Coder isn't available here yet: ${coderAvail.gaps[0]?.title ?? 'see why'} — click for what it takes`
                  : 'Open the coder — change this app by describing what you want'}
              ><Icon.Sparkles size={14} /> Coder</button>
              )}
            </span>
          </crane-app-topbar>
          {stage.url && <iframe key={stage.url} ref={iframeRef} className="lstage-iframe" src={stage.url} title={stage.name} />}
          {active && envMenu && (stage.isOwner || platformAdmin) && (
            <EnvActionMenu
              slug={stage.slug}
              state={envMenu}
              onClose={() => setEnvMenu(null)}
              onStarted={(msg) => {
                setEnvNotice(msg)
                // The deploy is asynchronous; re-probe both envs shortly so the
                // version pills catch up without the user reloading.
                setTimeout(() => setRefreshNonce(n => n + 1), 4000)
                setTimeout(() => setEnvNotice(null), 8000)
              }}
            />
          )}
          {active && envNotice && (
            <div className="env-notice" role="status">{envNotice}</div>
          )}
          {active && requestCtx && (
            <RequestModal slug={stage.slug} appName={stage.name} peekCtx={requestCtx} onClose={() => setRequestCtx(null)} />
          )}
          {(
            <CoderPanel
              slug={stage.slug}
              appName={stage.name}
              open={coderOpen}
              onClose={() => setCoderOpen(false)}
              top={folded ? 22 : 44}
              width={CODER_DOCK_WIDTH}
              canRelease={stage.canRelease}
              availability={coderAvail}
              peekActive={peek.active && peekFor === 'coder'}
              peekCtx={coderCtx}
              onPickStart={startCoderPick}
              onPickStop={peek.stop}
              onPeekConsumed={() => setCoderCtx(null)}
            />
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
