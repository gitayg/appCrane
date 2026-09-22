import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * Right-click menu on the topbar's environment pills.
 *
 * Both actions are hard to take back — a promote replaces what production is
 * serving, a redeploy restarts a running container — so each one confirms, and
 * the confirmation names the environment rather than asking "are you sure?".
 *
 * Only an owner ever sees this. That is not a UI preference: promote is
 * owner-gated in deploy.js:286 ("Only the app owner can promote to
 * production"), so offering it to anyone else would be offering a 403. Redeploy
 * is more permissive server-side — production needs the deploy.production
 * permission, sandbox needs app access — so a non-owner who holds that
 * permission still redeploys from the Applications page; this menu is
 * deliberately the narrower surface.
 */
export interface EnvMenuState { env: 'production' | 'sandbox'; x: number; y: number }

type Busy = null | 'promote' | 'redeploy'

export function EnvActionMenu(
  { slug, state, onClose, onStarted }:
  { slug: string; state: EnvMenuState; onClose: () => void; onStarted: (msg: string) => void },
) {
  const ref = useRef<HTMLDivElement>(null)
  const [busy, setBusy] = useState<Busy>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<Busy>(null)

  useEffect(() => {
    const away = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) onClose() }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    // capture: the topbar lives in a shadow root and retargets events, so a
    // bubbling listener here can miss a click that landed inside it.
    document.addEventListener('mousedown', away, true)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', away, true)
      document.removeEventListener('keydown', esc)
    }
  }, [onClose])

  const run = async (what: Exclude<Busy, null>) => {
    setBusy(what); setError(null)
    try {
      if (what === 'promote') {
        const r = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/promote`, {})
        onStarted(r?.message || 'Promoting sandbox to production')
      } else {
        await adminApi.post(`/api/apps/${slug}/deploy/${state.env}`, {})
        onStarted(`Redeploying ${state.env}`)
      }
      onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(null); setConfirming(null)
    }
  }

  // Keep the menu on screen when the pill is near the right edge or the fold.
  const style: React.CSSProperties = {
    position: 'fixed',
    left: Math.min(state.x, window.innerWidth - 240),
    top: Math.min(state.y, window.innerHeight - 140),
    zIndex: 1000,
  }

  return (
    <div className="env-menu" style={style} ref={ref} role="menu" aria-label={`${state.env} actions`}>
      <div className="env-menu__head">{state.env}</div>

      {state.env === 'sandbox' && (
        confirming === 'promote' ? (
          <button className="env-menu__item env-menu__item--confirm" role="menuitem" disabled={!!busy}
            onClick={() => run('promote')}>
            {busy === 'promote' ? 'Promoting…' : 'Promote this sandbox build to production?'}
          </button>
        ) : (
          <button className="env-menu__item" role="menuitem" disabled={!!busy}
            onClick={() => { setConfirming('promote'); setError(null) }}>
            Promote to Production
          </button>
        )
      )}

      {confirming === 'redeploy' ? (
        <button className="env-menu__item env-menu__item--confirm" role="menuitem" disabled={!!busy}
          onClick={() => run('redeploy')}>
          {busy === 'redeploy' ? 'Redeploying…' : `Redeploy ${state.env} now?`}
        </button>
      ) : (
        <button className="env-menu__item" role="menuitem" disabled={!!busy}
          onClick={() => { setConfirming('redeploy'); setError(null) }}>
          Redeploy {state.env}
        </button>
      )}

      {error && <div className="env-menu__error" role="alert">{error}</div>}
    </div>
  )
}
