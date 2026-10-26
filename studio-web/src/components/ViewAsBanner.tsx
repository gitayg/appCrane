import { useEffect, useState } from 'react'
import { getViewAs, stopViewAs, reloadView, roleLabel, type ViewAsStatus } from './viewAsApi'

const CSS = `
.viewas-banner{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:8px 16px;
  background:var(--yellow,#eab308);color:#1a1a1a;font-size:.85rem;font-weight:500}
.viewas-banner strong{font-weight:700}
.viewas-banner .viewas-stop{margin-left:auto;background:#1a1a1a;color:#fff;border:0;border-radius:6px;
  padding:4px 12px;font-size:.8rem;font-weight:600;cursor:pointer}
.viewas-banner .viewas-stop:hover{opacity:.9}
.viewas-banner .viewas-stop:focus-visible{outline:2px solid #1a1a1a;outline-offset:2px}
`

/**
 * Persistent "Viewing as <role> on <app> - Stop" bar. Renders nothing unless
 * the server reports an active preview for this sign-in, so it is safe to
 * mount on every page.
 */
export function ViewAsBanner() {
  const [status, setStatus] = useState<ViewAsStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    const load = () => getViewAs().then(s => { if (!cancelled) setStatus(s) }).catch(() => {})
    load()
    const t = setInterval(load, 60_000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  if (!status?.active) return null

  const stop = async () => {
    setBusy(true)
    setError('')
    try {
      await stopViewAs()
      reloadView()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  const platformWide = !status.app_slug
  return (
    <div className="viewas-banner" role="status" aria-live="polite">
      <style>{CSS}</style>
      <span>
        Viewing as <strong>{roleLabel(status.role, platformWide)}</strong>
        {status.app_slug ? <> on <strong>{status.app_name || status.app_slug}</strong></> : <> across AppCrane</>}
        {' '}(read-only preview; changes are blocked)
      </span>
      {error && <span role="alert">{error}</span>}
      <button type="button" className="viewas-stop" onClick={stop} disabled={busy}>
        {busy ? 'Stopping...' : 'Stop viewing as'}
      </button>
    </div>
  )
}
