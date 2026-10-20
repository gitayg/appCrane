import { useEffect, useState } from 'react'
import { getViewAsOptions, startViewAs, reloadView, roleLabel, type ViewAsOptions } from './viewAsApi'

interface Props {
  /** Limit the choices to one app (its Manage page). Omit for the user menu. */
  appSlug?: string
  /** Extra class for the trigger button, to match the surrounding menu. */
  className?: string
}

const PLATFORM = '__platform__'

/**
 * "View as..." picker. The server decides what is on offer (GET
 * /api/auth/view-as-options): a platform admin gets the platform as a user and
 * every app at any role; an app owner gets their own apps at lower roles;
 * everyone else gets nothing, and this renders nothing.
 */
export function ViewAsControl({ appSlug, className }: Props) {
  const [opts, setOpts] = useState<ViewAsOptions | null>(null)
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState('')
  const [role, setRole] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getViewAsOptions().then(setOpts).catch(() => setOpts(null))
  }, [])

  if (!opts) return null
  const apps = appSlug ? opts.apps.filter(a => a.slug === appSlug) : opts.apps
  const platformRoles = appSlug ? [] : opts.platform_roles
  if (!apps.length && !platformRoles.length) return null

  const choice = target || (platformRoles.length ? PLATFORM : apps[0]?.slug || '')
  const roles = choice === PLATFORM ? platformRoles : (apps.find(a => a.slug === choice)?.roles || [])
  const pickedRole = roles.includes(role) ? role : roles[0] || ''

  const go = async () => {
    setBusy(true)
    setError('')
    try {
      await startViewAs(pickedRole, choice === PLATFORM ? undefined : choice)
      reloadView()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button type="button" className={className || 'btn btn-sm'} onClick={() => setOpen(o => !o)} aria-expanded={open}>
        View as...
      </button>
      {open && (
        <div role="dialog" aria-label="View as another role" style={{
          position: 'absolute', zIndex: 50, right: 0, marginTop: 6, width: 280, padding: 12,
          background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow-lg)',
        }}>
          <div style={{ fontSize: '.8rem', color: 'var(--muted)', marginBottom: 8 }}>
            Preview AppCrane as a lower role. Read-only: every change is blocked until you stop. Ends after an hour.
          </div>
          {!appSlug && (
            <label style={{ display: 'block', fontSize: '.8rem', marginBottom: 8 }}>
              Where
              <select value={choice} onChange={e => { setTarget(e.target.value); setRole('') }} style={{ width: '100%', marginTop: 4 }}>
                {platformRoles.length > 0 && <option value={PLATFORM}>All of AppCrane</option>}
                {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
              </select>
            </label>
          )}
          <label style={{ display: 'block', fontSize: '.8rem', marginBottom: 10 }}>
            Role
            <select value={pickedRole} onChange={e => setRole(e.target.value)} style={{ width: '100%', marginTop: 4 }}>
              {roles.map(r => <option key={r} value={r}>{roleLabel(r, choice === PLATFORM)}</option>)}
            </select>
          </label>
          {error && <div role="alert" style={{ color: 'var(--red)', fontSize: '.78rem', marginBottom: 8 }}>{error}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-sm" onClick={() => setOpen(false)}>Cancel</button>
            <button type="button" className="btn btn-sm btn-primary" onClick={go} disabled={busy || !pickedRole}>
              {busy ? 'Starting...' : 'Start preview'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
