import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * Launcher view (v2.5.0) — tile grid alternate to the Applications
 * table. Used as the default for end users (non-admin, non-owner) and
 * available as a toggle for admins. Reuses the same data source as the
 * Applications table; no manage/delete/env affordances are exposed.
 *
 * Click a tile → opens the embedded FrameOverlay via the parent's
 * onOpen callback (same as the Dashboard's icon click). Health dot is
 * rendered green / red / yellow / gray, mirroring Applications.tsx
 * healthState() but inline so this view stays free of import churn.
 */

interface AppRow {
  slug:        string
  name:        string
  description?: string
  visibility?: string
  has_icon?:   boolean
  category?:   string
  production?: { health?: { status: string } }
  sandbox?:    { health?: { status: string } }
}

interface Props {
  onOpen: (slug: string, name: string, hasIcon: boolean) => void
}

function initials(name: string): string {
  if (!name) return '?'
  const parts = name.trim().split(/\s+/).slice(0, 2)
  return parts.map(p => p[0]?.toUpperCase() || '').join('') || name[0].toUpperCase()
}

function dotClass(prodHealth?: string, sandHealth?: string): { cls: string; title: string } {
  // Prefer production health; fall back to sandbox if prod missing.
  const h = prodHealth || sandHealth
  if (h === 'healthy')   return { cls: 'launcher-dot launcher-dot-green',  title: 'Healthy' }
  if (h === 'down')      return { cls: 'launcher-dot launcher-dot-red',    title: 'Down' }
  if (h === 'unhealthy') return { cls: 'launcher-dot launcher-dot-red',    title: 'Unhealthy' }
  if (h)                 return { cls: 'launcher-dot launcher-dot-yellow', title: 'Health unknown' }
  return                 { cls: 'launcher-dot launcher-dot-gray',   title: 'Not deployed' }
}

export function LauncherView({ onOpen }: Props) {
  const [apps, setApps] = useState<AppRow[]>([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    adminApi.get<{ apps: AppRow[] }>('/api/apps')
      .then(r => setApps(r?.apps || []))
      .catch(() => setApps([]))
  }, [])

  const filtered = apps.filter(a => {
    if (a.visibility === 'hidden') return false
    if (!search) return true
    const q = search.toLowerCase()
    return (a.name || '').toLowerCase().includes(q) ||
           (a.description || '').toLowerCase().includes(q) ||
           (a.category || '').toLowerCase().includes(q)
  })

  return (
    <div className="container launcher-container">
      <div className="launcher-header">
        <h2 style={{ margin: 0 }}>My Apps</h2>
        <input
          type="text"
          placeholder="Search…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          autoComplete="off"
          className="launcher-search"
        />
      </div>

      {filtered.length === 0 ? (
        <div className="launcher-empty">
          {apps.length === 0
            ? 'No apps available yet.'
            : `No apps match "${search}".`}
        </div>
      ) : (
        <div className="launcher-grid">
          {filtered.map(app => {
            const dot = dotClass(app.production?.health?.status, app.sandbox?.health?.status)
            const isDown = (app.production?.health?.status === 'down' || app.production?.health?.status === 'unhealthy') &&
                           (app.sandbox?.health?.status === 'down' || app.sandbox?.health?.status === 'unhealthy' || !app.sandbox?.health?.status)
            return (
              <button
                key={app.slug}
                type="button"
                className={'launcher-tile' + (isDown ? ' launcher-tile-disabled' : '')}
                onClick={() => { if (!isDown) onOpen(app.slug, app.name, !!app.has_icon) }}
                disabled={isDown}
                title={isDown ? 'App is down — open disabled' : `Open ${app.name}`}
              >
                <div className="launcher-tile-icon">
                  {app.has_icon ? (
                    <img src={`/api/apps/${app.slug}/icon`} alt="" />
                  ) : (
                    <span>{initials(app.name)}</span>
                  )}
                  <span className={dot.cls} title={dot.title} />
                </div>
                <div className="launcher-tile-name">{app.name}</div>
                {app.category && (
                  <div className="launcher-tile-cat">{app.category}</div>
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
