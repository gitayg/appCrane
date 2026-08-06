import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * v2.32.0: the /launch empty state. Previously a rocket glyph telling you to
 * "pick an app from the sidebar" — which required knowing the sidebar had apps
 * in it, and gave a brand-new user with one app nothing to click. Now it shows
 * the apps you can actually open, as tiles, so the empty state IS the picker.
 *
 * Reuses the `.launcher-*` styles left behind when the standalone Launcher page
 * merged into the nav in v2.13.0 — the CSS survived with no component using it,
 * so this matches the established look rather than inventing a second one.
 *
 * /api/apps is already role-filtered server-side (admins see everything, users
 * see what they're assigned plus public apps), so whatever comes back is
 * exactly what this user may open — no client-side filtering to get wrong.
 */

interface PickerApp {
  slug: string
  name: string
  description?: string | null
  has_icon?: boolean
  production?: { deploy?: { status?: string } }
  sandbox?: { deploy?: { status?: string } }
}

function initials(name: string): string {
  if (!name) return '?'
  const parts = name.trim().split(/\s+/).slice(0, 2)
  return parts.map(p => p[0]?.toUpperCase() || '').join('') || name[0].toUpperCase()
}

// An app is openable once either env has a live deployment. Showing a tile for
// something that can only 503 is worse than not showing it.
function isLive(a: PickerApp): boolean {
  return a.production?.deploy?.status === 'live' || a.sandbox?.deploy?.status === 'live'
}

export function AppPicker({ onOpen }: { onOpen: (slug: string) => void }) {
  const [apps, setApps] = useState<PickerApp[] | null>(null)

  useEffect(() => {
    let cancelled = false
    adminApi.get<{ apps: PickerApp[] }>('/api/apps')
      .then(r => { if (!cancelled) setApps(r?.apps ?? []) })
      .catch(() => { if (!cancelled) setApps([]) })
    return () => { cancelled = true }
  }, [])

  // Render nothing while loading rather than flashing "no apps" at someone who
  // has plenty.
  if (apps === null) return null

  const openable = apps.filter(isLive)

  if (openable.length === 0) {
    return (
      <div className="lstage-empty">
        <div className="lstage-empty-inner">
          <div className="lstage-empty-glyph">🚀</div>
          <h3>No apps available yet</h3>
          <p>
            {apps.length > 0
              ? 'Your apps have no live deployment yet — deploy one and it will appear here.'
              : 'Once an app is shared with you, it will appear here.'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="lstage-empty lstage-picker">
      <div className="lstage-picker-inner">
        <h3>Open an app</h3>
        <p className="lstage-picker-sub">
          {openable.length} app{openable.length === 1 ? '' : 's'} available — it opens here as a tab.
        </p>
        <div className="launcher-grid">
          {openable.map(a => (
            <button
              key={a.slug}
              type="button"
              className="launcher-tile"
              onClick={() => onOpen(a.slug)}
              title={a.description || a.name}
            >
              <span className="launcher-tile-icon">
                {a.has_icon
                  ? <img src={`/api/apps/${a.slug}/icon`} alt="" />
                  : <span>{initials(a.name)}</span>}
              </span>
              <span className="launcher-tile-name">{a.name}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
