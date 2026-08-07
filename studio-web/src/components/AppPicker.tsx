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
  owner?: { name?: string; email?: string } | null
  production?: { deploy?: { status?: string; version?: string } }
  sandbox?: { deploy?: { status?: string; version?: string } }
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
  const [menuFor, setMenuFor] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    adminApi.get<{ apps: PickerApp[] }>('/api/apps')
      .then(r => { if (!cancelled) setApps(r?.apps ?? []) })
      .catch(() => { if (!cancelled) setApps([]) })
    return () => { cancelled = true }
  }, [])

  // Close the open menu on any outside click or Escape. Registered only while
  // a menu is actually open, so the picker isn't holding global listeners for
  // the entire time it's on screen.
  useEffect(() => {
    if (!menuFor) return
    const close = () => setMenuFor(null)
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close() }
    document.addEventListener('click', close)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [menuFor])

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
          {openable.map(a => {
            const prodV = a.production?.deploy?.version
            const sandV = a.sandbox?.deploy?.version
            // Which env a click actually lands on — mirrors buildStage in
            // AppFrame, so the menu can't promise an env the frame won't open.
            const prodLive = a.production?.deploy?.status === 'live'
            const opensIn = prodLive ? 'production' : 'sandbox'
            const directUrl = opensIn === 'production' ? `/${a.slug}` : `/${a.slug}-sandbox`

            return (
              // The tile is a <button>; the menu control must be a sibling, not
              // a child, or it nests interactive elements. `.launcher-tile-cell`
              // exists for exactly this.
              <div key={a.slug} className="launcher-tile-cell picker-cell">
                <button
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

                <button
                  type="button"
                  className="picker-dots"
                  aria-label={`Details for ${a.name}`}
                  aria-expanded={menuFor === a.slug}
                  onClick={(e) => {
                    // Stop the document-level close handler from firing on the
                    // very click that opens this menu.
                    e.stopPropagation()
                    setMenuFor(menuFor === a.slug ? null : a.slug)
                  }}
                >
                  ⋯
                </button>

                {menuFor === a.slug && (
                  <div className="picker-menu" onClick={(e) => e.stopPropagation()}>
                    <div className="picker-menu-row">
                      <span className="picker-menu-k">Version</span>
                      <span className="picker-menu-v">
                        {prodV || sandV
                          ? [prodV && `prod ${prodV}`, sandV && `sandbox ${sandV}`]
                              .filter(Boolean).join(' · ')
                          : '—'}
                      </span>
                    </div>
                    <div className="picker-menu-row">
                      <span className="picker-menu-k">Builder</span>
                      <span className="picker-menu-v" title={a.owner?.email || ''}>
                        {a.owner?.name || a.owner?.email || '—'}
                      </span>
                    </div>
                    <a
                      className="picker-menu-action"
                      href={directUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={() => setMenuFor(null)}
                    >
                      Open in a new tab ↗
                    </a>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
