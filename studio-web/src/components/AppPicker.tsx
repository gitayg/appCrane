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
  category?: string | null
  has_icon?: boolean
  owner?: { name?: string; email?: string } | null
  production?: { deploy?: { status?: string; version?: string } }
  sandbox?: { deploy?: { status?: string; version?: string } }
}

const UNCATEGORIZED = 'Uncategorized'

function builderOf(a: PickerApp): string {
  return a.owner?.name || a.owner?.email || ''
}

// Name, builder and slug are all searched: people look for an app by what it's
// called, by who made it, or by the URL they half-remember.
function matches(a: PickerApp, q: string): boolean {
  if (!q) return true
  const hay = [a.name, builderOf(a), a.owner?.email, a.slug, a.category]
    .filter(Boolean).join(' ').toLowerCase()
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(term => hay.includes(term))
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
  const [query, setQuery] = useState('')
  // Persisted: sort order is a standing preference, not a per-visit decision,
  // and this screen is now the post-login landing page.
  const [sortBy, setSortBy] = useState<'name' | 'category'>(
    () => (localStorage.getItem('cc_picker_sort') === 'category' ? 'category' : 'name')
  )
  const setSort = (s: 'name' | 'category') => {
    setSortBy(s)
    try { localStorage.setItem('cc_picker_sort', s) } catch (_) { /* private mode */ }
  }

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

  const visible = openable.filter(a => matches(a, query))
  const byName = (x: PickerApp, y: PickerApp) => x.name.localeCompare(y.name)

  // Sorted by name → one flat grid. Sorted by category → a grid per category,
  // categories alphabetical with Uncategorized pinned last so an unlabelled
  // app never leads the page.
  const groups: { key: string; apps: PickerApp[] }[] =
    sortBy === 'category'
      ? Object.entries(
          visible.reduce<Record<string, PickerApp[]>>((acc, a) => {
            const k = (a.category || '').trim() || UNCATEGORIZED
            ;(acc[k] ||= []).push(a)
            return acc
          }, {})
        )
          .sort(([a], [b]) =>
            a === UNCATEGORIZED ? 1 : b === UNCATEGORIZED ? -1 : a.localeCompare(b))
          .map(([key, list]) => ({ key, apps: list.sort(byName) }))
      : [{ key: '', apps: [...visible].sort(byName) }]

  const renderTile = (a: PickerApp) => {
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
  }

  return (
    <div className="lstage-empty lstage-picker">
      <div className="lstage-picker-inner">
        <h3>Open an app</h3>

        <div className="picker-controls">
          <input
            className="picker-search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by name or builder…"
            aria-label="Search apps by name or builder"
            autoComplete="off"
          />
          <div className="applications-mode-toggle" role="group" aria-label="Sort apps">
            <button
              type="button"
              className={sortBy === 'name' ? 'active' : ''}
              aria-pressed={sortBy === 'name'}
              onClick={() => setSort('name')}
            >
              Name
            </button>
            <button
              type="button"
              className={sortBy === 'category' ? 'active' : ''}
              aria-pressed={sortBy === 'category'}
              onClick={() => setSort('category')}
            >
              Category
            </button>
          </div>
        </div>

        <p className="lstage-picker-sub">
          {query
            ? `${visible.length} of ${openable.length} app${openable.length === 1 ? '' : 's'} match “${query}”`
            : `${openable.length} app${openable.length === 1 ? '' : 's'} available — it opens here as a tab.`}
        </p>

        {visible.length === 0 ? (
          <p className="picker-no-match">
            Nothing matches “{query}”. Search covers app name, builder and slug.
          </p>
        ) : (
          groups.map(g => (
            <div key={g.key || 'all'} className="picker-group">
              {g.key && (
                <h4 className="picker-group-head">
                  {g.key} <span className="picker-group-count">{g.apps.length}</span>
                </h4>
              )}
              <div className="launcher-grid">{g.apps.map(renderTile)}</div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
