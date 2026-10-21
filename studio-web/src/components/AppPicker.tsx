import { useEffect, useState, type ReactElement } from 'react'
import { adminApi, ApiError } from '../adminApi'
import { useMe } from '../hooks/useMe'
import { ClassificationBadge } from './intake/ClassificationBadge'
import type { Level } from './intake/types'

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
 * /api/apps also returns apps this user has no role on (app_role 'none') so
 * they can ask for access. Those are never openable: they get their own
 * "Request access" section and a button instead of a tile that opens.
 */

interface PickerApp {
  slug: string
  name: string
  description?: string | null
  category?: string | null
  has_icon?: boolean
  owner?: { id?: number; name?: string; email?: string } | null
  owners?: { id?: number; name?: string }[]
  app_role?: 'owner' | 'admin' | 'user' | 'viewer' | 'none'
  /** Only on app_role 'none': this user already has a pending access request. */
  access_requested?: boolean
  production?: { deploy?: { status?: string; version?: string } }
  sandbox?: { deploy?: { status?: string; version?: string } }
  /** Server-computed: false when the app hides Sandbox from this caller. */
  sandbox_visible?: boolean
}

// Absent on an older server's payload, which hid nothing.
const sandboxOffered = (a: PickerApp) => a.sandbox_visible !== false

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
  return a.production?.deploy?.status === 'live' || (sandboxOffered(a) && a.sandbox?.deploy?.status === 'live')
}

const canOpen = (a: PickerApp) => a.app_role !== 'none'

export function AppPicker({ onOpen }: { onOpen: (slug: string) => void }) {
  const me = useMe()
  const myId = me?.user?.id
  const [apps, setApps] = useState<PickerApp[] | null>(null)
  const [levels, setLevels] = useState<Record<string, Level>>({})
  const [requested, setRequested] = useState<Record<string, 'sending' | 'sent' | 'failed'>>({})
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
    adminApi.get<{ levels: Record<string, Level> }>('/api/data-classification/apps')
      .then(r => { if (!cancelled) setLevels(r?.levels ?? {}) })
      .catch(() => {})
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

  // A platform admin's app_role is 'admin' everywhere, so ownership is also
  // read from the owners list.
  const isOwned = (a: PickerApp) =>
    a.app_role === 'owner' || (myId !== undefined && (a.owners ?? []).some(o => o.id === myId))
  const openable = apps.filter(a => canOpen(a) && isLive(a))
  const requestable = apps.filter(a => !canOpen(a))

  if (openable.length === 0 && requestable.length === 0) {
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

  const visibleOpenable = openable.filter(a => matches(a, query))
  const owned = visibleOpenable.filter(isOwned)
  const others = visibleOpenable.filter(a => !isOwned(a))
  const visibleRequestable = requestable.filter(a => matches(a, query))
  const anyVisible = visibleOpenable.length + visibleRequestable.length > 0
  const byName = (x: PickerApp, y: PickerApp) => x.name.localeCompare(y.name)

  // Sorted by name → one flat grid. Sorted by category → a grid per category,
  // categories alphabetical with Uncategorized pinned last so an unlabelled
  // app never leads the page.
  const groupsOf = (list: PickerApp[]): { key: string; apps: PickerApp[] }[] =>
    sortBy === 'category'
      ? Object.entries(
          list.reduce<Record<string, PickerApp[]>>((acc, a) => {
            const k = (a.category || '').trim() || UNCATEGORIZED
            ;(acc[k] ||= []).push(a)
            return acc
          }, {})
        )
          .sort(([a], [b]) =>
            a === UNCATEGORIZED ? 1 : b === UNCATEGORIZED ? -1 : a.localeCompare(b))
          .map(([key, l]) => ({ key, apps: l.sort(byName) }))
      : [{ key: '', apps: [...list].sort(byName) }]

  const requestAccess = async (a: PickerApp) => {
    setRequested(r => ({ ...r, [a.slug]: 'sending' }))
    try {
      await adminApi.post('/api/enhancements', {
        message: `Access request for app \u201c${a.name}\u201d`,
        app_slug: a.slug,
      })
      setRequested(r => ({ ...r, [a.slug]: 'sent' }))
    } catch (e) {
      const already = e instanceof ApiError && e.status === 409
      setRequested(r => ({ ...r, [a.slug]: already ? 'sent' : 'failed' }))
    }
  }

  // Never opens the app: no onOpen, no link. The only action is the request.
  const renderRequestTile = (a: PickerApp) => {
    const state = requested[a.slug] ?? (a.access_requested ? 'sent' : undefined)
    const done = state === 'sent'
    const builder = builderOf(a)
    return (
      <div key={a.slug} className="launcher-tile-cell picker-cell">
        <div
          className={'launcher-tile picker-locked' + (done ? ' launcher-tile-requested' : ' launcher-tile-request')}
          aria-disabled="true"
          title={builder ? `${a.name} — ask ${builder} for access` : a.name}
        >
          <span className="launcher-tile-icon">
            {a.has_icon
              ? <img src={`/api/apps/${a.slug}/icon`} alt="" />
              : <span>{initials(a.name)}</span>}
          </span>
          <span className="launcher-tile-name">
            <span aria-label="No access" role="img">🔒</span> {a.name}
          </span>
          {builder && <span className="picker-locked-owner">{builder}</span>}
        </div>
        <button
          type="button"
          className="launcher-tile-ctrl picker-request-btn"
          disabled={done || state === 'sending'}
          onClick={() => requestAccess(a)}
        >
          {done ? 'Requested' : state === 'sending' ? 'Sending…' : state === 'failed' ? 'Failed — try again' : 'Request access'}
        </button>
      </div>
    )
  }

  const renderSection = (
    key: string,
    title: string,
    list: PickerApp[],
    render: (a: PickerApp) => ReactElement,
  ) => list.length === 0 ? null : (
    <section key={key} className="picker-section" data-section={key}>
      <h3 className="picker-section-head">
        {title} <span className="picker-group-count">{list.length}</span>
      </h3>
      {groupsOf(list).map(g => (
        <div key={g.key || 'all'} className="picker-group">
          {g.key && (
            <h4 className="picker-group-head">
              {g.key} <span className="picker-group-count">{g.apps.length}</span>
            </h4>
          )}
          <div className="launcher-grid">{g.apps.map(render)}</div>
        </div>
      ))}
    </section>
  )

  const renderTile = (a: PickerApp) => {
            const prodV = a.production?.deploy?.version
            const sandV = sandboxOffered(a) ? a.sandbox?.deploy?.version : undefined
            // Which env a click actually lands on — mirrors buildStage in
            // AppFrame, so the menu can't promise an env the frame won't open.
            const prodLive = a.production?.deploy?.status === 'live'
            const opensIn = prodLive || !sandboxOffered(a) ? 'production' : 'sandbox'
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
                  <span className="launcher-tile-name">{a.name}{' '}<ClassificationBadge level={levels[a.slug]} /></span>
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
            ? `${visibleOpenable.length} of ${openable.length} app${openable.length === 1 ? '' : 's'} match “${query}”`
            : openable.length === 0
              ? 'No apps you can open yet — request access to one below.'
              : `${openable.length} app${openable.length === 1 ? '' : 's'} available — it opens here as a tab.`}
        </p>

        {!anyVisible ? (
          <p className="picker-no-match">
            Nothing matches “{query}”. Search covers app name, builder and slug.
          </p>
        ) : (
          <>
            {renderSection('owned', 'Apps you own', owned, renderTile)}
            {renderSection('yours', 'Your apps', others, renderTile)}
            {renderSection('request', 'Request access', visibleRequestable, renderRequestTile)}
          </>
        )}
      </div>
    </div>
  )
}
