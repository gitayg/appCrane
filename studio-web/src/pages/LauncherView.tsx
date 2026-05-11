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
  // v2.6.7: per-user role from the caller's perspective. 'none' means
  // the user can see the app exists but doesn't have an open-it
  // permission yet — the Launcher renders a Request-access tile.
  app_role?:   'admin' | 'owner' | 'user' | 'viewer' | 'none'
  production?: { health?: { status: string } }
  sandbox?:    { health?: { status: string } }
}

interface Props {
  onOpen: (slug: string, name: string, hasIcon: boolean) => void
  /**
   * Optional slot for a header-right control — used by Applications.tsx
   * (admin-only) to render the Launcher/Manage view toggle inline with
   * the page header. Without this slot the launcher renders no toggle;
   * end users have no Manage view to switch to anyway.
   */
  headerRight?: React.ReactNode
}

function initials(name: string): string {
  if (!name) return '?'
  const parts = name.trim().split(/\s+/).slice(0, 2)
  return parts.map(p => p[0]?.toUpperCase() || '').join('') || name[0].toUpperCase()
}

// v2.6.2: three-state availability semantics, matching what the user
// actually cares about when deciding whether to click:
//   green  — production is up; clicking opens prod
//   amber  — production is NOT up but sandbox is; clicking opens sandbox
//   red    — neither env is up; clicking is disabled
// No more yellow-for-uncertain or gray-for-never-deployed — those all
// collapse into red because the practical answer ("can I open this?")
// is the same. Tooltip explains which env the click will hit.
function availability(prodHealth?: string, sandHealth?: string): { dotCls: string; title: string; clickable: boolean } {
  const prodOk = prodHealth === 'healthy'
  const sandOk = sandHealth === 'healthy'
  if (prodOk) return { dotCls: 'launcher-dot launcher-dot-green',  title: 'Production available',                       clickable: true  }
  if (sandOk) return { dotCls: 'launcher-dot launcher-dot-amber',  title: 'Production unavailable — sandbox available', clickable: true  }
  return       { dotCls: 'launcher-dot launcher-dot-red',    title: 'Neither environment is available',           clickable: false }
}

export function LauncherView({ onOpen, headerRight }: Props) {
  const [apps, setApps] = useState<AppRow[]>([])
  const [search, setSearch] = useState('')
  // v2.6.7: track which apps the user has already filed an access
  // request for in this session so we don't fire duplicates on repeated
  // clicks. Keyed by slug; value is true once submitted. Survives only
  // for the current page — refreshing would clear, but that's fine
  // because the access request lands in enhancement_requests on the
  // server and admins see it regardless.
  const [requested, setRequested] = useState<Record<string, boolean>>({})
  const [requestingSlug, setRequestingSlug] = useState<string | null>(null)

  useEffect(() => {
    adminApi.get<{ apps: AppRow[] }>('/api/apps')
      .then(r => setApps(r?.apps || []))
      .catch(() => setApps([]))
  }, [])

  async function requestAccess(slug: string, name: string) {
    if (requested[slug] || requestingSlug) return
    setRequestingSlug(slug)
    try {
      // Use the same shape docs/login.html used pre-v2.5.14 — server
      // recognizes the "Access request for app …" prefix in
      // appcrane_list_access_requests, so the request appears in the
      // platform_admin's queue for approve/deny via MCP or dashboard.
      await adminApi.post('/api/enhancements', {
        message: `Access request for app "${name}"`,
        app_slug: slug,
      })
      setRequested(prev => ({ ...prev, [slug]: true }))
    } catch (e) {
      alert('Failed to send access request: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setRequestingSlug(null)
    }
  }

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
        {headerRight}
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
        // v2.6.1: group apps by category. Apps with no category fall into
        // an "Uncategorized" bucket rendered last. Within a group the
        // sort is whatever order the server returned; we don't re-sort
        // alphabetically because the server already does.
        (() => {
          const groups = new Map<string, AppRow[]>()
          for (const app of filtered) {
            const cat = (app.category || '').trim() || 'Uncategorized'
            if (!groups.has(cat)) groups.set(cat, [])
            groups.get(cat)!.push(app)
          }
          // Stable category ordering: named groups alphabetical, Uncategorized last.
          const orderedCats = [...groups.keys()]
            .sort((a, b) => {
              if (a === 'Uncategorized') return 1
              if (b === 'Uncategorized') return -1
              return a.localeCompare(b)
            })
          return orderedCats.map(cat => (
            <section key={cat} className="launcher-category">
              <h3 className="launcher-category-title">
                {cat}
                <span className="launcher-category-count">{groups.get(cat)!.length}</span>
              </h3>
              <div className="launcher-grid">
                {groups.get(cat)!.map(app => {
                  // v2.6.7: three render modes:
                  //   - app_role === 'none' → discoverable. Show
                  //     Request-access tile. Don't fire onOpen.
                  //   - app_role !== 'none' AND env available → normal
                  //     tile, opens via onOpen
                  //   - app_role !== 'none' AND no env available → tile
                  //     disabled (the existing red-dot case)
                  const canOpen = app.app_role && app.app_role !== 'none'
                  if (!canOpen) {
                    const alreadyRequested = !!requested[app.slug]
                    const busy = requestingSlug === app.slug
                    return (
                      <button
                        key={app.slug}
                        type="button"
                        className={'launcher-tile launcher-tile-request' + (alreadyRequested ? ' launcher-tile-requested' : '')}
                        onClick={() => { if (!alreadyRequested) requestAccess(app.slug, app.name) }}
                        disabled={alreadyRequested || busy}
                        title={alreadyRequested
                          ? `Access requested — an admin will review`
                          : `Request access to ${app.name}`}
                      >
                        <div className="launcher-tile-icon">
                          {app.has_icon ? (
                            <img src={`/api/apps/${app.slug}/icon`} alt="" />
                          ) : (
                            <span>{initials(app.name)}</span>
                          )}
                          <span className="launcher-dot launcher-dot-amber" title="No access — click to request" />
                        </div>
                        <div className="launcher-tile-name">{app.name}</div>
                        {app.description && (
                          <div className="launcher-tile-desc">{app.description}</div>
                        )}
                        <div className="launcher-tile-cta">
                          {busy ? 'Sending…' : alreadyRequested ? '✓ Access requested' : '🔒 Request access'}
                        </div>
                        {/* v2.6.8 hover popover with the full description. CSS-only:
                            hidden by default, shown on .launcher-tile:hover. The
                            short version above stays line-clamped — this surfaces
                            the rest on hover with no click required. Only renders
                            when there's actually a description to show. */}
                        {app.description && (
                          <div className="launcher-tile-tip" role="tooltip">{app.description}</div>
                        )}
                      </button>
                    )
                  }
                  const avail = availability(app.production?.health?.status, app.sandbox?.health?.status)
                  return (
                    <button
                      key={app.slug}
                      type="button"
                      className={'launcher-tile' + (!avail.clickable ? ' launcher-tile-disabled' : '')}
                      onClick={() => { if (avail.clickable) onOpen(app.slug, app.name, !!app.has_icon) }}
                      disabled={!avail.clickable}
                      title={!avail.clickable ? avail.title : `Open ${app.name} — ${avail.title.toLowerCase()}`}
                    >
                      <div className="launcher-tile-icon">
                        {app.has_icon ? (
                          <img src={`/api/apps/${app.slug}/icon`} alt="" />
                        ) : (
                          <span>{initials(app.name)}</span>
                        )}
                        <span className={avail.dotCls} title={avail.title} />
                      </div>
                      <div className="launcher-tile-name">{app.name}</div>
                      {app.description && (
                        <div className="launcher-tile-desc">{app.description}</div>
                      )}
                      {/* v2.6.8: full-description hover popover. See note in
                          the request-access tile above. */}
                      {app.description && (
                        <div className="launcher-tile-tip" role="tooltip">{app.description}</div>
                      )}
                    </button>
                  )
                })}
              </div>
            </section>
          ))
        })()
      )}
    </div>
  )
}
