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
  auth_mode?:  'authenticated' | 'headless'
  // v2.6.7: per-user role from the caller's perspective. 'none' means
  // the user can see the app exists but doesn't have an open-it
  // permission yet — the Launcher renders a Request-access tile.
  app_role?:   'admin' | 'owner' | 'user' | 'viewer' | 'none'
  owner?:      { id: number; name: string; email: string } | null
  production?: { health?: { status: string } }
  sandbox?:    { health?: { status: string } }
}

type AppMemberRole = 'none' | 'user' | 'admin' | 'owner'
interface ModalUser { id: number; name: string; email: string | null; role: string; app_role: AppMemberRole }

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
  // v2.7.9: owner self-service — manage members of an app you own from a
  // focused modal. Mirrors the admin per-app Users modal but reachable by
  // owners (server gates the endpoints to admin-or-owner).
  const [usersModalApp, setUsersModalApp] = useState<AppRow | null>(null)
  const [usersModalData, setUsersModalData] = useState<ModalUser[] | null>(null)
  const [usersSaving, setUsersSaving] = useState<Record<number, 'saving' | 'saved' | 'error'>>({})
  // v2.7.24: filter the per-app users modal by name/email. Resets on close.
  const [usersFilter, setUsersFilter] = useState('')

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

  // v2.7.6: owners can re-categorize apps they own from the tile. Existing
  // categories only — creating a NEW category is admin-only (enforced server
  // side too). The option list is the distinct set across visible apps.
  const categories = Array.from(
    new Set(apps.map(a => (a.category || '').trim()).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b))

  async function changeCategory(slug: string, value: string) {
    const snapshot = apps
    setApps(list => list.map(a => (a.slug === slug ? { ...a, category: value || undefined } : a)))
    try {
      await adminApi.put(`/api/apps/${slug}`, { category: value })
    } catch (e) {
      setApps(snapshot) // revert on failure (e.g. server rejects a new category)
      alert('Could not change category: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  // v2.7.9: owners can change visibility from the tile.
  async function changeVisibility(slug: string, value: string) {
    const snapshot = apps
    setApps(list => list.map(a => (a.slug === slug ? { ...a, visibility: value } : a)))
    try {
      await adminApi.put(`/api/apps/${slug}`, { visibility: value })
    } catch (e) {
      setApps(snapshot)
      alert('Could not change visibility: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  // v2.7.22: auth_mode is an exposure-changing toggle. Going `headless`
  // removes AppCrane's auth on the entire app (anyone on the internet can
  // hit it). Confirm before doing it.
  async function changeAuthMode(slug: string, name: string, value: string) {
    if (value === 'headless') {
      const ok = window.confirm(
        `Make "${name}" HEADLESS?\n\n` +
        'This removes ALL AppCrane authentication on the app. Anyone with the URL — ' +
        'logged in or not — can reach it directly.\n\n' +
        'Use this ONLY for single-purpose unauthenticated services (telemetry ingest, ' +
        'public webhooks, status pages). Your app\'s own server is responsible for any ' +
        'payload-level auth (HMAC, install-id, etc.).\n\n' +
        'Continue?'
      )
      if (!ok) return
    }
    const snapshot = apps
    setApps(list => list.map(a => (a.slug === slug ? { ...a, auth_mode: value as 'authenticated' | 'headless' } : a)))
    try {
      await adminApi.put(`/api/apps/${slug}`, { auth_mode: value })
    } catch (e) {
      setApps(snapshot)
      alert('Could not change auth_mode: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  // Load the merged user+role list when the Users modal opens.
  useEffect(() => {
    if (!usersModalApp) { setUsersModalData(null); return }
    let cancelled = false
    Promise.all([
      adminApi.get<{ users: { id: number; name: string; email: string | null; role: string }[] }>('/api/users'),
      adminApi.get<{ users: { id: number; app_role: AppMemberRole }[] }>(`/api/apps/${usersModalApp.slug}/identity/users`),
    ])
      .then(([allUsers, appUsers]) => {
        if (cancelled) return
        const roleByUser = new Map(appUsers.users.map(u => [u.id, u.app_role]))
        setUsersModalData((allUsers.users || []).map(u => ({
          id: u.id, name: u.name, email: u.email, role: u.role,
          app_role: roleByUser.get(u.id) ?? 'none',
        })))
      })
      .catch(() => { if (!cancelled) setUsersModalData([]) })
    return () => { cancelled = true }
  }, [usersModalApp])

  async function changeUserAppRole(userId: number, newRole: AppMemberRole) {
    if (!usersModalApp) return
    const prev = usersModalData?.find(u => u.id === userId)?.app_role ?? 'none'
    setUsersModalData(d => d ? d.map(u => u.id === userId ? { ...u, app_role: newRole } : u) : d)
    setUsersSaving(s => ({ ...s, [userId]: 'saving' }))
    try {
      await adminApi.put(`/api/apps/${usersModalApp.slug}/roles`, { user_id: userId, app_role: newRole })
      setUsersSaving(s => ({ ...s, [userId]: 'saved' }))
      setTimeout(() => setUsersSaving(s => { const c = { ...s }; delete c[userId]; return c }), 1500)
    } catch (e) {
      setUsersModalData(d => d ? d.map(u => u.id === userId ? { ...u, app_role: prev } : u) : d)
      setUsersSaving(s => ({ ...s, [userId]: 'error' }))
      alert('Could not save role: ' + (e instanceof Error ? e.message : String(e)))
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
                        {(app.description || app.owner) && (
                          <div className="launcher-tile-tip" role="tooltip">
                            {app.description}
                            {app.owner && (
                              <div className="launcher-tile-tip-owner">Owner: <b>{app.owner.name}</b></div>
                            )}
                          </div>
                        )}
                      </button>
                    )
                  }
                  const avail = availability(app.production?.health?.status, app.sandbox?.health?.status)
                  // v2.7.6/2.7.9: owners get inline controls under the tile —
                  // category, visibility, and a Users button. The tile itself
                  // is a <button>, so these can't nest inside it; wrap in a cell.
                  const isOwner = app.app_role === 'owner'
                  const tile = (
                    <button
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
                          the request-access tile above. v2.8.8: + owner line. */}
                      {(app.description || app.owner) && (
                        <div className="launcher-tile-tip" role="tooltip">
                          {app.description}
                          {app.owner && (
                            <div className="launcher-tile-tip-owner">Owner: <b>{app.owner.name}</b></div>
                          )}
                        </div>
                      )}
                    </button>
                  )
                  if (!isOwner) return <div key={app.slug} className="launcher-tile-cell">{tile}</div>
                  return (
                    <div key={app.slug} className="launcher-tile-cell">
                      {tile}
                      <div className="launcher-tile-owner-row">
                        <select
                          className="launcher-tile-ctrl"
                          value={app.category ?? ''}
                          onChange={e => changeCategory(app.slug, e.target.value)}
                          title="Category — pick an existing one (only admins can create new categories)"
                          aria-label={`Category for ${app.name}`}
                        >
                          <option value="">— no category —</option>
                          {categories.map(c => <option key={c} value={c}>{c}</option>)}
                        </select>
                        <select
                          className="launcher-tile-ctrl"
                          value={app.visibility ?? 'private'}
                          onChange={e => changeVisibility(app.slug, e.target.value)}
                          title="Visibility"
                          aria-label={`Visibility for ${app.name}`}
                        >
                          <option value="public">public</option>
                          <option value="private">private</option>
                          <option value="hidden">hidden</option>
                        </select>
                        <select
                          className="launcher-tile-ctrl"
                          value={app.auth_mode ?? 'authenticated'}
                          onChange={e => changeAuthMode(app.slug, app.name, e.target.value)}
                          title={app.auth_mode === 'headless'
                            ? '⚠ HEADLESS — no AppCrane auth on this app; anyone can reach it.'
                            : 'Auth mode — authenticated routes go through AppCrane SSO; headless bypasses auth entirely (telemetry / public webhooks / status pages).'}
                          aria-label={`Auth mode for ${app.name}`}
                          style={app.auth_mode === 'headless'
                            ? { borderColor: 'var(--red, #ef4444)', color: 'var(--red, #ef4444)' }
                            : undefined}
                        >
                          <option value="authenticated">SSO</option>
                          <option value="headless">headless</option>
                        </select>
                      </div>
                      <button
                        type="button"
                        className="launcher-tile-ctrl launcher-tile-users-btn"
                        onClick={() => setUsersModalApp(app)}
                        title={`Manage users for ${app.name}`}
                      >
                        Users
                      </button>
                    </div>
                  )
                })}
              </div>
            </section>
          ))
        })()
      )}

      {usersModalApp && (
        <div
          onClick={() => { setUsersModalApp(null); setUsersFilter('') }}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
            backdropFilter: 'blur(2px)',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12,
              padding: 24, maxWidth: 620, width: '94%', maxHeight: '80vh', overflowY: 'auto',
              boxShadow: '0 24px 64px rgba(0,0,0,.5)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <h3 style={{ margin: 0, fontSize: '1.05rem' }}>Users · {usersModalApp.name}</h3>
              <button className="btn btn-xs" onClick={() => { setUsersModalApp(null); setUsersFilter('') }}>Close</button>
            </div>
            <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: 4, marginBottom: 10 }}>
              Set each user's role on this app. A last-owner guard keeps the app from being left ownerless.
            </p>
            {/* v2.7.24: search by name or email. Empty = show everyone. */}
            <input
              type="text"
              placeholder="Search by name or email…"
              value={usersFilter}
              onChange={e => setUsersFilter(e.target.value)}
              autoFocus
              style={{
                width: '100%', boxSizing: 'border-box', marginBottom: 12,
                padding: '6px 10px', fontSize: '.85rem',
                background: 'var(--surface2)', border: '1px solid var(--border)',
                borderRadius: 6, color: 'var(--text)',
              }}
            />
            {usersModalData === null ? (
              <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>Loading…</p>
            ) : usersModalData.length === 0 ? (
              <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No users found.</p>
            ) : (() => {
              const q = usersFilter.trim().toLowerCase()
              const filtered = q
                ? usersModalData.filter(u =>
                    (u.name || '').toLowerCase().includes(q) ||
                    (u.email || '').toLowerCase().includes(q))
                : usersModalData
              if (filtered.length === 0) {
                return <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No users match &quot;{usersFilter}&quot;.</p>
              }
              return (
              <table style={{ width: '100%', fontSize: '.85rem' }}>
                <tbody>
                  {filtered.map(u => {
                    const status = usersSaving[u.id]
                    return (
                      <tr key={u.id} style={{ borderTop: '1px solid var(--border)' }}>
                        <td style={{ padding: '8px 6px' }}>
                          <div style={{ fontWeight: 600 }}>{u.name || u.email || `user#${u.id}`}</div>
                          {u.email && <div style={{ color: 'var(--dim)', fontSize: '.76rem' }}>{u.email}</div>}
                        </td>
                        <td style={{ padding: '8px 6px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <select
                            value={u.app_role}
                            onChange={e => changeUserAppRole(u.id, e.target.value as AppMemberRole)}
                            style={{ fontSize: '.8rem' }}
                          >
                            <option value="none">none</option>
                            <option value="user">user</option>
                            <option value="admin">admin</option>
                            <option value="owner">owner</option>
                          </select>
                          {status === 'saving' && <span style={{ marginLeft: 6, color: 'var(--dim)', fontSize: '.74rem' }}>…</span>}
                          {status === 'saved' && <span style={{ marginLeft: 6, color: 'var(--green)', fontSize: '.74rem' }}>✓</span>}
                          {status === 'error' && <span style={{ marginLeft: 6, color: 'var(--red)', fontSize: '.74rem' }}>✗</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              )
            })()}
          </div>
        </div>
      )}
    </div>
  )
}
