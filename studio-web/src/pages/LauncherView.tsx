import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * Launcher view — sidebar navigation (v2.12.0). Left rail lists the apps
 * (grouped by category, searchable, with health dots); selecting one opens
 * it inline in the content stage on the right, hosted by the same
 * <crane-app-topbar> custom element used by the full-screen FrameOverlay
 * (env switch, per-env version, back, refresh, fold). The rail collapses to
 * an icon-only strip.
 *
 * Reuses the same /api/apps data source as the Applications table. The
 * ask/request/bug drawers from the full-screen FrameOverlay are not hosted
 * here — those stay on the Manage path. Owner controls (category /
 * visibility / auth-mode / users) hang off owned-app rows when expanded.
 */

interface AppRow {
  slug:        string
  name:        string
  description?: string
  visibility?: string
  has_icon?:   boolean
  category?:   string
  auth_mode?:  'authenticated' | 'headless'
  app_role?:   'admin' | 'owner' | 'user' | 'viewer' | 'none'
  owner?:      { id: number; name: string; email: string } | null
  github_url?: string
  production?: { health?: { status: string }; deploy?: { version?: string } }
  sandbox?:    { health?: { status: string }; deploy?: { version?: string } }
}

type AppMemberRole = 'none' | 'user' | 'admin' | 'owner'
interface ModalUser { id: number; name: string; email: string | null; role: string; app_role: AppMemberRole }

// The app currently mounted in the content stage.
interface Stage {
  slug: string
  name: string
  hasIcon: boolean
  hasGithub: boolean
  env: 'production' | 'sandbox'
  url: string
  prodUrl: string
  sandUrl: string
  prodVersion: string
  sandVersion: string
}

interface Props {
  /** Legacy full-screen open callback. Unused — the launcher now opens apps
   *  inline in its own content stage. Kept so existing call sites compile. */
  onOpen?: (slug: string, name: string, hasIcon: boolean) => void
  /** Optional header-right control (e.g. the Launcher/Manage toggle). */
  headerRight?: React.ReactNode
}

function initials(name: string): string {
  if (!name) return '?'
  const parts = name.trim().split(/\s+/).slice(0, 2)
  return parts.map(p => p[0]?.toUpperCase() || '').join('') || name[0].toUpperCase()
}

function availability(prodHealth?: string, sandHealth?: string): { dotCls: string; title: string; clickable: boolean } {
  const prodOk = prodHealth === 'healthy'
  const sandOk = sandHealth === 'healthy'
  if (prodOk) return { dotCls: 'launcher-dot launcher-dot-green',  title: 'Production available',                       clickable: true  }
  if (sandOk) return { dotCls: 'launcher-dot launcher-dot-amber',  title: 'Production unavailable — sandbox available', clickable: true  }
  return       { dotCls: 'launcher-dot launcher-dot-red',    title: 'Neither environment is available',           clickable: false }
}

export function LauncherView({ headerRight }: Props) {
  const [apps, setApps] = useState<AppRow[]>([])
  const [search, setSearch] = useState('')
  const [requested, setRequested] = useState<Record<string, boolean>>({})
  const [requestingSlug, setRequestingSlug] = useState<string | null>(null)
  const [usersModalApp, setUsersModalApp] = useState<AppRow | null>(null)
  const [usersModalData, setUsersModalData] = useState<ModalUser[] | null>(null)
  const [usersSaving, setUsersSaving] = useState<Record<number, 'saving' | 'saved' | 'error'>>({})
  const [usersFilter, setUsersFilter] = useState('')

  // Sidebar-nav state.
  const [stage, setStage] = useState<Stage | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [folded, setFolded] = useState(false)
  const topbarRef = useRef<HTMLElement>(null)

  useEffect(() => {
    adminApi.get<{ apps: AppRow[] }>('/api/apps')
      .then(r => setApps(r?.apps || []))
      .catch(() => setApps([]))
  }, [])

  function openApp(app: AppRow) {
    const prodUrl = `/${app.slug}`
    const sandUrl = `/${app.slug}-sandbox`
    const prodOk = app.production?.health?.status === 'healthy'
    const sandOk = app.sandbox?.health?.status === 'healthy'
    const useSand = !prodOk && sandOk
    setFolded(false)
    setStage({
      slug: app.slug,
      name: app.name,
      hasIcon: !!app.has_icon,
      hasGithub: !!app.github_url,
      env: useSand ? 'sandbox' : 'production',
      url: useSand ? sandUrl : prodUrl,
      prodUrl, sandUrl,
      prodVersion: app.production?.deploy?.version || '',
      sandVersion: app.sandbox?.deploy?.version || '',
    })
  }

  // The topbar is a Custom Element firing CustomEvents (not React synthetic),
  // so wire a per-mount listener block. Re-binds when the open app changes.
  useEffect(() => {
    const el = topbarRef.current
    if (!el || !stage) return

    const onBack = () => setStage(null)
    const onRefresh = () => {
      // Cache-bust on refresh: clear the src, then remount with a fresh _ts so
      // the app's HTML is refetched and new content-hashed assets load.
      setStage(s => (s ? { ...s, url: '' } : s))
      setTimeout(() => setStage(s => {
        if (!s) return s
        const base = s.env === 'sandbox' ? s.sandUrl : s.prodUrl
        const sep = base.includes('?') ? '&' : '?'
        return { ...s, url: `${base}${sep}_ts=${Date.now()}` }
      }), 0)
    }
    const onEnv = (e: Event) => {
      const env = (e as CustomEvent<{ env: 'production' | 'sandbox' }>).detail.env
      setStage(s => (s ? { ...s, env, url: env === 'sandbox' ? s.sandUrl : s.prodUrl } : s))
    }
    const onFold = (e: Event) => setFolded((e as CustomEvent<{ folded: boolean }>).detail.folded)

    el.addEventListener('crane-back',        onBack)
    el.addEventListener('crane-refresh',     onRefresh)
    el.addEventListener('crane-env-change',  onEnv)
    el.addEventListener('crane-fold-toggle', onFold)
    return () => {
      el.removeEventListener('crane-back',        onBack)
      el.removeEventListener('crane-refresh',     onRefresh)
      el.removeEventListener('crane-env-change',  onEnv)
      el.removeEventListener('crane-fold-toggle', onFold)
    }
  }, [stage?.slug])

  async function requestAccess(slug: string, name: string) {
    if (requested[slug] || requestingSlug) return
    setRequestingSlug(slug)
    try {
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

  const categories = Array.from(
    new Set(apps.map(a => (a.category || '').trim()).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b))

  async function changeCategory(slug: string, value: string) {
    const snapshot = apps
    setApps(list => list.map(a => (a.slug === slug ? { ...a, category: value || undefined } : a)))
    try {
      await adminApi.put(`/api/apps/${slug}`, { category: value })
    } catch (e) {
      setApps(snapshot)
      alert('Could not change category: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

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

  const groups = new Map<string, AppRow[]>()
  for (const app of filtered) {
    const cat = (app.category || '').trim() || 'Uncategorized'
    if (!groups.has(cat)) groups.set(cat, [])
    groups.get(cat)!.push(app)
  }
  const orderedCats = [...groups.keys()].sort((a, b) => {
    if (a === 'Uncategorized') return 1
    if (b === 'Uncategorized') return -1
    return a.localeCompare(b)
  })

  return (
    <div className={'launcher-shell' + (collapsed ? ' launcher-collapsed' : '')}>
      <aside className="lnav">
        <div className="lnav-top">
          <div className="lnav-top-row">
            <button
              type="button"
              className="lnav-collapse"
              onClick={() => setCollapsed(c => !c)}
              title={collapsed ? 'Expand sidebar' : 'Collapse to icons'}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >{collapsed ? '»' : '«'}</button>
            {!collapsed && (
              <input
                type="text"
                placeholder="Search…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                autoComplete="off"
                className="lnav-search"
              />
            )}
          </div>
          {!collapsed && headerRight && <div className="lnav-top-actions">{headerRight}</div>}
        </div>

        <div className="lnav-list">
          {filtered.length === 0 ? (
            !collapsed && (
              <div className="lnav-empty-list">
                {apps.length === 0 ? 'No apps available yet.' : `No apps match "${search}".`}
              </div>
            )
          ) : (
            orderedCats.map(cat => (
              <div key={cat} className="lnav-group">
                {!collapsed && (
                  <div className="lnav-group-title">
                    <span>{cat}</span>
                    <span className="lnav-group-count">{groups.get(cat)!.length}</span>
                  </div>
                )}
                {groups.get(cat)!.map(app => {
                  const iconNode = app.has_icon
                    ? <img src={`/api/apps/${app.slug}/icon`} alt="" />
                    : <span>{initials(app.name)}</span>

                  if (app.app_role === 'none') {
                    const already = !!requested[app.slug]
                    return (
                      <button
                        key={app.slug}
                        type="button"
                        className={'lnav-item lnav-item-req' + (already ? ' is-requested' : '')}
                        onClick={() => { if (!already) requestAccess(app.slug, app.name) }}
                        title={already ? 'Access requested' : `Request access to ${app.name}`}
                      >
                        <span className="lnav-ico">
                          {iconNode}
                          <span className="launcher-dot launcher-dot-amber" />
                        </span>
                        {!collapsed && <span className="lnav-name">{app.name}</span>}
                        {!collapsed && <span className="lnav-req-badge">{already ? 'Requested' : 'Request'}</span>}
                      </button>
                    )
                  }

                  const avail = availability(app.production?.health?.status, app.sandbox?.health?.status)
                  const isActive = stage?.slug === app.slug
                  return (
                    <div key={app.slug} className="lnav-item-wrap">
                      <button
                        type="button"
                        className={'lnav-item' + (isActive ? ' active' : '') + (!avail.clickable ? ' disabled' : '')}
                        onClick={() => { if (avail.clickable) openApp(app) }}
                        disabled={!avail.clickable}
                        title={!avail.clickable ? avail.title : `Open ${app.name} — ${avail.title.toLowerCase()}`}
                      >
                        <span className="lnav-ico">
                          {iconNode}
                          <span className={avail.dotCls} title={avail.title} />
                        </span>
                        {!collapsed && <span className="lnav-name">{app.name}</span>}
                      </button>
                      {!collapsed && app.app_role === 'owner' && (
                        <div className="lnav-owner-ctrls">
                          <select
                            className="launcher-tile-ctrl"
                            value={app.category ?? ''}
                            onChange={e => changeCategory(app.slug, e.target.value)}
                            title="Category"
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
                              : 'Auth mode — SSO routes through AppCrane; headless bypasses auth entirely.'}
                            aria-label={`Auth mode for ${app.name}`}
                            style={app.auth_mode === 'headless'
                              ? { borderColor: 'var(--red, #ef4444)', color: 'var(--red, #ef4444)' }
                              : undefined}
                          >
                            <option value="authenticated">SSO</option>
                            <option value="headless">headless</option>
                          </select>
                          <button
                            type="button"
                            className="launcher-tile-ctrl launcher-tile-users-btn"
                            onClick={() => setUsersModalApp(app)}
                            title={`Manage users for ${app.name}`}
                          >Users</button>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            ))
          )}
        </div>
      </aside>

      <main className="lstage">
        {stage ? (
          <div className="lstage-frame">
            <crane-app-topbar
              ref={topbarRef}
              app-name={stage.name}
              app-icon-url={stage.hasIcon ? `/api/apps/${stage.slug}/icon` : ''}
              app-slug={stage.slug}
              prod-version={stage.prodVersion}
              sand-version={stage.sandVersion}
              prod-url={stage.prodUrl}
              sand-url={stage.sandUrl}
              env={stage.env}
              current-url={stage.url}
              {...(folded ? { folded: '' } : {})}
            />
            {stage.url && (
              <iframe
                className="lstage-iframe"
                src={stage.url}
                title={stage.name}
              />
            )}
          </div>
        ) : (
          <div className="lstage-empty">
            <div className="lstage-empty-inner">
              <div className="lstage-empty-glyph">🚀</div>
              <h3>Select an app</h3>
              <p>Pick an app from the sidebar to open it here.</p>
            </div>
          </div>
        )}
      </main>

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
              const flt = q
                ? usersModalData.filter(u =>
                    (u.name || '').toLowerCase().includes(q) ||
                    (u.email || '').toLowerCase().includes(q))
                : usersModalData
              if (flt.length === 0) {
                return <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No users match &quot;{usersFilter}&quot;.</p>
              }
              return (
                <table style={{ width: '100%', fontSize: '.85rem' }}>
                  <tbody>
                    {flt.map(u => {
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
