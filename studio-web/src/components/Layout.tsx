import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReactElement } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { adminApi } from '../adminApi'
import { Icon } from './icons'
import { WhatsNewModal, type WhatsNewChange } from './WhatsNewModal'

interface NavItem { id: string; label: string; href: string; icon: ReactElement; external?: boolean; platformAdminOnly?: boolean; adminOnly?: boolean; ownerOrAdmin?: boolean }
interface NavApp {
  slug: string; name: string; category?: string; has_icon?: boolean
  description?: string
  owner?: { name: string } | null
  app_role?: 'admin' | 'owner' | 'user' | 'viewer' | 'none'
  visibility?: string
  production?: { health?: { status: string } }
  sandbox?:    { health?: { status: string } }
}
function appDotClass(a: NavApp): string {
  const prodOk = a.production?.health?.status === 'healthy'
  const sandOk = a.sandbox?.health?.status === 'healthy'
  if (prodOk) return 'launcher-dot launcher-dot-green'
  if (sandOk) return 'launcher-dot launcher-dot-amber'
  return 'launcher-dot launcher-dot-red'
}
function appInitials(name: string): string {
  if (!name) return '?'
  const parts = name.trim().split(/\s+/).slice(0, 2)
  return parts.map(p => p[0]?.toUpperCase() || '').join('') || name[0].toUpperCase()
}
// v2.6.5: Settings is `platformAdminOnly`. Tier-2 admins still need
// access to user management / audit log etc. at the API level — they
// just shouldn't see the Settings entry in the sidebar.
// v2.6.9: Skills is `adminOnly` (admin OR platform_admin) and lives at
// the top level — was buried under /settings#skills, which non-platform
// admins couldn't reach after v2.6.5. Promoting because skill bundles
// are an admin-day-to-day workflow (assign skills to apps, refresh
// content) and don't belong behind a platform-level gate. DELETE-skill
// is still platform_admin-only (server-side gate), enforced both in
// the SkillsTab UI and on the API.
const NAV: NavItem[] = [
  { id: 'dashboard',    label: 'Dashboard',    href: '/dashboard',    icon: <Icon.Dashboard /> },
  { id: 'applications', label: 'Manage',       href: '/applications', icon: <Icon.Layers /> },
  { id: 'requests',     label: 'Requests',     href: '/requests',     icon: <Icon.Lightbulb /> },
  { id: 'docs',         label: 'Docs',         href: '/docs',         icon: <Icon.Book /> },
  { id: 'settings',     label: 'Settings',     href: '/settings',     icon: <Icon.Settings /> },
]

interface SubItem { id: string; label: string; href: string; platformAdminOnly?: boolean; ownerOrAdmin?: boolean; adminOnly?: boolean }

interface Props {
  children: React.ReactNode
  subItems?: SubItem[]
  activeSub?: string
}

export function Layout({ children, subItems, activeSub }: Props) {
  const { isAuthed, signOut } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  // v2.14.1: whether the user can create apps — gates the sidebar "+ Add
  // Application" button (mirrors canCreateApps: admins or a granted tier).
  const [canCreate, setCanCreate] = useState(false)
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('cc_sb_col') === '1')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [theme, setTheme] = useState(() => localStorage.getItem('cc_theme') || 'dark')
  const [userName, setUserName] = useState('')
  // v2.5.9: AppCrane version + update info is platform_admin-only. We
  // capture role here from /api/auth/me and gate every version-related
  // render on it; non-platform-admins never see the pill or the badge.
  const [userRole, setUserRole] = useState<string>('')
  const isPlatformAdmin = userRole === 'platform_admin'
  const [version, setVersion] = useState('')
  const [notifOpen, setNotifOpen] = useState(false)
  const [notifItems, setNotifItems] = useState<{ title: string; sub: string; color: string }[]>([])
  const [notifLoaded, setNotifLoaded] = useState(false)
  const [openRequests, setOpenRequests] = useState(0)
  // v2.13.0: AppCrane's own What's New, shown to platform admins post-login
  // when the running version is newer than what they last saw.
  const [platformWN, setPlatformWN] = useState<{ currentVersion: string | null; changes: WhatsNewChange[]; seenUrl?: string; primaryLabel?: string; onPrimary?: () => void } | null>(null)
  // v2.13.0: app list merged into the main nav. Accessible apps grouped by
  // category; the whole section and each category collapse (persisted).
  const [navApps, setNavApps] = useState<NavApp[]>([])
  const [appsOpen, setAppsOpen] = useState(() => localStorage.getItem('cc_nav_apps_open') !== '0')
  const [closedCats, setClosedCats] = useState<Set<string>>(() => {
    try { return new Set(JSON.parse(localStorage.getItem('cc_nav_closed_cats') || '[]') as string[]) } catch { return new Set() }
  })
  const toggleAppsOpen = () => setAppsOpen(o => { const n = !o; try { localStorage.setItem('cc_nav_apps_open', n ? '1' : '0') } catch (_) {} ; return n })
  const toggleCat = (cat: string) => setClosedCats(prev => {
    const next = new Set(prev)
    if (next.has(cat)) next.delete(cat); else next.add(cat)
    try { localStorage.setItem('cc_nav_closed_cats', JSON.stringify([...next])) } catch (_) {}
    return next
  })
  // v2.5.6: AppCrane self-update auto-check. Today the version pill in the
  // sidebar only learns about updates on click — that's why people miss
  // them. We hit /api/version-check on mount + every 30 min so the pill
  // can render "↑ v2.5.7 available" without user action. Click still does
  // the self-update flow (uses updateInfo state, not DOM manipulation).
  const [updateInfo, setUpdateInfo] = useState<{ current: string; latest: string | null; update_available: boolean } | null>(null)
  const [updating, setUpdating] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    if (!isAuthed) return
    adminApi.get<{ user: { name: string; email?: string; role: string; can_create_apps?: boolean } }>('/api/auth/me')
      .then(d => {
        // v2.7.16: show "email (humanized role)" in the topbar, e.g.
        // "itay.glick@opswat.com (platform admin)". Falls back to name if
        // the user has no email; omits the parens when role is empty.
        const role = d.user.role || ''
        const roleLabel = role.replace(/_/g, ' ')
        const who = d.user.email || d.user.name || ''
        setUserName(who ? (roleLabel ? `${who} (${roleLabel})` : who) : '')
        setUserRole(role)
        setCanCreate(role === 'admin' || role === 'platform_admin' || d.user.can_create_apps === true)
      })
      .catch(() => {})
    // Version display is platform-admin only (gated by isPlatformAdmin
    // on render below). The /api/info call still happens here for
    // backward compat — the response only renders when the role is
    // resolved. We deliberately skip /api/version-check fallback for
    // non-platform-admins because the endpoint now enforces the same.
    adminApi.get<{ version?: string }>('/api/info')
      .then(d => { if (d?.version) setVersion('v' + d.version) })
      .catch(() => {})
  }, [isAuthed])

  // v2.5.6: auto-check for AppCrane self-updates so the sidebar pill
  // can light up without the user clicking. Runs on mount and every 30
  // min; the server caches the GitHub call for 5 min so this is cheap.
  // v2.5.9: gated on isPlatformAdmin — regular admins don't see version
  // info or update offers; the endpoint enforces the same role server-side.
  useEffect(() => {
    if (!isAuthed || !isPlatformAdmin) return
    let cancelled = false
    const check = async () => {
      try {
        const data = await adminApi.get<{ current: string; latest: string | null; update_available: boolean }>('/api/version-check')
        if (!cancelled) setUpdateInfo(data)
      } catch (_) { /* keep last good state */ }
    }
    check()
    const t = setInterval(check, 30 * 60 * 1000)
    return () => { cancelled = true; clearInterval(t) }
  }, [isAuthed, isPlatformAdmin])

  async function runSelfUpdate(skipConfirm = false) {
    if (!updateInfo?.update_available || updating) return
    if (!skipConfirm && !confirm(`Update AppCrane from v${updateInfo.current} to v${updateInfo.latest}?\n\nThe server will rebuild the SPA and restart. Active deploys are checked first; the update aborts if any are in flight.`)) return
    setUpdating(true)
    try {
      await adminApi.post('/api/self-update', {})
      // Self-update kicks off async; the server restarts a few seconds
      // later. Reload to pick up the new bundle.
      setTimeout(() => window.location.reload(), 5000)
    } catch (err) {
      alert('Self-update failed: ' + (err instanceof Error ? err.message : String(err)))
      setUpdating(false)
    }
  }

  // Open-requests counter for the Requests nav badge.
  // Admin endpoint first, fall back to /owned (requests filed against apps
  // the caller owns/admins) so the badge matches what the /requests page
  // shows. Plain users with no app role get 0 → sidebar hides the link.
  useEffect(() => {
    if (!isAuthed) return
    const TERM = new Set(['done', 'merged', 'closed', 'failed', 'cancelled'])
    const fetchCount = () =>
      adminApi.get<{ requests: { status?: string }[] }>('/api/enhancements')
        .catch(() => adminApi.get<{ requests: { status?: string }[] }>('/api/enhancements/owned').catch(() => ({ requests: [] })))
        .then(({ requests }) => {
          setOpenRequests((requests || []).filter(r => !TERM.has((r.status || '').toLowerCase())).length)
        })
    fetchCount()
    const t = setInterval(fetchCount, 15000)
    return () => clearInterval(t)
  }, [isAuthed])


  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (notifOpen && notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false)
      }
    }
    document.addEventListener('click', handleClick)
    return () => document.removeEventListener('click', handleClick)
  }, [notifOpen])

  const toggleCollapse = () => {
    const next = !collapsed
    setCollapsed(next)
    localStorage.setItem('cc_sb_col', next ? '1' : '')
  }

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    localStorage.setItem('cc_theme', next)
  }

  const openNotif = useCallback(async () => {
    const next = !notifOpen
    setNotifOpen(next)
    if (next && !notifLoaded) {
      setNotifLoaded(true)
      try {
        const data = await adminApi.get<{ apps: any[] }>('/api/apps')
        const items: typeof notifItems = []
        for (const a of data.apps || []) {
          if (a.prod_down) items.push({ title: a.name + ' (prod)', sub: 'Health check failing', color: 'var(--red)' })
          if (a.sand_down) items.push({ title: a.name + ' (sandbox)', sub: 'Health check failing', color: 'var(--orange)' })
        }
        setNotifItems(items)
      } catch {}
    }
  }, [notifOpen, notifLoaded])

  // v2.13.0: load the accessible app list for the nav "Apps" section.
  useEffect(() => {
    adminApi.get<{ apps: NavApp[] }>('/api/apps')
      .then(r => setNavApps((r?.apps || []).filter(a => a.app_role !== 'none' && a.visibility !== 'hidden')))
      .catch(() => setNavApps([]))
  }, [])

  // v2.13.0: post-login AppCrane What's New for platform admins. Checked once
  // per browser session; the server records "seen" on dismiss so it won't
  // re-fire until the next AppCrane update.
  useEffect(() => {
    if (userRole !== 'platform_admin') return
    if (sessionStorage.getItem('cc_platform_wn') === '1') return
    sessionStorage.setItem('cc_platform_wn', '1')
    adminApi.get<{ current_version: string | null; changes: WhatsNewChange[] }>('/api/whats-new/platform')
      .then(r => { if (r?.changes?.length) setPlatformWN({ currentVersion: r.current_version, changes: r.changes, seenUrl: '/api/whats-new/platform/seen' }) })
      .catch(() => {})
  }, [userRole])

  // v2.13.0: clicking the "update available" pill previews the new version's
  // What's New (current → latest) with an "Upgrade now" action — the same
  // dialog as the post-login one, just forward-looking.
  async function openUpgradeWhatsNew() {
    if (!updateInfo?.update_available || !updateInfo.latest || updating) return
    let changes: WhatsNewChange[] = []
    try {
      const r = await adminApi.get<{ changes: WhatsNewChange[] }>(
        `/api/whats-new/platform?from=${encodeURIComponent(updateInfo.current)}&to=${encodeURIComponent(updateInfo.latest)}`
      )
      changes = r?.changes || []
    } catch { /* still show the dialog so the user can upgrade */ }
    if (changes.length === 0) {
      changes = [{ version: updateInfo.latest, commit_hash: null, commit_message: 'A new version of AppCrane is available.', finished_at: null }]
    }
    setPlatformWN({
      currentVersion: updateInfo.latest,
      changes,
      primaryLabel: 'Upgrade now',
      onPrimary: () => runSelfUpdate(true),
    })
  }

  // Group nav apps by category; Uncategorized last.
  const appGroups: [string, NavApp[]][] = (() => {
    const m = new Map<string, NavApp[]>()
    for (const a of navApps) {
      const cat = (a.category || '').trim() || 'Uncategorized'
      if (!m.has(cat)) m.set(cat, [])
      m.get(cat)!.push(a)
    }
    return [...m.entries()].sort(([a], [b]) => a === 'Uncategorized' ? 1 : b === 'Uncategorized' ? -1 : a.localeCompare(b))
  })()

  const adminLike = userRole === 'admin' || userRole === 'platform_admin'
  const isOwner = navApps.some(a => a.app_role === 'owner')
  const currentPath = location.pathname
  const activeNav = NAV.find(n => n.href === currentPath)
  const activeNavId = activeNav?.id ?? ''
  const pageTitle = activeNav?.label ?? ''

  // v2.14.3: split the nav — primary items (+ the Apps list) at the top, the
  // admin/config items pinned to the bottom of the rail.
  const BOTTOM_NAV = new Set(['applications', 'docs', 'settings'])
  const gatedNav = NAV.filter(p => {
    if (p.platformAdminOnly && userRole !== 'platform_admin') return false
    if (p.adminOnly && !adminLike) return false
    if (p.ownerOrAdmin && !adminLike && !isOwner) return false
    if (p.id === 'settings' && !adminLike && !isOwner) return false
    if (p.id === 'requests' && openRequests === 0 && !adminLike) return false
    return true
  })
  const renderNavItem = (p: NavItem) => (
    <div key={p.id}>
      {p.external ? (
        <a href={p.href} className={'sidebar-link' + (location.pathname === p.href ? ' active' : '')} title={p.label}>
          <span className="sidebar-link-icon">{p.icon}</span>
          <span className="sidebar-link-text">{p.label}</span>
        </a>
      ) : (
        <NavLink
          to={p.href}
          className={({ isActive }) => 'sidebar-link' + (isActive ? ' active' : '')}
          title={p.id === 'requests' && openRequests > 0 ? `${p.label} — ${openRequests} open` : p.label}
        >
          <span className="sidebar-link-icon">{p.icon}</span>
          <span className="sidebar-link-text">{p.label}</span>
          {p.id === 'requests' && openRequests > 0 && <span className="sidebar-link-badge">{openRequests}</span>}
        </NavLink>
      )}
      {activeNavId === p.id && subItems && subItems.length > 0 && !collapsed && (
        <div className="sidebar-sub-nav">
          {subItems.filter(s => {
            if (s.platformAdminOnly && userRole !== 'platform_admin') return false
            if (s.ownerOrAdmin && !adminLike && !isOwner) return false
            if (s.adminOnly && !adminLike) return false
            return true
          }).map(s => (
            <a key={s.id} href={s.href} className={'sidebar-sub-link' + (activeSub === s.id ? ' active' : '')}>{s.label}</a>
          ))}
        </div>
      )}
    </div>
  )

  return (
    <div className="admin-layout">
      {/* Mobile topbar */}
      <div className="mobile-topbar">
        <a href="/dashboard" style={{ fontWeight: 700, fontSize: '1.05rem', textDecoration: 'none', color: 'var(--text)' }}>
          App<span style={{ color: 'var(--accent)' }}>Crane</span>
        </a>
        <button className="hamburger" onClick={() => setMobileOpen(o => !o)} aria-label="Menu">&#9776;</button>
      </div>

      {/* Overlay */}
      {mobileOpen && <div className="sidebar-overlay open" onClick={() => setMobileOpen(false)} />}

      {/* Sidebar */}
      <aside className={`admin-sidebar${collapsed ? ' collapsed' : ''}${mobileOpen ? ' open' : ''}`} id="mainSidebar">
        {/* Logo + version */}
        <div className="sidebar-logo-section">
          <a href="/dashboard" className="sidebar-logo">
            App<span>Crane</span>
          </a>
          {/* v2.14.1: the version + update pill lives in the sidebar (moved
              from the topbar). Platform-admin only; hidden in the icon rail. */}
          {isPlatformAdmin && version && !collapsed && (
            <div className="sidebar-version">
              {updateInfo?.update_available ? (
                <span
                  className="topbar-version-pill topbar-version-pill-update"
                  title={`See what's new and update AppCrane v${updateInfo.current} → v${updateInfo.latest}`}
                  onClick={openUpgradeWhatsNew}
                >
                  {updating
                    ? '⏳ updating…'
                    : <>↑ AppCrane v{updateInfo.latest}<span className="topbar-version-pill-current"> (now v{updateInfo.current})</span></>}
                </span>
              ) : (
                <span
                  className="topbar-version-pill"
                  title="Click to re-check for AppCrane updates"
                  onClick={async () => {
                    try {
                      const data = await adminApi.get<{ current: string; latest: string | null; update_available: boolean }>('/api/version-check?force=1')
                      setUpdateInfo(data)
                      if (!data.update_available) {
                        alert(`AppCrane v${data.current} — already up to date${data.latest ? ` (latest is v${data.latest})` : ''}.`)
                      }
                    } catch { /* silent */ }
                  }}
                >
                  AppCrane {version}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Nav. Role-gating:
            - platformAdminOnly entries (Settings) hidden unless the
              caller is platform_admin (v2.6.5 tightened from v2.6.4
              which let admin see it too — tier-2 admins shouldn't
              normally need it)
            - Requests hidden when the user has zero open requests AND
              isn't admin/platform_admin (no use for the page either way) */}
        {canCreate && (
          <button
            type="button"
            className="sidebar-add-app btn btn-accent"
            onClick={() => navigate('/applications', { state: { addApp: true } })}
            title="Add Application"
          >{collapsed ? '+' : '+ Add Application'}</button>
        )}
        <nav className="sidebar-nav">
          {gatedNav.filter(p => !BOTTOM_NAV.has(p.id)).map(renderNavItem)}

          {/* v2.13.0: merged launcher — accessible apps live in the main nav,
              grouped by category. Section + each category collapse. Apps open
              inline at /launch/:slug. Hidden in the icon-rail (collapsed) mode. */}
          {!collapsed && navApps.length > 0 && (
            <div className="sidebar-apps">
              <button className="sidebar-apps-toggle" onClick={toggleAppsOpen} title="Apps">
                <span className="sidebar-apps-label">Apps</span>
                <span className="sidebar-apps-chev">{appsOpen ? '▾' : '▸'}</span>
              </button>
              {appsOpen && appGroups.map(([cat, list]) => {
                const closed = closedCats.has(cat)
                return (
                  <div key={cat} className="sidebar-apps-group">
                    <button className="sidebar-apps-cat" onClick={() => toggleCat(cat)}>
                      <span className="sidebar-apps-chev">{closed ? '▸' : '▾'}</span>
                      <span className="sidebar-apps-cat-name">{cat}</span>
                      <span className="sidebar-apps-count">{list.length}</span>
                    </button>
                    {!closed && list.map(a => (
                      <NavLink
                        key={a.slug}
                        to={`/launch/${a.slug}`}
                        className={({ isActive }) => 'sidebar-app-link' + (isActive ? ' active' : '')}
                        title={[a.name, a.description, a.owner?.name ? `Owner: ${a.owner.name}` : null].filter(Boolean).join('\n')}
                      >
                        <span className="sidebar-app-ico">
                          {a.has_icon
                            ? <img src={`/api/apps/${a.slug}/icon`} alt="" />
                            : <span>{appInitials(a.name)}</span>}
                          <span className={appDotClass(a)} />
                        </span>
                        <span className="sidebar-app-name">{a.name}</span>
                      </NavLink>
                    ))}
                  </div>
                )
              })}
            </div>
          )}
        </nav>

        {/* v2.14.3: admin/config items (Manage, Docs, Settings) pinned to the
            bottom of the rail, above the footer. */}
        <nav className="sidebar-nav sidebar-nav-bottom">
          {gatedNav.filter(p => BOTTOM_NAV.has(p.id)).map(renderNavItem)}
        </nav>

        {/* Footer — user + sign out (moved here from the topbar in v2.14.3). */}
        <div className="sidebar-footer">
          {!collapsed && userName && <div className="sidebar-user" title={userName}>{userName}</div>}
          <div className="sidebar-footer-row">
            <button className="sidebar-signout" onClick={signOut} title="Sign out">
              {collapsed ? '⎋' : 'Sign out'}
            </button>
            <button className="theme-btn" onClick={toggleTheme} title="Toggle theme">
              {theme === 'dark' ? '☀' : '🌙'}
            </button>
            <button
              className="sidebar-collapse-btn"
              onClick={toggleCollapse}
              style={{ marginLeft: 'auto' }}
              title={collapsed ? 'Expand' : 'Collapse'}
            >
              {collapsed ? '▸' : '◄'}{!collapsed && <span> Collapse</span>}
            </button>
          </div>
        </div>
      </aside>

      {/* Page content */}
      <main className={`admin-content${collapsed ? ' collapsed' : ''}`}>
        <div className="admin-topbar">
          <span className="admin-topbar-title">{pageTitle}</span>
          <div className="admin-topbar-right">
            {/* v2.14.1: AppCrane version + update pill moved to the sidebar. */}
            <div className="notif-wrap" ref={notifRef}>
              <button className="notif-bell-btn" onClick={openNotif} title="Notifications">🔔</button>
              {notifItems.length > 0 && (
                <span className="notif-badge show">{notifItems.length}</span>
              )}
              <div className={`notif-dropdown${notifOpen ? ' open' : ''}`}>
                <div className="notif-dd-hdr">Notifications</div>
                {notifItems.length === 0
                  ? <div className="notif-empty">All systems operational ✓</div>
                  : notifItems.map((n, i) => (
                    <div key={i} className="notif-row">
                      <div className="notif-row-dot" style={{ background: n.color }} />
                      <div>
                        <div className="notif-row-title">{n.title}</div>
                        <div className="notif-row-sub">{n.sub}</div>
                      </div>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        </div>
        {children}
      </main>
      {platformWN && (
        <WhatsNewModal
          appName="AppCrane"
          currentVersion={platformWN.currentVersion}
          changes={platformWN.changes}
          seenUrl={platformWN.seenUrl}
          primaryLabel={platformWN.primaryLabel}
          onPrimary={platformWN.onPrimary}
          onClose={() => setPlatformWN(null)}
        />
      )}
    </div>
  )
}
