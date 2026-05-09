import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReactElement } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { adminApi } from '../adminApi'
import { Icon } from './icons'

interface NavItem { id: string; label: string; href: string; icon: ReactElement; external?: boolean }
const NAV: NavItem[] = [
  { id: 'dashboard',    label: 'Dashboard',    href: '/dashboard',    icon: <Icon.Dashboard /> },
  { id: 'applications', label: 'Applications', href: '/applications', icon: <Icon.Layers /> },
  { id: 'requests',     label: 'Requests',     href: '/requests',     icon: <Icon.Lightbulb /> },
  { id: 'mcp',          label: 'MCP',          href: '/mcp',          icon: <Icon.PlugZap /> },
  { id: 'docs',         label: 'Docs',         href: '/docs',         icon: <Icon.Book /> },
  { id: 'settings',     label: 'Settings',     href: '/settings',     icon: <Icon.Settings /> },
]

interface SubItem { id: string; label: string; href: string }

interface Props {
  children: React.ReactNode
  subItems?: SubItem[]
  activeSub?: string
}

export function Layout({ children, subItems, activeSub }: Props) {
  const { isAuthed, signOut } = useAuth()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('cc_sb_col') === '1')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [theme, setTheme] = useState(() => localStorage.getItem('cc_theme') || 'dark')
  const [userName, setUserName] = useState('')
  const [version, setVersion] = useState('')
  const [notifOpen, setNotifOpen] = useState(false)
  const [notifItems, setNotifItems] = useState<{ title: string; sub: string; color: string }[]>([])
  const [notifLoaded, setNotifLoaded] = useState(false)
  const [openRequests, setOpenRequests] = useState(0)
  const [mcpStatus, setMcpStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown')
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
    adminApi.get<{ user: { name: string; role: string } }>('/api/auth/me')
      .then(d => setUserName(d.user.name + ' (' + d.user.role + ')'))
      .catch(() => {})
    // Defensive: /api/info can return without `version` if the request races
    // auth-state setup (older servers gated it on a header check). Fall back
    // to /api/version-check.current so the sidebar never renders "vundefined".
    adminApi.get<{ version?: string }>('/api/info')
      .then(d => {
        if (d?.version) {
          setVersion('v' + d.version)
        } else {
          return adminApi.get<{ current?: string }>('/api/version-check')
            .then(v => { if (v?.current) setVersion('v' + v.current) })
            .catch(() => {})
        }
      })
      .catch(() => {})
  }, [isAuthed])

  // v2.5.6: auto-check for AppCrane self-updates so the sidebar pill
  // can light up without the user clicking. Runs on mount and every 30
  // min; the server caches the GitHub call for 5 min so this is cheap.
  useEffect(() => {
    if (!isAuthed) return
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
  }, [isAuthed])

  async function runSelfUpdate() {
    if (!updateInfo?.update_available || updating) return
    if (!confirm(`Update AppCrane from v${updateInfo.current} to v${updateInfo.latest}?\n\nThe server will rebuild the SPA and restart. Active deploys are checked first; the update aborts if any are in flight.`)) return
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
  // Admin endpoint first, fall back to /my for portal users.
  useEffect(() => {
    if (!isAuthed) return
    const TERM = new Set(['done', 'merged', 'closed', 'failed', 'cancelled'])
    const fetchCount = () =>
      adminApi.get<{ requests: { status?: string }[] }>('/api/enhancements')
        .catch(() => adminApi.get<{ requests: { status?: string }[] }>('/api/enhancements/my').catch(() => ({ requests: [] })))
        .then(({ requests }) => {
          setOpenRequests((requests || []).filter(r => !TERM.has((r.status || '').toLowerCase())).length)
        })
    fetchCount()
    const t = setInterval(fetchCount, 15000)
    return () => clearInterval(t)
  }, [isAuthed])

  // MCP connection status pill — pings /api/mcp/connection. 200 → connected;
  // anything else → disconnected. The endpoint requires auth; if the user's
  // session is broken the pill shows disconnected, which is correct since
  // their MCP calls would fail too. Refresh every 30s.
  useEffect(() => {
    if (!isAuthed) return
    const ping = () => {
      adminApi.get<{ server: { name: string; version: string } }>('/api/mcp/connection')
        .then(() => setMcpStatus('connected'))
        .catch(() => setMcpStatus('disconnected'))
    }
    ping()
    const t = setInterval(ping, 30000)
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

  const currentPath = location.pathname
  const activeNav = NAV.find(n => n.href === currentPath)
  const activeNavId = activeNav?.id ?? ''
  const pageTitle = activeNav?.label ?? ''

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
          {!collapsed && version && (
            updateInfo?.update_available ? (
              <span
                className="sidebar-logo-version sidebar-logo-version-update"
                title={`Click to update AppCrane v${updateInfo.current} → v${updateInfo.latest}`}
                onClick={runSelfUpdate}
                style={{ cursor: 'pointer' }}
              >
                {updating
                  ? '⏳ updating…'
                  : <>↑ v{updateInfo.latest}<span className="sidebar-logo-version-current"> (now v{updateInfo.current})</span></>}
              </span>
            ) : (
              <span
                className="sidebar-logo-version"
                title="Click to re-check for updates"
                style={{ cursor: 'pointer' }}
                onClick={async () => {
                  try {
                    const data = await adminApi.get<{ current: string; latest: string | null; update_available: boolean }>('/api/version-check')
                    setUpdateInfo(data)
                    if (!data.update_available) {
                      alert(`AppCrane v${data.current} — already up to date${data.latest ? ` (latest is v${data.latest})` : ''}.`)
                    }
                  } catch { /* silent */ }
                }}
              >
                {version}
              </span>
            )
          )}
        </div>

        {/* Nav */}
        <nav className="sidebar-nav">
          {NAV.map(p => (
            <div key={p.id}>
              {p.external ? (
                <a
                  href={p.href}
                  className={'sidebar-link' + (location.pathname === p.href ? ' active' : '')}
                  title={p.label}
                >
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
                  {p.id === 'requests' && openRequests > 0 && (
                    <span className="sidebar-link-badge">{openRequests}</span>
                  )}
                  {p.id === 'mcp' && mcpStatus !== 'unknown' && (
                    <span
                      className="sidebar-link-pill"
                      title={mcpStatus === 'connected' ? 'MCP server is reachable' : 'MCP server is unreachable'}
                      style={{
                        marginLeft: 'auto',
                        fontSize: '.62rem',
                        fontWeight: 700,
                        letterSpacing: '.5px',
                        textTransform: 'uppercase',
                        padding: '2px 7px',
                        borderRadius: 999,
                        background: mcpStatus === 'connected' ? 'var(--green, #22c55e)' : 'var(--dim, #71717a)',
                        color: 'var(--bg, #0f1117)',
                      }}
                    >
                      {mcpStatus === 'connected' ? 'on' : 'off'}
                    </span>
                  )}
                </NavLink>
              )}
              {activeNavId === p.id && subItems && subItems.length > 0 && !collapsed && (
                <div className="sidebar-sub-nav">
                  {subItems.map(s => (
                    <a
                      key={s.id}
                      href={s.href}
                      className={'sidebar-sub-link' + (activeSub === s.id ? ' active' : '')}
                    >
                      {s.label}
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="sidebar-footer">
          <div className="sidebar-footer-links">
            <a href="/agent-guide">Agent Guide</a>
          </div>
          <div className="sidebar-footer-row">
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
            {/* v2.5.7: AppCrane version + update indicator. Lives in the
                topbar so it's visible on every page even with the sidebar
                collapsed. The pulsing amber state when an update is
                available is the same flow as the sidebar pill. */}
            {version && (
              updateInfo?.update_available ? (
                <span
                  className="topbar-version-pill topbar-version-pill-update"
                  title={`Click to update AppCrane v${updateInfo.current} → v${updateInfo.latest}`}
                  onClick={runSelfUpdate}
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
                      const data = await adminApi.get<{ current: string; latest: string | null; update_available: boolean }>('/api/version-check')
                      setUpdateInfo(data)
                      if (!data.update_available) {
                        alert(`AppCrane v${data.current} — already up to date${data.latest ? ` (latest is v${data.latest})` : ''}.`)
                      }
                    } catch { /* silent */ }
                  }}
                >
                  AppCrane {version}
                </span>
              )
            )}
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
            {userName && <span className="admin-topbar-user">{userName}</span>}
            <button className="admin-topbar-signout" onClick={signOut}>Sign out</button>
          </div>
        </div>
        {children}
      </main>
    </div>
  )
}
