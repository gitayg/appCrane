import { useState, useEffect, useRef, useCallback } from 'react'
import { Navigate, Link } from 'react-router-dom'
import { adminApi } from '../adminApi'
import { useMe, isAdmin } from '../hooks/useMe'

interface App {
  slug: string
  name: string
  description?: string
  visibility?: string
  github_url?: string
  users?: { id: number; name: string }[]
  has_icon?: boolean
  urls?: { production?: string; sandbox?: string }
  resource_limits?: { max_ram_mb?: number; max_cpu_percent?: number }
  production?: { deploy?: { status?: string; version?: string }; health?: { status: string; config?: { endpoint?: string } } }
  sandbox?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
}

interface User {
  id: number
  name: string
  email: string
}

interface Enhancement {
  id: number
  status: string
  message: string
  app_slug?: string
}

interface ActivityApp {
  name?: string
  slug: string
  counts: number[]
}

interface ServerHealth {
  system: {
    cpu: { percent: number; count: number }
    memory: { percent: number }
    memory_formatted: { used: string; total: string }
    disk: { percent: number }
    disk_formatted: { used: string; total: string }
  }
}

interface UsageSummary {
  total_jobs?: number
  succeeded?: number
  failed?: number
  total_tokens?: number
  total_cost?: number
}



const TREND_PALETTE = ['#4f9cf9', '#a855f7', '#f97316', '#22c55e', '#eab308', '#e91e63', '#00bcd4', '#ff5722']

function barColor(pct: number): string {
  if (pct > 80) return 'var(--red)'
  if (pct > 60) return 'var(--yellow)'
  return 'var(--green)'
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function TrendChart({ days, apps }: { days: string[]; apps: ActivityApp[] }) {
  if (!apps.length || !days.length) {
    return (
      <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--dim)', fontSize: '.85rem' }}>
        No visitor data yet
      </div>
    )
  }

  const PL = 28, PR = 12, PT = 16, PB = 28
  const W = 900, H = 160
  const chartW = W - PL - PR
  const chartH = H - PT - PB

  const allCounts = apps.flatMap(a => a.counts)
  const maxVal = Math.max(...allCounts, 1)

  const xOf = (i: number) => PL + (i / (days.length - 1 || 1)) * chartW
  const yOf = (v: number) => PT + chartH - (v / maxVal) * chartH

  const gridLines = 5
  const gridValues = Array.from({ length: gridLines }, (_, i) => Math.round((maxVal / (gridLines - 1)) * i))

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', display: 'block' }}>
      {gridValues.map((val, i) => {
        const y = yOf(val)
        return (
          <g key={i}>
            <line x1={PL} y1={y} x2={W - PR} y2={y} stroke="var(--border)" strokeWidth="1" />
            {val > 0 && (
              <text x={PL - 4} y={y + 4} textAnchor="end" fontSize="9" fill="var(--dim)">{val}</text>
            )}
          </g>
        )
      })}

      {days.map((d, i) => (
        <text key={i} x={xOf(i)} y={H - 4} textAnchor="middle" fontSize="9" fill="var(--dim)">
          {formatDate(d)}
        </text>
      ))}

      {apps.map((app, ai) => {
        const color = TREND_PALETTE[ai % TREND_PALETTE.length]
        const pts = app.counts.map((v, i) => `${xOf(i)},${yOf(v)}`).join(' ')
        return (
          <g key={app.slug}>
            <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
            {app.counts.map((v, i) => (
              <g key={i}>
                <circle cx={xOf(i)} cy={yOf(v)} r="3" fill={color} />
                {v > 0 && (
                  <text x={xOf(i)} y={yOf(v) - 6} textAnchor="middle" fontSize="8" fill={color}>{v}</text>
                )}
              </g>
            ))}
          </g>
        )
      })}
    </svg>
  )
}

const ONBOARD_KEY = 'cc_onboard_dismissed'

export function Dashboard() {
  // v2.6.6: Dashboard is admin-flavored — it fetches /api/users (admin
  // only) inside the main Promise.all without a .catch, so a regular
  // user landing here saw "Error: Admin access required" with no
  // recovery path. Non-admins redirect to /applications (Launcher view)
  // which is where they should be anyway. The role check happens after
  // all hooks fire to stay within React's rules-of-hooks.
  const me = useMe()
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [apps, setApps] = useState<App[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [enhancements, setEnhancements] = useState<Enhancement[]>([])
  const [activity, setActivity] = useState<{ days: string[]; apps: ActivityApp[] }>({ days: [], apps: [] })
  // v2.6.10: top-10 leaderboards. Apps by distinct daily active users
  // and users by distinct apps opened, both over the last 7 days.
  // Source: app_visits table, populated on every Caddy forward_auth.
  const [leaders, setLeaders] = useState<{
    apps: { slug: string; name: string; users: number; owner_name?: string | null; owner_email?: string | null }[]
    users: { id: number; name: string; email: string | null; apps: number }[]
  }>({ apps: [], users: [] })
  const [usageSummary, setUsageSummary] = useState<UsageSummary | null>(null)
  // Users currently active in the system (active accounts with app or platform
  // activity in the last 15 min). Refreshed with fetchMain every 30s.
  const [activeUsers, setActiveUsers] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [onboardDismissed, setOnboardDismissed] = useState(!!localStorage.getItem(ONBOARD_KEY))
  // v2.10.0: let users tick items off by hand (some can't be auto-detected,
  // and the checklist was previously display-only — unclickable). Persisted.
  const [onboardChecked, setOnboardChecked] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('cc_onboard_checked') || '[]') } catch { return [] }
  })
  function toggleOnboard(key: string) {
    setOnboardChecked(prev => {
      const next = prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
      try { localStorage.setItem('cc_onboard_checked', JSON.stringify(next)) } catch { /* ignore */ }
      return next
    })
  }


  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchMain = useCallback(async () => {
    try {
      // v2.6.6: every admin-only call gets a `.catch(() => safe-empty)`
      // so a single 403 (e.g. /api/users for a non-admin who somehow
      // got past the redirect) doesn't reject the whole Promise.all
      // and render a bare "Admin access required" error page. /api/apps
      // works for everyone (server filters by role); /api/server/health
      // works for everyone (status only, no sensitive detail). The
      // admin-only ones now degrade gracefully.
      const [h, appsRes, usersRes, enhRes, actRes, ldrRes, activeRes] = await Promise.all([
        adminApi.get<ServerHealth>('/api/server/health').catch(() => null),
        adminApi.get<{ apps: App[] }>('/api/apps'),
        adminApi.get<{ users: User[] }>('/api/users').catch(() => ({ users: [] })),
        adminApi.get<{ requests: Enhancement[] }>('/api/enhancements').catch(() => ({ requests: [] })),
        adminApi.get<{ days: string[]; apps: ActivityApp[] }>('/api/dashboard/app-activity').catch(() => ({ days: [], apps: [] })),
        adminApi.get<typeof leaders>('/api/dashboard/leaderboards?days=7&top=10').catch(() => ({ apps: [], users: [] })),
        adminApi.get<{ minutes: number; count: number }>('/api/dashboard/active-users').catch(() => null),
      ])
      if (h) setHealth(h)
      setApps(appsRes.apps ?? [])
      setUsers(usersRes.users ?? [])
      setEnhancements(enhRes.requests ?? [])
      setLeaders({ apps: ldrRes.apps ?? [], users: ldrRes.users ?? [] })
      setActivity(actRes)
      if (activeRes) setActiveUsers(activeRes.count)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchSecondary = useCallback(() => {
    adminApi.get<UsageSummary>('/api/appstudio/usage/summary')
      .then(d => {
        if (d && (d.total_jobs !== undefined || d.succeeded !== undefined)) {
          setUsageSummary(d)
        }
      })
      .catch(() => {})
  }, [])

  const fetchLiveVersions = useCallback((appList: App[]) => {
    for (const app of appList) {
      for (const env of ['production', 'sandbox'] as const) {
        adminApi.get<{ version?: string }>(`/api/apps/${app.slug}/live-version/${env}`)
          .then(d => {
            if (!d.version) return
            const el = document.getElementById(`ver_${app.slug}_${env}`)
            if (el) {
              el.textContent = d.version
              el.style.color = 'var(--green)'
            }
          })
          .catch(() => {})
      }
    }
  }, [])

  useEffect(() => {
    fetchMain().then(() => {
      fetchSecondary()
    })

    intervalRef.current = setInterval(() => {
      fetchMain()
      fetchSecondary()
    }, 30000)

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [fetchMain, fetchSecondary])

  useEffect(() => {
    if (apps.length > 0) fetchLiveVersions(apps)
  }, [apps, fetchLiveVersions])

  function dismissOnboard() {
    localStorage.setItem(ONBOARD_KEY, '1')
    setOnboardDismissed(true)
  }

  if (loading) return <div id="loading">Loading dashboard…</div>
  if (error) return <div className="container" style={{ color: 'var(--red)', paddingTop: 40 }}>{error}</div>

  const s = health?.system
  const allApps = apps
  const prodLive = allApps.filter(a => {
    const st = a.production?.deploy?.status?.toLowerCase()
    return st === 'live' || st === 'deployed' || a.production?.health?.status?.toLowerCase() === 'healthy'
  }).length
  const sandLive = allApps.filter(a => {
    const st = a.sandbox?.deploy?.status?.toLowerCase()
    return st === 'live' || st === 'deployed' || a.sandbox?.health?.status?.toLowerCase() === 'healthy'
  }).length
  const totalUsers = users.length
  const totalEnhReqs = enhancements.length

  // `auto` is what we can detect; the user can also tick any item by hand
  // (onboardChecked). Either marks it done.
  const onboardItems = [
    { key: 'running', label: 'AppCrane is running', auto: true },
    { key: 'create-app', label: 'Create your first app', auto: apps.length > 0, link: '/applications' },
    { key: 'invite', label: 'Invite a team member', auto: users.length > 1, link: '/users-page' },
    { key: 'health', label: 'Configure a health check', auto: apps.some(a => (a.production?.health as any)?.config?.endpoint), link: '/applications' },
    { key: 'env', label: 'Set environment variables', auto: false, hint: 'Open an app row and click "env" to set variables' },
  ].map(i => ({ ...i, done: i.auto || onboardChecked.includes(i.key) }))
  const allOnboardDone = onboardItems.every(i => i.done)
  const showOnboard = !onboardDismissed && !allOnboardDone

  const erroredApps = allApps.filter(a => {
    const ps = a.production?.deploy?.status?.toLowerCase()
    const ss = a.sandbox?.deploy?.status?.toLowerCase()
    return ps === 'failed' || ps === 'error' || ss === 'failed' || ss === 'error'
  })

  // v2.6.6: after all hooks have run, check the role. Non-admins go to
  // /applications. Returning <Navigate> at this position is safe under
  // React's rules-of-hooks because every hook above this point has
  // already been called this render.
  if (me && !isAdmin(me)) {
    return <Navigate to="/applications" replace />
  }

  return (
    <div className="container">
      {showOnboard && (
        <div className="onboard-card">
          <div style={{ flex: 1 }}>
            <div className="onboard-hdr">
              <span className="onboard-title">Get started with AppCrane</span>
              <button className="onboard-dismiss" onClick={dismissOnboard}>×</button>
            </div>
            <div className="onboard-items">
              {onboardItems.map((item, i) => (
                <div key={i} className="onboard-item">
                  <button
                    type="button"
                    className={`onboard-check${item.done ? ' done' : ''}`}
                    onClick={() => toggleOnboard(item.key)}
                    title={item.auto ? 'Auto-detected — click to override' : 'Click to mark done'}
                    aria-pressed={item.done}
                  >
                    {item.done && '✓'}
                  </button>
                  <span className={`onboard-item-text${item.done ? ' done' : ''}`}>
                    {item.link && !item.done ? (
                      <a href={item.link} style={{ color: 'inherit', textDecoration: 'underline' }}>{item.label}</a>
                    ) : item.label}
                    {item.hint && !item.done && (
                      <span style={{ marginLeft: 8, color: 'var(--dim)', fontSize: '.78rem' }}>{item.hint}</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <h2>Server</h2>
      <div className="grid">
        {s && (
          <>
            <div className="stat">
              <div className="label">CPU</div>
              <div className="value">{s.cpu.percent}%</div>
              <div className="sub">{s.cpu.count} cores</div>
              <div className="bar">
                <div className="bar-fill" style={{ width: `${s.cpu.percent}%`, background: barColor(s.cpu.percent) }} />
              </div>
            </div>
            <div className="stat">
              <div className="label">Memory</div>
              <div className="value">{s.memory_formatted.used}</div>
              <div className="sub">of {s.memory_formatted.total}</div>
              <div className="bar">
                <div className="bar-fill" style={{ width: `${s.memory.percent}%`, background: barColor(s.memory.percent) }} />
              </div>
            </div>
            <div className="stat">
              <div className="label">Disk</div>
              <div className="value">{s.disk_formatted.used}</div>
              <div className="sub">of {s.disk_formatted.total}</div>
              <div className="bar">
                <div className="bar-fill" style={{ width: `${s.disk.percent}%`, background: barColor(s.disk.percent) }} />
              </div>
            </div>
          </>
        )}
        <div className="stat">
          <div className="label">Production</div>
          <div className="value">{prodLive} live</div>
          <div className="sub">{allApps.length} total apps</div>
        </div>
        <div className="stat">
          <div className="label">Sandbox</div>
          <div className="value">{sandLive} live</div>
          <div className="sub">{allApps.length} total apps</div>
        </div>
        <div className="stat">
          <div className="label">Users</div>
          <div className="value">{totalUsers}</div>
          <div className="sub">registered accounts</div>
        </div>
        <div className="stat" title="Active accounts with app or platform activity in the last 15 minutes">
          <div className="label">Active Now</div>
          <div className="value">{activeUsers ?? '—'}</div>
          <div className="sub">in the last 15 min</div>
        </div>
        <a className="stat" href="/enhancements-page" style={{ cursor: 'pointer' }}>
          <div className="label">Enhancements</div>
          <div className="value">{totalEnhReqs}</div>
          <div className="sub">all time requests</div>
        </a>
      </div>

      {usageSummary && (
        <>
          <h2>App Creation</h2>
          <div className="grid">
            <div className="stat">
              <div className="label">Total Jobs</div>
              <div className="value">{usageSummary.total_jobs ?? 0}</div>
            </div>
            <div className="stat">
              <div className="label">Succeeded</div>
              <div className="value" style={{ color: 'var(--green)' }}>{usageSummary.succeeded ?? 0}</div>
            </div>
            <div className="stat">
              <div className="label">Failed</div>
              <div className="value" style={{ color: 'var(--red)' }}>{usageSummary.failed ?? 0}</div>
            </div>
            <div className="stat">
              <div className="label">Total Tokens</div>
              <div className="value">{(usageSummary.total_tokens ?? 0).toLocaleString()}</div>
            </div>
            <div className="stat">
              <div className="label">Total Cost</div>
              <div className="value">${(usageSummary.total_cost ?? 0).toFixed(2)}</div>
            </div>
          </div>
        </>
      )}

      <h2>Visitors — Last 7 Days</h2>
      <div className="trend-box">
        {activity.apps.length > 0 && (
          <div className="trend-legend">
            {activity.apps.map((a, i) => (
              <span key={a.slug} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{
                  width: 10, height: 10, borderRadius: 2,
                  background: TREND_PALETTE[i % TREND_PALETTE.length], flexShrink: 0,
                }} />
                {a.name ?? a.slug}
              </span>
            ))}
          </div>
        )}
        <TrendChart days={activity.days} apps={activity.apps} />
      </div>

      {/* v2.6.10: top-10 leaderboards. Distinct active users per app,
          distinct apps opened per user. 7-day window, source app_visits. */}
      {(leaders.apps.length > 0 || leaders.users.length > 0) && (
        <div className="leaderboards">
          <div className="leaderboard-card">
            <h3>Top apps · 7 days <span className="leaderboard-sub">by distinct users</span></h3>
            {leaders.apps.length === 0 ? (
              <div className="leaderboard-empty">No app activity in the last 7 days.</div>
            ) : (
              <ol className="leaderboard-list">
                {leaders.apps.map((a, i) => (
                  <li key={a.slug}>
                    <span className="leaderboard-rank">{i + 1}</span>
                    <span className="leaderboard-name">
                      {a.name || a.slug}
                      {a.owner_name && (
                        <span className="leaderboard-attribution" title={a.owner_email || ''}>
                          by {a.owner_name}
                        </span>
                      )}
                    </span>
                    <span className="leaderboard-count">{a.users} {a.users === 1 ? 'user' : 'users'}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>
          <div className="leaderboard-card">
            <h3>Top users · 7 days <span className="leaderboard-sub">by distinct apps</span></h3>
            {leaders.users.length === 0 ? (
              <div className="leaderboard-empty">No user activity in the last 7 days.</div>
            ) : (
              <ol className="leaderboard-list">
                {leaders.users.map((u, i) => (
                  <li key={u.id}>
                    <span className="leaderboard-rank">{i + 1}</span>
                    <span className="leaderboard-name" title={u.email || ''}>{u.name}</span>
                    <span className="leaderboard-count">{u.apps} {u.apps === 1 ? 'app' : 'apps'}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      )}

      {/* v2.21.14: per-app operations (open, deploy, env, onboard, delete) live
          on the Manage page now — the Dashboard is overview-only. */}
      <h2>Applications</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.88rem', margin: '4px 0 0' }}>
        {allApps.length} app{allApps.length === 1 ? '' : 's'}
        {erroredApps.length > 0 && <span style={{ color: 'var(--red)' }}> · {erroredApps.length} with issues</span>}
        {' — '}<Link to="/applications">Manage applications →</Link>
      </p>
    </div>
  )
}
