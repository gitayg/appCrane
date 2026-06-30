import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * Manage — owner self-service (v2.13.0). A top-level page (gated to app-owners
 * and admins) where you set category / visibility / auth-mode and manage the
 * users of apps you own or admin. These controls used to live on the launcher
 * tiles; when the launcher dissolved into the main nav they moved here so
 * non-admin owners keep self-service.
 */

interface AppRow {
  slug:        string
  name:        string
  description?: string
  visibility?: string
  category?:   string
  auth_mode?:  'authenticated' | 'headless'
  app_role?:   'admin' | 'owner' | 'user' | 'viewer' | 'none'
}

type AppMemberRole = 'none' | 'user' | 'admin' | 'owner'
interface ModalUser { id: number; name: string; email: string | null; role: string; app_role: AppMemberRole }

export function ManageView() {
  const [apps, setApps] = useState<AppRow[]>([])
  const [search, setSearch] = useState('')
  const [usersModalApp, setUsersModalApp] = useState<AppRow | null>(null)
  const [usersModalData, setUsersModalData] = useState<ModalUser[] | null>(null)
  const [usersSaving, setUsersSaving] = useState<Record<number, 'saving' | 'saved' | 'error'>>({})
  const [usersFilter, setUsersFilter] = useState('')

  useEffect(() => {
    adminApi.get<{ apps: AppRow[] }>('/api/apps')
      .then(r => setApps((r?.apps || []).filter(a => a.app_role === 'owner' || a.app_role === 'admin')))
      .catch(() => setApps([]))
  }, [])

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
    if (!search) return true
    const q = search.toLowerCase()
    return (a.name || '').toLowerCase().includes(q) || (a.category || '').toLowerCase().includes(q)
  })

  return (
    <div className="container">
      <div className="launcher-header">
        <h2 style={{ margin: 0 }}>Manage</h2>
        <input
          type="text"
          placeholder="Search…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          autoComplete="off"
          className="launcher-search"
        />
      </div>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginTop: 0 }}>
        Apps you own or admin. Set category, visibility, and auth mode, and manage who can access each app.
      </p>

      {filtered.length === 0 ? (
        <div className="launcher-empty">
          {apps.length === 0 ? 'You don’t own or admin any apps yet.' : `No apps match "${search}".`}
        </div>
      ) : (
        <table className="manage-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.85rem' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--dim)', fontSize: '.72rem', textTransform: 'uppercase', letterSpacing: '.05em' }}>
              <th style={{ padding: '8px 6px' }}>App</th>
              <th style={{ padding: '8px 6px' }}>Category</th>
              <th style={{ padding: '8px 6px' }}>Visibility</th>
              <th style={{ padding: '8px 6px' }}>Auth</th>
              <th style={{ padding: '8px 6px' }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(app => (
              <tr key={app.slug} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 6px', fontWeight: 600 }}>{app.name}</td>
                <td style={{ padding: '8px 6px' }}>
                  <select className="launcher-tile-ctrl" value={app.category ?? ''} onChange={e => changeCategory(app.slug, e.target.value)} aria-label={`Category for ${app.name}`}>
                    <option value="">— none —</option>
                    {categories.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </td>
                <td style={{ padding: '8px 6px' }}>
                  <select className="launcher-tile-ctrl" value={app.visibility ?? 'private'} onChange={e => changeVisibility(app.slug, e.target.value)} aria-label={`Visibility for ${app.name}`}>
                    <option value="public">public</option>
                    <option value="private">private</option>
                    <option value="hidden">hidden</option>
                  </select>
                </td>
                <td style={{ padding: '8px 6px' }}>
                  <select
                    className="launcher-tile-ctrl"
                    value={app.auth_mode ?? 'authenticated'}
                    onChange={e => changeAuthMode(app.slug, app.name, e.target.value)}
                    aria-label={`Auth mode for ${app.name}`}
                    style={app.auth_mode === 'headless' ? { borderColor: 'var(--red, #ef4444)', color: 'var(--red, #ef4444)' } : undefined}
                  >
                    <option value="authenticated">SSO</option>
                    <option value="headless">headless</option>
                  </select>
                </td>
                <td style={{ padding: '8px 6px', textAlign: 'right' }}>
                  <button className="btn btn-xs" onClick={() => setUsersModalApp(app)} title={`Manage users for ${app.name}`}>Users</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {usersModalApp && (
        <div
          onClick={() => { setUsersModalApp(null); setUsersFilter('') }}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, backdropFilter: 'blur(2px)' }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 24, maxWidth: 620, width: '94%', maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 24px 64px rgba(0,0,0,.5)' }}
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
              style={{ width: '100%', boxSizing: 'border-box', marginBottom: 12, padding: '6px 10px', fontSize: '.85rem', background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
            />
            {usersModalData === null ? (
              <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>Loading…</p>
            ) : usersModalData.length === 0 ? (
              <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No users found.</p>
            ) : (() => {
              const q = usersFilter.trim().toLowerCase()
              const flt = q
                ? usersModalData.filter(u => (u.name || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))
                : usersModalData
              if (flt.length === 0) return <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No users match &quot;{usersFilter}&quot;.</p>
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
                            <select value={u.app_role} onChange={e => changeUserAppRole(u.id, e.target.value as AppMemberRole)} style={{ fontSize: '.8rem' }}>
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
