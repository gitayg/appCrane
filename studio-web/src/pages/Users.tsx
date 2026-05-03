import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'

interface User {
  id: number
  name: string
  email: string
  username: string | null
  phone: string | null
  has_password: boolean
  last_login_at: string | null
  sso_provider: string | null
  kind?: 'human' | 'agent'
  created_at?: string
}

interface AgentUser {
  id: number
  name: string
  email: string
  created_at?: string
  assigned_apps?: string | null
}

interface App {
  slug: string
  name: string
}

type AppRole = 'none' | 'user' | 'admin'

function relativeTime(iso: string | null): { rel: string; abs: string } {
  if (!iso) return { rel: 'never', abs: '' }
  const d = new Date(iso)
  const abs = d.toLocaleString()
  const diff = (Date.now() - d.getTime()) / 1000
  if (diff < 60) return { rel: 'just now', abs }
  if (diff < 3600) return { rel: `${Math.floor(diff / 60)}m ago`, abs }
  if (diff < 86400) return { rel: `${Math.floor(diff / 3600)}h ago`, abs }
  if (diff < 2592000) return { rel: `${Math.floor(diff / 86400)}d ago`, abs }
  return { rel: abs, abs }
}

export function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [agents, setAgents] = useState<AgentUser[]>([])
  const [apps, setApps] = useState<App[]>([])
  const [roles, setRoles] = useState<Record<string, Record<number, AppRole>>>({})
  const [showForm, setShowForm] = useState(false)
  const [formMsg, setFormMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const nameRef = useRef<HTMLInputElement>(null)
  const emailRef = useRef<HTMLInputElement>(null)
  const usernameRef = useRef<HTMLInputElement>(null)
  const passwordRef = useRef<HTMLInputElement>(null)
  const phoneRef = useRef<HTMLInputElement>(null)
  const yobRef = useRef<HTMLInputElement>(null)

  // Settings → Users is for human portal users only. Agent / API-key
  // users created via "+ New App Agent" on /applications live in the
  // App Agents section below — they have no profile to edit, just
  // create + delete.  Pre-migration rows (kind absent) treat as human.
  const loadUsers = () =>
    adminApi.get<{ users: User[] }>('/api/users')
      .then(d => {
        const all = d.users ?? []
        setUsers(all.filter(u => (u.kind ?? 'human') === 'human'))
        setAgents(all.filter(u => u.kind === 'agent') as AgentUser[])
      })
      .catch(() => {})

  useEffect(() => {
    Promise.all([
      adminApi.get<{ users: User[] }>('/api/users'),
      adminApi.get<{ apps: App[] }>('/api/apps'),
    ]).then(([ur, ar]) => {
      const all = ur.users ?? []
      const u = all.filter(x => (x.kind ?? 'human') === 'human')
      const a = ar.apps ?? []
      setUsers(u)
      setAgents(all.filter(x => x.kind === 'agent') as AgentUser[])
      setApps(a)
      const roleMap: Record<string, Record<number, AppRole>> = {}
      Promise.all(
        a.map(app =>
          adminApi
            .get<{ users: { id: number; user_id?: number; app_role: AppRole }[] }>(`/api/apps/${app.slug}/identity/users`)
            .then(d => {
              roleMap[app.slug] = {}
              for (const r of (d.users ?? [])) roleMap[app.slug][r.user_id ?? r.id] = r.app_role
            })
            .catch(() => {
              roleMap[app.slug] = {}
            })
        )
      ).then(() => setRoles({ ...roleMap }))
    }).catch(() => {})
  }, [])

  async function createUser() {
    setFormMsg(null)
    const name = nameRef.current?.value.trim() ?? ''
    const email = emailRef.current?.value.trim() ?? ''
    const password = passwordRef.current?.value ?? ''
    if (!name || !email || !password) {
      setFormMsg({ text: 'Name, email, and password are required.', ok: false })
      return
    }
    const body: Record<string, unknown> = { name, email, role: 'user', password }
    const username = usernameRef.current?.value.trim()
    if (username) body.username = username
    const phone = phoneRef.current?.value.trim()
    if (phone) body.phone = phone
    const yob = yobRef.current?.value.trim()
    if (yob) body.year_of_birth = Number(yob)

    const res = await adminApi.post<{ error?: string }>('/api/users', body).catch(e => ({ error: String(e) }))
    if (res && (res as { error?: string }).error) {
      setFormMsg({ text: (res as { error?: string }).error!, ok: false })
    } else {
      setFormMsg({ text: 'User created!', ok: true })
      if (nameRef.current) nameRef.current.value = ''
      if (emailRef.current) emailRef.current.value = ''
      if (usernameRef.current) usernameRef.current.value = ''
      if (passwordRef.current) passwordRef.current.value = ''
      if (phoneRef.current) phoneRef.current.value = ''
      if (yobRef.current) yobRef.current.value = ''
      loadUsers()
    }
  }

  function updateProfile(id: number, field: string, value: string) {
    adminApi.put(`/api/users/${id}/profile`, { [field]: value || null }).catch(() => {})
  }

  async function setPassword(id: number) {
    const pw = prompt('New password:')
    if (!pw) return
    await adminApi.put(`/api/users/${id}/password`, { password: pw }).catch(() => {})
  }

  async function deleteUser(id: number) {
    if (!confirm('Delete this user?')) return
    await adminApi.del(`/api/users/${id}`).catch(() => {})
    loadUsers()
  }

  async function changeRole(slug: string, userId: number, role: AppRole) {
    setRoles(prev => ({
      ...prev,
      [slug]: { ...prev[slug], [userId]: role },
    }))
    await adminApi.put(`/api/apps/${slug}/roles`, { user_id: userId, app_role: role }).catch(() => {})
  }

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Users</h2>
        <button className="btn btn-sm" onClick={() => setShowForm(v => !v)}>
          {showForm ? 'Cancel' : '+ New User'}
        </button>
      </div>

      {showForm && (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'flex-end' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Name *</label>
              <input ref={nameRef} type="text" style={{ width: 120 }} placeholder="Name" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Email *</label>
              <input ref={emailRef} type="email" style={{ width: 180 }} placeholder="Email" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Username</label>
              <input ref={usernameRef} type="text" style={{ width: 120 }} placeholder="Username" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Password *</label>
              <input ref={passwordRef} type="password" style={{ width: 120 }} placeholder="Password" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Phone</label>
              <input ref={phoneRef} type="text" style={{ width: 120 }} placeholder="Phone" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Year of Birth</label>
              <input ref={yobRef} type="number" style={{ width: 80 }} placeholder="Year" />
            </div>
            <button className="btn btn-accent btn-sm" onClick={createUser}>Create</button>
          </div>
          {formMsg && (
            <div style={{ marginTop: 8, fontSize: '0.85rem', color: formMsg.ok ? 'var(--green)' : 'var(--red)' }}>
              {formMsg.text}
            </div>
          )}
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Username</th>
            <th>Phone</th>
            <th>Password</th>
            <th>Last login</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => {
            const { rel, abs } = relativeTime(u.last_login_at)
            return (
              <tr key={u.id}>
                <td>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{u.id}</span>
                  {u.id === 1 && (
                    <span className="tag" style={{ marginLeft: 6, color: 'var(--accent)', borderColor: 'var(--accent)' }}>OWNER</span>
                  )}
                  {u.sso_provider && (
                    <span className="tag" style={{ marginLeft: 6, color: 'var(--dim)' }}>{u.sso_provider.toUpperCase()}</span>
                  )}
                </td>
                <td>
                  <input
                    className="editable"
                    defaultValue={u.name ?? ''}
                    onBlur={e => updateProfile(u.id, 'name', e.target.value)}
                  />
                </td>
                <td>
                  <input
                    className="editable"
                    defaultValue={u.email ?? ''}
                    onBlur={e => updateProfile(u.id, 'email', e.target.value)}
                  />
                </td>
                <td>
                  <input
                    className="editable"
                    defaultValue={u.username ?? ''}
                    onBlur={e => updateProfile(u.id, 'username', e.target.value)}
                  />
                </td>
                <td>
                  <input
                    className="editable"
                    defaultValue={u.phone ?? ''}
                    onBlur={e => updateProfile(u.id, 'phone', e.target.value)}
                  />
                </td>
                <td>
                  {u.has_password && (
                    <span style={{ color: 'var(--green)', marginRight: 6 }}>&#10003;</span>
                  )}
                  <button className="btn btn-xs" onClick={() => setPassword(u.id)}>set</button>
                </td>
                <td>
                  <span style={{ color: 'var(--dim)', fontSize: '0.82rem' }} title={abs}>{rel}</span>
                </td>
                <td>
                  {u.id !== 1 && (
                    <button className="btn btn-red btn-xs" onClick={() => deleteUser(u.id)}>Delete</button>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      <h2 style={{ marginTop: 32 }}>App Agents</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginTop: -8, marginBottom: 12 }}>
        API-key identities created from <a href="/applications" style={{ color: 'var(--accent)' }}>/applications</a> via &ldquo;+ New App Agent&rdquo;.
        These have no profile to edit — manage them here.
      </p>
      {agents.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No app agents.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Assigned apps</th>
              <th>Created</th>
              <th>Delete</th>
            </tr>
          </thead>
          <tbody>
            {agents.map(a => (
              <tr key={a.id}>
                <td style={{ fontFamily: 'monospace', fontSize: '.8rem' }}>{a.id}</td>
                <td>{a.name}</td>
                <td>{a.email}</td>
                <td style={{ color: a.assigned_apps ? 'var(--text)' : 'var(--dim)', fontSize: '.82rem' }}>
                  {a.assigned_apps || 'unused'}
                </td>
                <td style={{ color: 'var(--dim)', fontSize: '.8rem' }}>
                  {a.created_at ? new Date(a.created_at).toLocaleDateString() : ''}
                </td>
                <td>
                  <button className="btn btn-red btn-xs" onClick={() => deleteUser(a.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {apps.length > 0 && users.length > 0 && (
        <>
          <h2 style={{ marginTop: 32 }}>App Roles</h2>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  {apps.map(a => <th key={a.slug}>{a.name}</th>)}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{u.name}</td>
                    {apps.map(a => (
                      <td key={a.slug}>
                        <select
                          value={roles[a.slug]?.[u.id] ?? 'none'}
                          onChange={e => changeRole(a.slug, u.id, e.target.value as AppRole)}
                        >
                          <option value="none">none</option>
                          <option value="user">user</option>
                          <option value="admin">admin</option>
                        </select>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
