import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'

interface User {
  id: number
  name: string
  email: string
  role: 'platform_admin' | 'admin' | 'user'
  username: string | null
  phone: string | null
  has_password: boolean
  last_login_at: string | null
  sso_provider: string | null
  kind?: 'human' | 'agent'
  created_at?: string
}

interface App {
  slug: string
  name: string
}

type AppRole = 'none' | 'user' | 'admin' | 'owner'

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
  const [apps, setApps] = useState<App[]>([])
  const [roles, setRoles] = useState<Record<string, Record<number, AppRole>>>({})
  const [roleSaveStatus, setRoleSaveStatus] = useState<Record<string, 'saving' | 'saved' | 'error'>>({})
  const [showForm, setShowForm] = useState(false)
  const [formMsg, setFormMsg] = useState<{ text: string; ok: boolean } | null>(null)
  // v2.5.19: per-user app-access modal. Click "Apps" on a user row to
  // open a focused list of every app + that user's role on it. Uses the
  // same changeRole + roles state as the wide matrix below — both views
  // stay in sync, and the modal is easier with many apps. The wide
  // matrix stays for now as a power-user / bulk-edit affordance.
  const [appsModalUser, setAppsModalUser] = useState<User | null>(null)
  const [newKind, setNewKind] = useState<'human' | 'agent'>('human')
  const [kindFilter, setKindFilter] = useState<'all' | 'human' | 'agent'>('human')
  // Modal shows the result of any key-issuance flow. `kind === 'mcp'` →
  // the value is a dhk_mcp_* key with a `claude mcp add` command.
  // `kind === 'legacy'` → a dhk_user_* / dhk_admin_* key intended for CI
  // env vars; the "setup command" shows the env-var form instead.
  const [mcpKeyModal, setMcpKeyModal] = useState<{
    open: boolean
    kind?: 'mcp' | 'legacy'
    userName?: string
    userEmail?: string
    apiKey?: string
    setupCmd?: string
    copiedKey?: boolean
    copiedCmd?: boolean
  }>({ open: false })

  const nameRef = useRef<HTMLInputElement>(null)
  const emailRef = useRef<HTMLInputElement>(null)
  const usernameRef = useRef<HTMLInputElement>(null)
  const passwordRef = useRef<HTMLInputElement>(null)
  const phoneRef = useRef<HTMLInputElement>(null)
  const yobRef = useRef<HTMLInputElement>(null)

  // Settings → Users is for human portal users only. Agent / API-key
  // identities are filtered out client-side (kind === 'agent' rows are
  // dropped). Pre-migration rows (kind absent) treat as human. The
  // separate /settings#agents tab was removed in v2.5.10 — agents are
  // managed via the API key issuance flow, not a UI tab.
  const loadUsers = () =>
    adminApi.get<{ users: User[] }>('/api/users')
      .then(d => setUsers((d.users ?? []).filter(u => (u.kind ?? 'human') === 'human')))
      .catch(() => {})

  useEffect(() => {
    Promise.all([
      adminApi.get<{ users: User[] }>('/api/users'),
      adminApi.get<{ apps: App[] }>('/api/apps'),
    ]).then(([ur, ar]) => {
      const u = (ur.users ?? []).filter(x => (x.kind ?? 'human') === 'human')
      const a = ar.apps ?? []
      setUsers(u)
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
    const isAgent = newKind === 'agent'

    if (!name || !email) {
      setFormMsg({ text: 'Name and email are required.', ok: false })
      return
    }
    if (!isAgent && !password) {
      setFormMsg({ text: 'Password is required for human users.', ok: false })
      return
    }

    const body: Record<string, unknown> = { name, email, role: 'user', kind: newKind }
    if (password) body.password = password
    const username = usernameRef.current?.value.trim()
    if (username) body.username = username
    const phone = phoneRef.current?.value.trim()
    if (phone) body.phone = phone
    const yob = yobRef.current?.value.trim()
    if (yob) body.year_of_birth = Number(yob)

    const res = await adminApi
      .post<{ error?: string; key?: string; api_key?: string; user?: { name: string; email: string } }>(
        '/api/users',
        body,
      )
      .catch(e => ({ error: String(e) }))
    if (res && (res as { error?: string }).error) {
      setFormMsg({ text: (res as { error?: string }).error!, ok: false })
      return
    }

    // Clear the form
    if (nameRef.current) nameRef.current.value = ''
    if (emailRef.current) emailRef.current.value = ''
    if (usernameRef.current) usernameRef.current.value = ''
    if (passwordRef.current) passwordRef.current.value = ''
    if (phoneRef.current) phoneRef.current.value = ''
    if (yobRef.current) yobRef.current.value = ''
    loadUsers()

    // Agents come back with a freshly-generated legacy API key — show it
    // in the same modal we use for MCP keys, with an env-var setup hint
    // instead of a `claude mcp add` command.
    if (isAgent) {
      const apiKey = (res as { key?: string; api_key?: string }).key ?? (res as { api_key?: string }).api_key ?? ''
      if (apiKey) {
        setMcpKeyModal({
          open: true,
          kind: 'legacy',
          userName: name,
          userEmail: email,
          apiKey,
          setupCmd:
            `# CI / scripts / external integrations:\n` +
            `export APPCRANE_API_KEY="${apiKey}"\n` +
            `\n` +
            `# Or pass directly with curl:\n` +
            `curl -H "X-API-Key: ${apiKey}" https://${typeof window !== 'undefined' ? window.location.host : 'your-appcrane-host'}/api/info`,
        })
        setFormMsg({ text: `Agent created — API key shown in dialog (won't be shown again).`, ok: true })
      } else {
        setFormMsg({ text: 'Agent created (no API key returned).', ok: true })
      }
    } else {
      setFormMsg({ text: 'User created.', ok: true })
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

  /**
   * Admin issues an MCP key for any user — they don't need to log in to
   * the dashboard themselves. Output is the full `claude mcp add` command
   * with the key inlined, ready to paste into a note/email to the user.
   */
  async function issueMcpKey(u: User) {
    if (!confirm(`Issue an MCP key for ${u.name}?\n\nThe key will be shown once. You'll need to send it to them via a secure channel.`)) return
    try {
      const r = await adminApi.post<{
        api_key?: string
        target?: { name: string; email: string }
      }>(`/api/users/${u.id}/mcp-keys`, { label: `admin-issued-${new Date().toISOString().slice(0, 10)}` })
      if (!r?.api_key) throw new Error('Server returned no key')
      const origin = typeof window !== 'undefined' ? window.location.origin : 'https://your-appcrane-host'
      const setupCmd =
        `claude mcp add --transport http appcrane ${origin}/api/mcp \\\n` +
        `  --header "X-API-Key: ${r.api_key}" \\\n` +
        `  --header "X-Github-Token: <YOUR_GITHUB_PAT>"`
      setMcpKeyModal({
        open: true,
        kind: 'mcp',
        userName: r.target?.name || u.name,
        userEmail: r.target?.email || u.email,
        apiKey: r.api_key,
        setupCmd,
      })
    } catch (e) {
      alert('Could not issue MCP key: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  async function changeRole(slug: string, userId: number, role: AppRole) {
    const cellKey = `${slug}:${userId}`
    const previousRole = roles[slug]?.[userId] ?? 'none'

    // Optimistic UI update + "saving" indicator
    setRoles(prev => ({
      ...prev,
      [slug]: { ...prev[slug], [userId]: role },
    }))
    setRoleSaveStatus(s => ({ ...s, [cellKey]: 'saving' }))

    try {
      await adminApi.put(`/api/apps/${slug}/roles`, { user_id: userId, app_role: role })
      setRoleSaveStatus(s => ({ ...s, [cellKey]: 'saved' }))
      // Auto-clear the green check after 1.8s.
      setTimeout(() => {
        setRoleSaveStatus(s => {
          if (s[cellKey] !== 'saved') return s
          const copy = { ...s }
          delete copy[cellKey]
          return copy
        })
      }, 1800)
    } catch (e) {
      // Revert the optimistic update so the dropdown reflects truth.
      setRoles(prev => ({
        ...prev,
        [slug]: { ...prev[slug], [userId]: previousRole },
      }))
      setRoleSaveStatus(s => ({ ...s, [cellKey]: 'error' }))
      const msg = e instanceof Error ? e.message : String(e)
      alert(`Could not save role for "${slug}": ${msg}`)
    }
  }

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Users</h2>
        <button className="btn btn-sm" onClick={() => setShowForm(v => !v)}>
          {showForm ? 'Cancel' : '+ New User'}
        </button>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          {(['all', 'human', 'agent'] as const).map(k => (
            <button
              key={k}
              className={`btn btn-xs${kindFilter === k ? ' btn-accent' : ''}`}
              onClick={() => setKindFilter(k)}
              style={{ textTransform: 'capitalize' }}
            >
              {k === 'all' ? 'All' : k === 'human' ? 'Humans' : 'Agents'}
            </button>
          ))}
        </div>
      </div>

      {showForm && (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'flex-end' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>Kind</label>
              <select
                value={newKind}
                onChange={e => setNewKind(e.target.value as 'human' | 'agent')}
                style={{ width: 100 }}
                title="Human users sign in with a password. Agents are bot/CI identities that authenticate by API key (legacy or MCP)."
              >
                <option value="human">Human</option>
                <option value="agent">Agent</option>
              </select>
            </div>
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
              <label style={{ fontSize: '0.75rem', color: 'var(--dim)' }}>
                Password{newKind === 'human' ? ' *' : ''}
              </label>
              <input
                ref={passwordRef}
                type="password"
                style={{ width: 120, opacity: newKind === 'agent' ? 0.5 : 1 }}
                placeholder={newKind === 'agent' ? '(not used)' : 'Password'}
                disabled={newKind === 'agent'}
              />
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
          {users
            .filter(u => {
              if (kindFilter === 'all') return true
              const kind = u.kind ?? 'human'
              return kindFilter === kind
            })
            .map(u => {
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
                  <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                    <button
                      className="btn btn-xs"
                      onClick={() => setAppsModalUser(u)}
                      title="Edit which apps this user has access to and at what role"
                    >
                      Apps
                    </button>
                    <button
                      className="btn btn-xs"
                      onClick={() => issueMcpKey(u)}
                      title="Issue an MCP key for this user — they don't need to log in to the dashboard. The key is shown once."
                    >
                      + MCP key
                    </button>
                    {u.id !== 1 && (
                      <button className="btn btn-red btn-xs" onClick={() => deleteUser(u.id)}>Delete</button>
                    )}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {/* v2.5.21: the wide N×M App Roles matrix moved out of Users in two
          directions:
          - Per-user editor: the "Apps" button on each user row above
            (added v2.5.19) opens a focused per-user modal.
          - Per-app editor: a "Users" button on each app row in the
            Applications Manage table opens a focused per-app modal.
          The matrix is gone — same surface area, less visual noise,
          and it scales to many apps × many users without becoming a
          400-cell soup. */}

      {mcpKeyModal.open && (
        <div
          onClick={() => setMcpKeyModal({ open: false })}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
            backdropFilter: 'blur(2px)',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 12, padding: 28, maxWidth: 720, width: '94%',
              boxShadow: '0 24px 64px rgba(0,0,0,.5)',
            }}
          >
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>
              ✓ {mcpKeyModal.kind === 'legacy' ? 'Agent created — legacy API key issued' : 'MCP key issued'}
            </h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              For <strong style={{ color: 'var(--text)' }}>{mcpKeyModal.userName}</strong>
              {mcpKeyModal.userEmail ? <> · {mcpKeyModal.userEmail}</> : null}
            </p>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>API key</span>
                <button
                  className="btn btn-xs"
                  onClick={() => {
                    if (mcpKeyModal.apiKey) {
                      navigator.clipboard.writeText(mcpKeyModal.apiKey).then(() => {
                        setMcpKeyModal(s => ({ ...s, copiedKey: true }))
                        setTimeout(() => setMcpKeyModal(s => ({ ...s, copiedKey: false })), 1800)
                      })
                    }
                  }}
                >
                  {mcpKeyModal.copiedKey ? '✓ Copied' : 'Copy key'}
                </button>
              </div>
              <code
                style={{
                  display: 'block', background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace',
                  fontSize: '.82rem', wordBreak: 'break-all', userSelect: 'all',
                }}
              >
                {mcpKeyModal.apiKey}
              </code>
            </div>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>
                  {mcpKeyModal.kind === 'legacy' ? 'CI / env-var setup' : 'Setup command (paste-ready for the user)'}
                </span>
                <button
                  className="btn btn-xs"
                  onClick={() => {
                    if (mcpKeyModal.setupCmd) {
                      navigator.clipboard.writeText(mcpKeyModal.setupCmd).then(() => {
                        setMcpKeyModal(s => ({ ...s, copiedCmd: true }))
                        setTimeout(() => setMcpKeyModal(s => ({ ...s, copiedCmd: false })), 1800)
                      })
                    }
                  }}
                >
                  {mcpKeyModal.copiedCmd ? '✓ Copied' : 'Copy command'}
                </button>
              </div>
              <pre
                style={{
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace',
                  fontSize: '.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  userSelect: 'all', margin: 0,
                }}
              >
                {mcpKeyModal.setupCmd}
              </pre>
              {mcpKeyModal.kind !== 'legacy' && (
                <p style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6, marginBottom: 0 }}>
                  The user replaces <code style={{ fontFamily: 'monospace' }}>&lt;YOUR_GITHUB_PAT&gt;</code> with their own GitHub PAT before running.
                </p>
              )}
            </div>

            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)',
              border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow, #f59e0b)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Send it to the user via a secure channel (encrypted message, password manager, etc.).
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setMcpKeyModal({ open: false })}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* v2.5.19: per-user apps modal. Reuses changeRole + roles state so
          changes here are immediately visible in the wide matrix below. */}
      {appsModalUser && (
        <div
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onClick={() => setAppsModalUser(null)}
        >
          <div
            style={{
              width: 'min(560px, 92vw)', maxHeight: '80vh',
              background: 'var(--surface, #1a1a1a)', color: 'var(--text)',
              border: '1px solid var(--border, #333)', borderRadius: 8,
              boxShadow: '0 16px 48px rgba(0,0,0,.5)',
              display: 'flex', flexDirection: 'column', overflow: 'hidden',
            }}
            onClick={e => e.stopPropagation()}
            role="dialog"
            aria-label={`Apps for ${appsModalUser.name}`}
          >
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '12px 16px',
              borderBottom: '1px solid var(--border, #333)',
              background: 'var(--surface2, #232323)',
            }}>
              <span style={{ fontWeight: 600, fontSize: '.95rem' }}>
                Apps · {appsModalUser.name}
              </span>
              {appsModalUser.role === 'platform_admin' && (
                <span style={{
                  fontSize: '.7rem', padding: '2px 8px', borderRadius: 3,
                  background: 'rgba(245, 158, 11, .2)', color: '#fbbf24',
                  border: '1px solid rgba(245, 158, 11, .4)',
                }}>
                  platform_admin — implicit owner everywhere
                </span>
              )}
              <button
                style={{
                  marginLeft: 'auto', background: 'none', border: 'none',
                  color: 'var(--dim)', fontSize: '1.4rem', lineHeight: 1, cursor: 'pointer',
                }}
                onClick={() => setAppsModalUser(null)}
                aria-label="Close"
              >×</button>
            </div>

            <div style={{ overflowY: 'auto', padding: '8px 16px', flex: 1 }}>
              {apps.length === 0 ? (
                <div style={{ color: 'var(--dim)', padding: 16 }}>No apps registered.</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border, #333)' }}>
                      <th style={{ textAlign: 'left', padding: '8px 4px', fontSize: '.78rem', color: 'var(--dim)', fontWeight: 500 }}>App</th>
                      <th style={{ textAlign: 'right', padding: '8px 4px', fontSize: '.78rem', color: 'var(--dim)', fontWeight: 500 }}>Role</th>
                      <th style={{ width: 28 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {apps.map(a => {
                      const cellKey = `${a.slug}:${appsModalUser.id}`
                      const status = roleSaveStatus[cellKey]
                      const isPlatformAdmin = appsModalUser.role === 'platform_admin'
                      const value = isPlatformAdmin ? 'owner' : (roles[a.slug]?.[appsModalUser.id] ?? 'none')
                      return (
                        <tr key={a.slug} style={{ borderBottom: '1px solid var(--border-faint, #2a2a2a)' }}>
                          <td style={{ padding: '8px 4px', fontSize: '.88rem' }}>
                            <div style={{ fontWeight: 500 }}>{a.name}</div>
                            <div style={{ fontSize: '.74rem', color: 'var(--dim)', fontFamily: 'monospace' }}>{a.slug}</div>
                          </td>
                          <td style={{ padding: '8px 4px', textAlign: 'right' }}>
                            <select
                              value={value}
                              disabled={isPlatformAdmin || status === 'saving'}
                              onChange={e => changeRole(a.slug, appsModalUser.id, e.target.value as AppRole)}
                              style={{ minWidth: 110 }}
                            >
                              <option value="none">none</option>
                              <option value="user">user</option>
                              <option value="admin">admin</option>
                              <option value="owner">owner</option>
                            </select>
                          </td>
                          <td style={{ padding: '8px 0', textAlign: 'center', width: 28 }}>
                            {!isPlatformAdmin && status === 'saving' && <span style={{ color: 'var(--dim)' }}>…</span>}
                            {!isPlatformAdmin && status === 'saved'  && <span style={{ color: 'var(--green)' }}>✓</span>}
                            {!isPlatformAdmin && status === 'error'  && <span style={{ color: 'var(--red)' }}>✗</span>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            <div style={{
              padding: '10px 16px',
              borderTop: '1px solid var(--border, #333)',
              background: 'var(--surface2, #232323)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span style={{ fontSize: '.74rem', color: 'var(--dim)' }}>
                Changes save automatically.
              </span>
              <button className="btn btn-accent" onClick={() => setAppsModalUser(null)}>Done</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
