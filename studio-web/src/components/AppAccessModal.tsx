import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

/**
 * Access — the two role systems for one app, side by side.
 *
 * AppCrane's own per-app tier (owner / admin / user) decides what someone may
 * do to the app INSIDE AppCrane: deploy it, read its env, delete it. It is
 * read-only here on purpose — it is set in Users, and this screen must not
 * become a second place membership is managed.
 *
 * App-defined roles are the vocabulary the app invents for itself. AppCrane
 * only stores them and hands them to the app (/api/me and the
 * X-AppCrane-App-Roles header); the app decides what they mean. They confer
 * nothing in AppCrane. The two are drawn deliberately differently — square
 * muted tier chips vs. rounded monospace role pills — because "admin" the
 * platform tier and "approver" the app role are the two things people
 * conflate, and the UI is where that confusion starts.
 */

/** Mirrors ROLE_KEY_PATTERN in server/services/appDefinedRoles.js. The server
 *  is the enforcer; this only exists so the form can say no before the POST. */
const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/
const RESERVED_KEYS = ['owner', 'admin', 'user', 'viewer', 'none', 'platform_admin']
const MAX_ROLES_PER_APP = 16

const CSS = `
.aa-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:10500;display:flex;align-items:center;justify-content:center}
.aa-modal{width:min(760px,94vw);max-height:86vh;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;box-shadow:0 16px 48px rgba(0,0,0,.5);display:flex;flex-direction:column;overflow:hidden}
.aa-hdr{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}
.aa-hdr-title{font-weight:600;font-size:.95rem}
.aa-hdr-slug{font-size:.74rem;color:var(--dim);font-family:'SF Mono',Monaco,monospace}
.aa-close{margin-left:auto;background:none;border:none;color:var(--dim);font-size:1.4rem;line-height:1;cursor:pointer}
.aa-body{overflow-y:auto;padding:14px 16px;flex:1;display:flex;flex-direction:column;gap:16px}
.aa-msg{padding:7px 11px;border-radius:6px;font-size:.82rem}
.aa-msg-ok{background:#22c55e18;border:1px solid #22c55e44;color:var(--green)}
.aa-msg-err{background:#ef444418;border:1px solid #ef444444;color:var(--red)}
.aa-legend{display:flex;gap:10px;flex-wrap:wrap}
.aa-legend-col{flex:1 1 260px;background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:10px 12px}
.aa-legend-col h4{font-size:.78rem;margin:0 0 5px;display:flex;align-items:center;gap:6px;font-weight:600}
.aa-legend-col p{font-size:.75rem;color:var(--dim);line-height:1.5;margin:0}
.aa-panel{border:1px solid var(--border);border-radius:8px;background:var(--surface2)}
.aa-panel-hdr{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border)}
.aa-panel-hdr h3{font-size:.85rem;margin:0;font-weight:600}
.aa-panel-count{font-size:.72rem;color:var(--dim)}
.aa-panel-body{padding:10px 12px}
.aa-table{width:100%;border-collapse:collapse}
.aa-table th{text-align:left;padding:6px 6px;font-size:.72rem;color:var(--dim);font-weight:500;border-bottom:1px solid var(--border);white-space:nowrap}
.aa-table td{padding:8px 6px;font-size:.84rem;border-bottom:1px solid var(--border);vertical-align:top}
.aa-table tr:last-child td{border-bottom:none}
.aa-key{font-family:'SF Mono',Monaco,monospace;font-size:.78rem;background:#3b82f61a;border:1px solid #3b82f655;color:var(--accent);border-radius:999px;padding:1px 9px;display:inline-block}
.aa-tier{font-size:.68rem;text-transform:uppercase;letter-spacing:.4px;font-weight:600;background:var(--bg);border:1px solid var(--border);color:var(--dim);border-radius:3px;padding:2px 7px;display:inline-block}
.aa-rolechip{font-family:'SF Mono',Monaco,monospace;font-size:.75rem;border-radius:999px;padding:2px 10px;cursor:pointer;background:transparent;border:1px dashed var(--border);color:var(--dim)}
.aa-rolechip:hover{border-color:var(--accent);color:var(--accent)}
.aa-rolechip.on{background:#3b82f61a;border:1px solid var(--accent);color:var(--accent);font-weight:600}
.aa-rolechip:disabled{cursor:default;opacity:.55}
.aa-chiprow{display:flex;flex-wrap:wrap;gap:5px;align-items:center}
.aa-empty{font-size:.82rem;color:var(--dim);line-height:1.6}
.aa-empty strong{color:var(--text)}
.aa-empty code{font-family:'SF Mono',Monaco,monospace;font-size:.78rem;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1px 5px}
.aa-form{display:flex;flex-wrap:wrap;gap:7px;align-items:flex-start;margin-top:10px;padding-top:10px;border-top:1px solid var(--border)}
.aa-form input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 9px;border-radius:5px;font-size:.82rem}
.aa-form input.mono{font-family:'SF Mono',Monaco,monospace}
.aa-hint{font-size:.72rem;color:var(--dim);width:100%}
.aa-hint-bad{color:var(--red)}
.aa-foot{padding:10px 16px;border-top:1px solid var(--border);background:var(--surface2);display:flex;justify-content:space-between;align-items:center;gap:10px}
.aa-foot-note{font-size:.73rem;color:var(--dim)}
`

interface DefinedRole {
  id: number
  key: string
  label: string
  description: string | null
  member_count: number
}

/** AppCrane's own per-app tier. 'none' means assigned to the app but granted
 *  no tier — worth showing verbatim rather than dressing up as 'user'. */
type Tier = 'owner' | 'admin' | 'user' | 'none'

interface Member {
  id: number
  name: string
  email: string | null
  app_role: Tier
  app_roles: string[]
}

interface AppAccessModalProps {
  slug: string
  name: string
  onClose: () => void
}

export function AppAccessModal({ slug, name, onClose }: AppAccessModalProps) {
  const [roles, setRoles] = useState<DefinedRole[] | null>(null)
  const [members, setMembers] = useState<Member[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [saving, setSaving] = useState<Record<number, boolean>>({})

  const [newKey, setNewKey] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [creating, setCreating] = useState(false)

  const [editId, setEditId] = useState<number | null>(null)
  const [editLabel, setEditLabel] = useState('')
  const [editDesc, setEditDesc] = useState('')

  function flash(text: string, ok: boolean) {
    setMsg({ text, ok })
    setTimeout(() => setMsg(m => (m && m.text === text ? null : m)), 5000)
  }

  useEffect(() => {
    let cancelled = false
    setLoadError(null)
    Promise.all([
      adminApi.get<{ roles: DefinedRole[] }>(`/api/apps/${slug}/app-roles`),
      adminApi.get<{ members: Member[] }>(`/api/apps/${slug}/app-roles/members`),
    ])
      .then(([r, m]) => {
        if (cancelled) return
        setRoles(r.roles || [])
        setMembers(m.members || [])
      })
      .catch(e => { if (!cancelled) setLoadError((e as Error).message) })

    return () => { cancelled = true }
  }, [slug])

  /** Live count from the members list, which this screen mutates as chips are
   *  toggled. Falls back to the server's count if members failed to load. */
  function holdersOf(role: DefinedRole): number {
    if (!members) return role.member_count
    return members.filter(m => m.app_roles.includes(role.key)).length
  }

  const keyTrimmed = newKey.trim()
  const keyError = !keyTrimmed ? null
    : !ROLE_KEY_PATTERN.test(keyTrimmed)
      ? 'Lowercase letter first, then lowercase letters, digits, - or _ (max 32).'
      : RESERVED_KEYS.includes(keyTrimmed)
        ? `'${keyTrimmed}' is reserved by AppCrane — pick a name the platform does not already use.`
        : roles?.some(r => r.key === keyTrimmed)
          ? `This app already defines '${keyTrimmed}'.`
          : null
  const atLimit = (roles?.length ?? 0) >= MAX_ROLES_PER_APP

  async function createRole() {
    if (!keyTrimmed || keyError || !newLabel.trim()) return
    setCreating(true)
    try {
      const r = await adminApi.post<{ role: DefinedRole }>(`/api/apps/${slug}/app-roles`, {
        key: keyTrimmed,
        label: newLabel.trim(),
        description: newDesc.trim() || undefined,
      })
      setRoles(prev => [...(prev || []), { ...r.role, member_count: 0 }].sort((a, b) => a.key.localeCompare(b.key)))
      setNewKey(''); setNewLabel(''); setNewDesc('')
      flash(`Role '${r.role.key}' defined. Grant it below — nobody holds it yet.`, true)
    } catch (e) {
      flash((e as Error).message, false)
    } finally {
      setCreating(false)
    }
  }

  async function saveEdit(role: DefinedRole) {
    if (!editLabel.trim()) return
    try {
      const r = await adminApi.patch<{ role: DefinedRole }>(`/api/apps/${slug}/app-roles/${role.id}`, {
        label: editLabel.trim(),
        description: editDesc.trim() || null,
      })
      setRoles(prev => (prev || []).map(x => x.id === role.id ? { ...x, label: r.role.label, description: r.role.description } : x))
      setEditId(null)
      flash(`Updated '${role.key}'.`, true)
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function removeRole(role: DefinedRole) {
    const n = holdersOf(role)
    const who = n === 0
      ? 'Nobody currently holds it.'
      : `${n} ${n === 1 ? 'person holds' : 'people hold'} it and will lose it — the app will stop seeing '${role.key}' for them.`
    if (!confirm(`Delete the role '${role.key}'?\n\n${who}\n\nThis cannot be undone; grants are not restored if you recreate the key.`)) return
    try {
      const r = await adminApi.del<{ grants_removed: number }>(`/api/apps/${slug}/app-roles/${role.id}`)
      setRoles(prev => (prev || []).filter(x => x.id !== role.id))
      setMembers(prev => (prev || []).map(m => ({ ...m, app_roles: m.app_roles.filter(k => k !== role.key) })))
      flash(`Deleted '${role.key}' — ${r.grants_removed} grant${r.grants_removed === 1 ? '' : 's'} removed.`, true)
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function toggleGrant(member: Member, key: string) {
    const held = member.app_roles.includes(key)
    const next = held ? member.app_roles.filter(k => k !== key) : [...member.app_roles, key].sort()
    const prev = member.app_roles
    setMembers(list => (list || []).map(m => m.id === member.id ? { ...m, app_roles: next } : m))
    setSaving(s => ({ ...s, [member.id]: true }))
    try {
      const r = await adminApi.put<{ app_roles: string[] }>(`/api/apps/${slug}/app-roles/members/${member.id}`, { keys: next })
      setMembers(list => (list || []).map(m => m.id === member.id ? { ...m, app_roles: r.app_roles } : m))
    } catch (e) {
      setMembers(list => (list || []).map(m => m.id === member.id ? { ...m, app_roles: prev } : m))
      flash((e as Error).message, false)
    } finally {
      setSaving(s => { const c = { ...s }; delete c[member.id]; return c })
    }
  }

  return (
    <div className="aa-overlay" onClick={onClose}>
      <style>{CSS}</style>
      <div
        className="aa-modal"
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-label={`Access for ${name}`}
      >
        <div className="aa-hdr">
          <span className="aa-hdr-title">Access · {name}</span>
          <span className="aa-hdr-slug">{slug}</span>
          <button className="aa-close" onClick={onClose} aria-label="Close">×</button>
        </div>

        <div className="aa-body">
          {msg && <div className={'aa-msg ' + (msg.ok ? 'aa-msg-ok' : 'aa-msg-err')}>{msg.text}</div>}
          {loadError && <div className="aa-msg aa-msg-err">{loadError}</div>}

          <div className="aa-legend">
            <div className="aa-legend-col">
              <h4><span className="aa-tier">admin</span> Platform tier — AppCrane&apos;s</h4>
              <p>
                One tier per person: owner, admin or user. It decides what they can do to this app
                <em> inside AppCrane</em> — deploy it, read its env vars, delete it. Set in <strong>Users</strong>;
                shown here read-only so you can see it next to the app&apos;s own roles.
              </p>
            </div>
            <div className="aa-legend-col">
              <h4><span className="aa-key">approver</span> App roles — this app&apos;s</h4>
              <p>
                Names this app invents, as many per person as you like. AppCrane hands them to the app
                in <code>/api/me</code> and the <code>X-AppCrane-App-Roles</code> header and stops there —
                the app decides what they mean. They grant nothing in AppCrane.
              </p>
            </div>
          </div>

          <div className="aa-panel">
            <div className="aa-panel-hdr">
              <h3>Roles this app defines</h3>
              <span className="aa-panel-count">
                {roles === null ? '' : `${roles.length} of ${MAX_ROLES_PER_APP}`}
              </span>
            </div>
            <div className="aa-panel-body">
              {roles === null ? (
                <div className="aa-empty">Loading…</div>
              ) : roles.length === 0 ? (
                <div className="aa-empty">
                  <strong>This app defines no roles of its own.</strong> That is often the right answer.
                  If all your app needs to know is whether someone is an admin, read
                  the <code>X-AppCrane-Is-Admin</code> header (or <code>is_admin</code> from <code>/api/me</code>)
                  and skip this feature entirely — one less permission model to keep in sync.
                  Define roles here only when the app has its own distinctions AppCrane cannot know about,
                  like approver, auditor or reviewer.
                </div>
              ) : (
                <table className="aa-table">
                  <thead>
                    <tr>
                      <th>Key</th>
                      <th>Label</th>
                      <th>Description</th>
                      <th>Holders</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {roles.map(role => {
                      const editing = editId === role.id
                      return (
                        <tr key={role.id}>
                          <td>
                            <span
                              className="aa-key"
                              title="Immutable — this is the string the app compares against. Delete and recreate to change it."
                            >{role.key}</span>
                          </td>
                          <td>
                            {editing ? (
                              <input
                                value={editLabel} autoFocus
                                aria-label={`Label for ${role.key}`}
                                onChange={e => setEditLabel(e.target.value)}
                                style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', padding: '4px 8px', borderRadius: 5, fontSize: '.82rem', width: '100%' }}
                              />
                            ) : role.label}
                          </td>
                          <td style={{ color: 'var(--dim)', fontSize: '.79rem' }}>
                            {editing ? (
                              <input
                                value={editDesc}
                                aria-label={`Description for ${role.key}`}
                                onChange={e => setEditDesc(e.target.value)}
                                style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', padding: '4px 8px', borderRadius: 5, fontSize: '.82rem', width: '100%' }}
                              />
                            ) : (role.description || '—')}
                          </td>
                          <td style={{ whiteSpace: 'nowrap', color: 'var(--dim)', fontSize: '.79rem' }}>
                            {holdersOf(role)}
                          </td>
                          <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                            {editing ? (
                              <>
                                <button className="btn btn-xs btn-accent" onClick={() => saveEdit(role)}>Save</button>{' '}
                                <button className="btn btn-xs" onClick={() => setEditId(null)}>Cancel</button>
                              </>
                            ) : (
                              <>
                                <button
                                  className="btn btn-xs"
                                  title="Edit the label and description. The key cannot change."
                                  onClick={() => { setEditId(role.id); setEditLabel(role.label); setEditDesc(role.description || '') }}
                                >edit</button>{' '}
                                <button className="btn btn-xs btn-red" onClick={() => removeRole(role)}>delete</button>
                              </>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}

              <div className="aa-form">
                <input
                  className="mono" placeholder="key" value={newKey} aria-label="New role key"
                  onChange={e => setNewKey(e.target.value)} style={{ width: 150 }} disabled={atLimit}
                />
                <input
                  placeholder="Label (what people see)" value={newLabel} aria-label="New role label"
                  onChange={e => setNewLabel(e.target.value)} style={{ width: 200 }} disabled={atLimit}
                />
                <input
                  placeholder="Description (optional)" value={newDesc} aria-label="New role description"
                  onChange={e => setNewDesc(e.target.value)} style={{ flex: 1, minWidth: 160 }} disabled={atLimit}
                />
                <button
                  className="btn btn-xs btn-accent"
                  disabled={creating || atLimit || !keyTrimmed || !!keyError || !newLabel.trim()}
                  onClick={createRole}
                >{creating ? 'Defining…' : '+ Define role'}</button>
                <div className={'aa-hint' + (keyError ? ' aa-hint-bad' : '')}>
                  {atLimit
                    ? `This app already defines the maximum of ${MAX_ROLES_PER_APP} roles. Delete one before adding another.`
                    : keyError
                      ? keyError
                      : `The key is what the app matches on and it can never be changed. ${RESERVED_KEYS.join(', ')} are reserved by AppCrane.`}
                </div>
              </div>
            </div>
          </div>

          <div className="aa-panel">
            <div className="aa-panel-hdr">
              <h3>Members</h3>
              <span className="aa-panel-count">
                {members === null ? '' : `${members.length} assigned to this app`}
              </span>
            </div>
            <div className="aa-panel-body">
              {members === null ? (
                <div className="aa-empty">Loading…</div>
              ) : members.length === 0 ? (
                <div className="aa-empty">
                  Nobody is assigned to this app yet. Add people in <strong>Users</strong> — app roles can only
                  be granted to someone who is already a member.
                </div>
              ) : (
                <table className="aa-table">
                  <thead>
                    <tr>
                      <th>Member</th>
                      <th>Platform tier</th>
                      <th>App roles</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map(m => {
                      return (
                        <tr key={m.id}>
                          <td>
                            <div style={{ fontWeight: 500 }}>{m.name}</div>
                            {m.email && <div style={{ fontSize: '.74rem', color: 'var(--dim)' }}>{m.email}</div>}
                          </td>
                          <td>
                            <span
                              className="aa-tier"
                              title="AppCrane's own tier for this app. Read-only here — change it in Users."
                            >{m.app_role}</span>
                          </td>
                          <td>
                            {roles === null || roles.length === 0 ? (
                              <span style={{ fontSize: '.78rem', color: 'var(--dim)' }}>
                                Define a role above first.
                              </span>
                            ) : (
                              <div className="aa-chiprow">
                                {roles.map(role => {
                                  const on = m.app_roles.includes(role.key)
                                  return (
                                    <button
                                      key={role.id}
                                      type="button"
                                      className={'aa-rolechip' + (on ? ' on' : '')}
                                      aria-pressed={on}
                                      disabled={!!saving[m.id]}
                                      title={on
                                        ? `${m.name} holds '${role.key}' — click to revoke`
                                        : `Grant '${role.key}' to ${m.name}`}
                                      onClick={() => toggleGrant(m, role.key)}
                                    >{role.key}</button>
                                  )
                                })}
                                {saving[m.id] && <span style={{ fontSize: '.72rem', color: 'var(--dim)' }}>saving…</span>}
                              </div>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        <div className="aa-foot">
          <span className="aa-foot-note">
            App roles save as you click. Membership and platform tier are managed in Users.
          </span>
          <button className="btn btn-accent" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  )
}
