import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { AppAccessModal } from '../AppAccessModal'
import { AccessRulesCard } from '../AccessRulesCard'
import { WidgetScopesCard } from '../WidgetScopesCard'
import { errText, relTime } from './format'
import type { ManageCtx } from './types'

type Member = { id: number; name: string; email: string | null; role: string; app_role: 'none' | 'user' | 'admin' | 'owner' }
type Req = { id: number; app_slug: string; user_name?: string; message: string; status?: string; created_at: string }

/** Who can use the app, in one list: members and their role, the app's own roles, visibility, requests, path rules. */
export function AccessTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, app, detail } = ctx
  const [members, setMembers] = useState<Member[] | null>(null)
  const [membersErr, setMembersErr] = useState('')
  const [filter, setFilter] = useState('')
  const [saving, setSaving] = useState<Record<number, 'saving' | 'saved' | 'error'>>({})
  const [roles, setRoles] = useState(false)
  const [reqs, setReqs] = useState<Req[] | null | undefined>(undefined)
  const [showSandbox, setShowSandbox] = useState(app.show_sandbox !== false)

  useEffect(() => {
    adminApi.get<{ users: Member[] }>(`/api/apps/${slug}/identity/users`)
      .then(r => { setMembers(r.users || []); setMembersErr('') })
      .catch(e => { setMembers([]); setMembersErr(errText(e)) })
    // Plain fetch, not adminApi: /owned accepts only a signed-in session, and an
    // API-key session's 401 there must not read as "signed out".
    fetch('/api/enhancements/owned', { headers: adminApi.authHeaders() })
      .then(r => (r.ok ? r.json() as Promise<{ requests: Req[] }> : Promise.reject(new Error(String(r.status)))))
      .then(r => setReqs((r.requests || []).filter(x => x.app_slug === slug && x.status !== 'done' && /^Access request for app/.test(x.message))))
      .catch(() => setReqs(null))
  }, [slug, ctx.reload])

  async function setRole(id: number, next: Member['app_role']) {
    const prev = members?.find(u => u.id === id)?.app_role ?? 'none'
    setMembers(m => m && m.map(u => u.id === id ? { ...u, app_role: next } : u))
    setSaving(s => ({ ...s, [id]: 'saving' }))
    try {
      await adminApi.put(`/api/apps/${slug}/roles`, { user_id: id, app_role: next })
      setSaving(s => ({ ...s, [id]: 'saved' }))
    } catch (e) {
      setMembers(m => m && m.map(u => u.id === id ? { ...u, app_role: prev } : u))
      setSaving(s => ({ ...s, [id]: 'error' }))
      ctx.onMsg({ text: 'Save failed: ' + errText(e), ok: false })
    }
  }

  async function setVisibility(v: string) {
    try { await adminApi.put(`/api/apps/${slug}`, { visibility: v }); ctx.patchApp({ visibility: v }) }
    catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function toggleSandbox(next: boolean) {
    try {
      await adminApi.put(`/api/apps/${slug}`, { show_sandbox: next })
      setShowSandbox(next); ctx.patchApp({ show_sandbox: next })
      ctx.onMsg({ text: next ? 'Sandbox is shown to users again.' : 'Sandbox is now hidden from users.', ok: true })
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  const q = filter.trim().toLowerCase()
  const list = (members || [])
    .filter(u => !q || (u.name || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))
    .sort((a, b) => (a.app_role === 'none' ? 1 : 0) - (b.app_role === 'none' ? 1 : 0) || (a.name || '').localeCompare(b.name || ''))

  return (
    <div className="am2-cards">
      <div className="am-card">
        <h3 style={{ marginBottom: 10 }}>Who sees this app</h3>
        <div style={{ display: 'grid', gap: 10 }}>
          <label className="am2-row">Visibility
            <select className="am2-input" value={app.visibility || 'hidden'} onChange={e => setVisibility(e.target.value)} aria-label="Visibility">
              <option value="hidden">hidden</option>
              <option value="private">private</option>
              <option value="public">public</option>
            </select>
          </label>
          {detail?.app?.can_change_show_sandbox && (
            <label className="am2-row" title="Owner or platform admin only">
              <input type="checkbox" checked={showSandbox} onChange={e => toggleSandbox(e.target.checked)} /> Show Sandbox to users
              <span className="am2-small am2-dim">{showSandbox ? 'Members and viewers can pick Sandbox in the launcher and the app frame.' : "Users won't see Sandbox in the launcher; the sandbox URL still works for anyone with access. Owners and admins still see it."}</span>
            </label>
          )}
        </div>
      </div>

      <div className="am-card">
        <div className="am2-row" style={{ marginBottom: 10 }}>
          <h3 style={{ margin: 0, flex: 1 }}>Members</h3>
          <button className="btn btn-sm" onClick={() => setRoles(true)} title="Roles this app defines for itself, and who holds them">App roles…</button>
        </div>
        {membersErr ? <div className="am2-dim am2-small">{membersErr}</div> : members === null ? <div className="am2-dim">Loading…</div> : (
          <>
            <input className="am2-input" placeholder="Search by name or email" value={filter} onChange={e => setFilter(e.target.value)} style={{ width: '100%', marginBottom: 8 }} aria-label="Search members" />
            <div className="am2-table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
              <table className="am2-table" style={{ minWidth: 0 }} aria-label="Members">
                <thead><tr><th scope="col">User</th><th scope="col" style={{ width: 150 }}>Role on this app</th></tr></thead>
                <tbody>
                  {list.map(u => (
                    <tr key={u.id}>
                      <td>
                        <div className="am2-row">{u.name}{u.role === 'platform_admin' && <span className="am2-pill warn">platform admin</span>}</div>
                        {u.email && <div className="am2-small am2-dim">{u.email}</div>}
                      </td>
                      <td>
                        <span className="am2-row">
                          <select className="am2-input" value={u.app_role} disabled={saving[u.id] === 'saving'} onChange={e => setRole(u.id, e.target.value as Member['app_role'])} aria-label={`Role for ${u.name}`}
                            title={u.role === 'platform_admin' ? 'Platform admins can manage every app whatever is set here. Set owner to be listed, and e-mailed, as an owner of this app.' : undefined}>
                            <option value="none">none</option>
                            <option value="user">user</option>
                            <option value="admin">admin</option>
                            <option value="owner">owner</option>
                          </select>
                          {saving[u.id] === 'saved' && <span style={{ color: 'var(--green)' }}>✓</span>}
                          {saving[u.id] === 'error' && <span style={{ color: 'var(--red)' }}>✗</span>}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      <div className="am-card">
        <h3 style={{ marginBottom: 8 }}>Pending access requests</h3>
        {reqs === undefined ? <div className="am2-dim">Loading…</div> : reqs === null ? <div className="am2-dim am2-small">Could not list them here. See <a href="/requests">Requests</a>.</div> : reqs.length === 0 ? <div className="am2-dim am2-small">None.</div> : (
          <ul style={{ listStyle: 'none', display: 'grid', gap: 6 }}>
            {reqs.map(r => (
              <li key={r.id} className="am2-row">
                <span>{r.user_name || 'Someone'}</span>
                <span className="am2-dim am2-small">{relTime(r.created_at)}</span>
                <a className="btn btn-xs" href={`/requests/${r.id}`}>Review</a>
              </li>
            ))}
          </ul>
        )}
      </div>

      <AccessRulesCard slug={slug} env="production" reload={ctx.reload} onMsg={ctx.onMsg} />
      <AccessRulesCard slug={slug} env="sandbox" reload={ctx.reload} onMsg={ctx.onMsg} />
      <WidgetScopesCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
      {roles && <AppAccessModal slug={slug} name={app.name} onClose={() => setRoles(false)} />}
    </div>
  )
}
