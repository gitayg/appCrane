import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { BlueprintEditor } from './BlueprintEditor'
import type { Blueprint, BlueprintAdminList, ScopeGroup } from './blueprintTypes'

// Settings > Security (platform admin): named scope sets for agent credentials.
// Backed by /api/oauth/admin/blueprints (server/routes/oauthAdminBlueprints.js).
export function BlueprintsCard() {
  const [list, setList] = useState<Blueprint[] | null>(null)
  const [groups, setGroups] = useState<ScopeGroup[]>([])
  const [editing, setEditing] = useState<Blueprint | 'new' | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<BlueprintAdminList>('/api/oauth/admin/blueprints')
      .then(r => { setList(r.blueprints); setGroups(r.scope_groups) })
      .catch(e => setMsg({ text: (e as Error).message, ok: false }))
  }, [])
  useEffect(load, [load])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    setMsg(null)
    try { await fn(); setMsg({ text: ok, ok: true }); setEditing(null); load() } catch (e) { setMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }
  const labelOf = (scope: string) => groups.find(g => g.scope === scope)?.label ?? scope

  const remove = (b: Blueprint) => {
    if (!window.confirm(`Delete the ${b.name} blueprint?\n\nEvery key and connection that uses it loses ALL tools at once. They do not fall back to full access; people have to issue or approve them again.`)) return
    run(() => adminApi.del(`/api/oauth/admin/blueprints/${b.id}`), `Deleted ${b.name}`)
  }

  return (
    <div className="setting-card">
      <h3>MCP scope blueprints</h3>
      <p style={{ marginBottom: 8 }}>
        A blueprint is a named set of things an agent may do, optionally limited to some apps. Put one on a personal MCP
        key, pick one when approving a connection, or pin one to a client below. The agent still never gets more than the
        person's own role allows. Keys and connections without a blueprint keep working as before.
      </p>
      {msg && <div role={msg.ok ? 'status' : 'alert'} style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.8rem', marginBottom: 8 }}>{msg.text}</div>}
      {list && (
        <table style={{ width: '100%', fontSize: '.82rem', borderCollapse: 'collapse' }}>
          <tbody>
            {list.map(b => (
              <tr key={b.id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: 6, verticalAlign: 'top' }}><strong>{b.name}</strong>{b.builtin && <span style={{ color: 'var(--dim)' }}> (built-in)</span>}
                  <div style={{ color: 'var(--dim)' }}>{b.description}</div></td>
                <td style={{ padding: 6, verticalAlign: 'top' }}>{b.scopes.map(labelOf).join(', ')}</td>
                <td style={{ padding: 6, verticalAlign: 'top' }}>{b.apps ? `Only: ${b.apps.join(', ') || 'no apps'}` : 'All their apps'}</td>
                <td style={{ padding: 6, textAlign: 'right', whiteSpace: 'nowrap', verticalAlign: 'top' }}>
                  <button type="button" className="btn btn-xs" onClick={() => setEditing(b)} disabled={busy}>Edit</button>{' '}
                  {!b.builtin && <button type="button" className="btn btn-xs btn-danger" onClick={() => remove(b)} disabled={busy}>Delete</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {editing ? (
        <BlueprintEditor
          key={editing === 'new' ? 'new' : editing.id}
          groups={groups}
          initial={editing === 'new' ? null : editing}
          busy={busy}
          onCancel={() => setEditing(null)}
          onSave={body => editing === 'new'
            ? run(() => adminApi.post('/api/oauth/admin/blueprints', body), 'Blueprint created')
            : run(() => adminApi.patch(`/api/oauth/admin/blueprints/${editing.id}`, body), 'Blueprint saved; it applies to keys and connections already using it')}
        />
      ) : (
        <button type="button" className="btn btn-xs" style={{ marginTop: 8 }} onClick={() => setEditing('new')} disabled={busy}>+ New blueprint</button>
      )}
    </div>
  )
}
