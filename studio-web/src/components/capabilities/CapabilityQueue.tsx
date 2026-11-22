import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { personLabel, scopeText, type CapabilityPolicy, type CapabilityRequest } from './types'

type View = 'pending' | 'unreviewed' | 'active' | 'flagged'

const VIEWS: { id: View; label: string; hint: string }[] = [
  { id: 'pending', label: 'Pending', hint: 'Requests from owners, app admins and agents. Approve (optionally narrowing the scope and setting an expiry) or deny.' },
  { id: 'unreviewed', label: 'Unreviewed', hint: 'Capabilities apps already used before approvals existed. Nothing changed for them; confirm to keep, revoke to end.' },
  { id: 'active', label: 'Active grants', hint: 'Every grant in force. Revoking a sign-in bypass, headless, public visibility, e-mail or LLM gateway grant removes the setting; a database, port or secret store grant is only flagged.' },
  { id: 'flagged', label: 'Expired in place', hint: 'Grants that expired on a capability AppCrane does not remove by itself (database, port, secret store). Decide what to do with each.' },
]

// Platform admins: the capability approval queue and the per-capability policy.
// Decisions need a dashboard session; the server refuses them from an API key,
// from an agent identity and from the person who asked.
export function CapabilityQueue() {
  const [view, setView] = useState<View>('pending')
  const [rows, setRows] = useState<CapabilityRequest[] | null>(null)
  const [policy, setPolicy] = useState<Record<string, CapabilityPolicy> | null>(null)
  const [edit, setEdit] = useState<Record<number, { scope: string; days: string; note: string }>>({})
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<{ requests: CapabilityRequest[] }>(`/api/capability-requests?status=${view}`)
      .then(d => setRows(d.requests)).catch(e => setMsg({ text: (e as Error).message, ok: false }))
    adminApi.get<{ policy: Record<string, CapabilityPolicy> }>('/api/capability-approvals/policy')
      .then(d => setPolicy(d.policy)).catch(() => setPolicy(null))
  }, [view])
  useEffect(() => { load() }, [load])

  const field = (id: number) => edit[id] || { scope: '', days: '', note: '' }
  const setField = (id: number, k: 'scope' | 'days' | 'note', v: string) => setEdit(e => ({ ...e, [id]: { ...field(id), [k]: v } }))

  async function act(r: CapabilityRequest, action: 'approve' | 'deny' | 'confirm' | 'revoke') {
    const f = field(r.id)
    const body: Record<string, unknown> = {}
    if (f.note.trim()) body.note = f.note.trim()
    if ((action === 'approve' || action === 'confirm') && f.days.trim()) body.expires_in_days = Number(f.days)
    if (action === 'approve' && f.scope.trim()) {
      try { body.scope = JSON.parse(f.scope) } catch { setMsg({ text: 'Narrowed scope must be JSON', ok: false }); return }
    }
    setBusy(true)
    try {
      const out = await adminApi.post<{ effect?: string }>(`/api/capability-requests/${r.id}/${action}`, body)
      setMsg({ text: `#${r.id} ${action === 'deny' ? 'denied' : `${action}d`}${out.effect ? `: ${out.effect}` : ''}.`, ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function togglePolicy(id: string, on: boolean) {
    setBusy(true)
    try {
      const out = await adminApi.put<{ policy: Record<string, CapabilityPolicy> }>('/api/capability-approvals/policy', { [id]: { approval_required: on } })
      setPolicy(out.policy)
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  const hint = VIEWS.find(v => v.id === view)?.hint

  return (
    <>
      {msg && <div style={{ marginBottom: 10, color: msg.ok ? 'var(--green)' : 'var(--red)' }}>{msg.text}</div>}
      <div className="am-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
          {VIEWS.map(v => (
            <button key={v.id} className={`btn btn-xs${view === v.id ? ' btn-primary' : ''}`} onClick={() => setView(v.id)}>{v.label}</button>
          ))}
        </div>
        <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 8 }}>{hint}</div>
        {!rows ? null : rows.length === 0 ? <div style={{ color: 'var(--dim)' }}>Nothing here.</div> : (
          <table style={{ width: '100%', fontSize: '.85rem' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}><th>App</th><th>Capability</th><th>Scope</th><th>Who and why</th><th /></tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id} style={{ borderTop: '1px solid var(--border)', verticalAlign: 'top' }}>
                  <td style={{ padding: 6 }}>{r.app ? <a href={`/app?slug=${encodeURIComponent(r.app.slug)}`}>{r.app.name || r.app.slug}</a> : '(deleted)'}</td>
                  <td style={{ padding: 6 }}>#{r.id} {r.label}</td>
                  <td style={{ padding: 6 }}>
                    {scopeText(view === 'pending' ? r.requested_scope : r.scope)}
                    {r.expires_at && <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>until {serverDate(r.expires_at).toLocaleString()}</div>}
                  </td>
                  <td style={{ padding: 6 }}>
                    {r.origin === 'grandfathered' ? 'In use before approvals' : `${personLabel(r.requested_by)}${r.requested_by_kind === 'agent' ? ' (agent)' : ''} via ${r.requested_via || 'api'}`}
                    {r.reason && <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>{r.reason}</div>}
                  </td>
                  <td style={{ padding: 6, minWidth: 220 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {view === 'pending' && (
                        <input className="input" placeholder="Narrow scope (JSON, optional)" value={field(r.id).scope} onChange={e => setField(r.id, 'scope', e.target.value)} disabled={busy} />
                      )}
                      {(view === 'pending' || view === 'unreviewed') && (
                        <input className="input" placeholder="Expires in days (optional)" value={field(r.id).days} onChange={e => setField(r.id, 'days', e.target.value)} disabled={busy} />
                      )}
                      <input className="input" placeholder="Note (optional)" value={field(r.id).note} onChange={e => setField(r.id, 'note', e.target.value)} disabled={busy} />
                      <div style={{ display: 'flex', gap: 4 }}>
                        {view === 'pending' && <>
                          <button className="btn btn-xs btn-primary" disabled={busy} onClick={() => act(r, 'approve')}>Approve</button>
                          <button className="btn btn-xs" disabled={busy} onClick={() => act(r, 'deny')}>Deny</button>
                        </>}
                        {view === 'unreviewed' && <button className="btn btn-xs btn-primary" disabled={busy} onClick={() => act(r, 'confirm')}>Confirm</button>}
                        {(view === 'unreviewed' || view === 'active') && <button className="btn btn-xs" disabled={busy} onClick={() => act(r, 'revoke')}>Revoke</button>}
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {policy && (
        <div className="am-card">
          <h3 style={{ marginBottom: 6 }}>Which capabilities need approval</h3>
          <table style={{ width: '100%', fontSize: '.85rem' }}>
            <tbody>
              {Object.entries(policy).map(([id, p]) => (
                <tr key={id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: 6 }}>
                    <label>
                      <input type="checkbox" checked={p.approval_required} disabled={busy || p.always_required} title={p.always_required ? 'Always needs an approved grant' : undefined} onChange={e => togglePolicy(id, e.target.checked)} />
                      {' '}<strong>{p.label}</strong>
                    </label>
                    <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>{p.description} When off: {p.when_off}. On expiry: {p.on_expiry === 'revoke' ? 'removed' : 'flagged, left in place'}.</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
