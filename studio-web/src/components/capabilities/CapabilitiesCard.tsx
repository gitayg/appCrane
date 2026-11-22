import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { personLabel, scopeText, type AppCapabilities, type AppCapability } from './types'

interface Props {
  slug: string
  reload?: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

// Sensitive capabilities on this app: which need platform admin approval, what
// is granted (and until when), and a request form for owners and app admins.
// The server decides everything; this card only shows it and files requests.
export function CapabilitiesCard({ slug, reload = 0, onMsg }: Props) {
  const [data, setData] = useState<AppCapabilities | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [scope, setScope] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const base = `/api/apps/${encodeURIComponent(slug)}`

  const load = useCallback(() => {
    adminApi.get<AppCapabilities>(`${base}/capabilities`).then(setData).catch(() => setData(null))
  }, [base])
  useEffect(() => { load() }, [load, reload])

  function startRequest(id: string, cap: AppCapability) {
    setOpen(id)
    setScope(JSON.stringify(cap.example_scope))
    setReason('')
  }

  async function submit(id: string) {
    let parsed: unknown
    try { parsed = scope.trim() ? JSON.parse(scope) : {} } catch { onMsg({ text: 'Scope must be JSON, for example {"paths":["/webhooks"]}', ok: false }); return }
    setBusy(true)
    try {
      await adminApi.post(`${base}/capability-requests`, { capability: id, scope: parsed, reason })
      onMsg({ text: 'Request sent to the platform admins.', ok: true })
      setOpen(null)
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function cancel(requestId: number) {
    setBusy(true)
    try {
      await adminApi.post(`${base}/capability-requests/${requestId}/cancel`)
      onMsg({ text: 'Request cancelled.', ok: true })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!data) return null
  const entries = Object.entries(data.capabilities)
  const annex = data.external.ai_annex_iii

  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 6 }}>Capabilities</h3>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 10 }}>
        Sensitive settings a platform admin approves first. A grant covers exactly its scope; anything more needs a new request.
      </div>
      <table style={{ width: '100%', fontSize: '.85rem' }}>
        <tbody>
          {entries.map(([id, cap]) => (
            <tr key={id} style={{ borderTop: '1px solid var(--border)', verticalAlign: 'top' }}>
              <td style={{ padding: 6, width: '30%' }} title={cap.description}>
                <strong>{cap.label}</strong>
                {!cap.approval_required && <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>No approval needed: {cap.when_off}</div>}
              </td>
              <td style={{ padding: 6 }}>
                {cap.grants.length === 0 && !cap.pending && cap.approval_required && <span style={{ color: 'var(--dim)' }}>Not granted</span>}
                {cap.grants.map(g => (
                  <div key={g.id}>
                    <span style={{ color: 'var(--green)' }}>Granted</span> {scopeText(g.scope)}
                    {g.expires_at ? `, until ${serverDate(g.expires_at).toLocaleDateString()}` : ''}
                    {g.unreviewed && <span style={{ color: 'var(--orange)' }}> (in use before approvals; unreviewed)</span>}
                    {g.origin === 'implicit' && <span style={{ color: 'var(--dim)' }}> (set by {personLabel(g.decided_by)})</span>}
                  </div>
                ))}
                {cap.pending && (
                  <div>
                    <span style={{ color: 'var(--orange)' }}>Waiting for a platform admin</span>: {scopeText(cap.pending.requested_scope)}
                    {data.can_request && (
                      <> <button className="btn btn-xs" disabled={busy} onClick={() => cancel(cap.pending!.id)}>Cancel</button></>
                    )}
                  </div>
                )}
                {cap.history.slice(0, 1).map(h => (
                  <div key={h.id} style={{ fontSize: '.75rem', color: 'var(--dim)' }}>
                    Last: #{h.id} {h.status}{h.expiry_action === 'flagged' ? ' (left in place)' : ''}{h.decision_note ? `: ${h.decision_note}` : ''}
                  </div>
                ))}
                {open === id && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                    <input className="input" value={scope} onChange={e => setScope(e.target.value)} disabled={busy} aria-label="Scope (JSON)" />
                    <input className="input" placeholder="Why the app needs it" value={reason} maxLength={1000} onChange={e => setReason(e.target.value)} disabled={busy} />
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-xs" disabled={busy || !reason.trim()} onClick={() => submit(id)}>Send request</button>
                      <button className="btn btn-xs" disabled={busy} onClick={() => setOpen(null)}>Close</button>
                    </div>
                  </div>
                )}
              </td>
              <td style={{ padding: 6, width: 90, textAlign: 'right' }}>
                {data.can_request && cap.approval_required && !cap.pending && open !== id && (
                  <button className="btn btn-xs" disabled={busy} onClick={() => startRequest(id, cap)}>Request</button>
                )}
              </td>
            </tr>
          ))}
          {annex && (
            <tr style={{ borderTop: '1px solid var(--border)' }}>
              <td style={{ padding: 6 }}><strong>{annex.label}</strong></td>
              <td style={{ padding: 6 }} colSpan={2}>
                {annex.in_use ? `In use (${annex.category || 'category not set'}). ` : ''}
                <span style={{ color: 'var(--dim)' }}>{annex.description}</span>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
