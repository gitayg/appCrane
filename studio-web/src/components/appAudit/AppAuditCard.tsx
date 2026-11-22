import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { AppAuditStreams } from './AppAuditStreams'
import { AppAuditEventsTable } from './AppAuditEventsTable'
import type { AppAuditConfig, AppAuditPage } from './types'

// Audit events the app itself wrote (/api/apps/:slug/audit-events). Shown to
// whoever may see the app's audit trail; hidden for everyone else (the config
// call is refused). Every row is labelled as reported by the app, and an actor
// AppCrane could not vouch for is marked "as reported".

interface Props { slug: string; reload?: number; onMsg: (m: { text: string; ok: boolean }) => void }

export function AppAuditCard({ slug, reload = 0, onMsg }: Props) {
  const base = `/api/apps/${encodeURIComponent(slug)}/audit-events`
  const [cfg, setCfg] = useState<AppAuditConfig | null>(null)
  const [page, setPage] = useState<AppAuditPage | null>(null)
  const [filters, setFilters] = useState({ action: '', actor_id: '', target_type: '', target_id: '', since: '', until: '' })
  const [applied, setApplied] = useState(filters)
  const [newType, setNewType] = useState('')
  const [busy, setBusy] = useState(false)

  const query = useCallback((before?: number) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(applied)) if (v) q.set(k, k === 'since' || k === 'until' ? new Date(v).toISOString() : v)
    if (before) q.set('before', String(before))
    return q
  }, [applied])

  const loadEvents = useCallback((before?: number) => {
    adminApi.get<AppAuditPage>(`${base}?${query(before)}`).then(setPage).catch((e: Error) => onMsg({ text: e.message, ok: false }))
  }, [base, query, onMsg])

  const loadCfg = useCallback(() => {
    adminApi.get<AppAuditConfig>(`${base}/config`).then(setCfg).catch(() => setCfg(null))
  }, [base])

  useEffect(() => { loadCfg() }, [loadCfg, reload])
  useEffect(() => { if (cfg) loadEvents() }, [cfg, loadEvents])

  async function exportAs(format: 'csv' | 'json') {
    const q = query()
    q.set('format', format)
    const r = await fetch(`${base}/export?${q}`, { headers: adminApi.authHeaders() })
    if (!r.ok) { onMsg({ text: `Export failed: HTTP ${r.status}`, ok: false }); return }
    const url = URL.createObjectURL(await r.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = `${slug}-audit-events.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function addType() {
    setBusy(true)
    try { await adminApi.post(`${base}/types`, { action: newType.trim() }); setNewType(''); loadCfg() } catch (e) { onMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }

  if (!cfg) return null
  const set = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLInputElement>) => setFilters(f => ({ ...f, [k]: e.target.value }))

  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 4 }}>Audit events from this app</h3>
      <div style={{ fontSize: '.8rem', color: 'var(--text-dim)', marginBottom: 8 }}>
        Written by the app's server with its service token, sealed into AppCrane's tamper-evident audit chain, kept {cfg.retention_days} days.
        These are not AppCrane's own records of the app.
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
        <input className="input" placeholder="action or prefix." value={filters.action} onChange={set('action')} />
        <input className="input" placeholder="actor id" value={filters.actor_id} onChange={set('actor_id')} />
        <input className="input" placeholder="target type" value={filters.target_type} onChange={set('target_type')} />
        <input className="input" placeholder="target id" value={filters.target_id} onChange={set('target_id')} />
        <input className="input" type="datetime-local" value={filters.since} onChange={set('since')} title="from" />
        <input className="input" type="datetime-local" value={filters.until} onChange={set('until')} title="to" />
        <button className="btn btn-sm" onClick={() => setApplied(filters)}>Filter</button>
        <button className="btn btn-sm" onClick={() => exportAs('csv')}>CSV</button>
        <button className="btn btn-sm" onClick={() => exportAs('json')}>JSON</button>
      </div>

      {page && <AppAuditEventsTable events={page.events} />}
      {page?.next_before && <button className="btn btn-xs" style={{ marginTop: 6 }} onClick={() => loadEvents(page.next_before!)}>Older</button>}

      <h4 style={{ margin: '14px 0 6px' }}>Event types</h4>
      <div style={{ fontSize: '.85rem' }}>
        {cfg.types.length ? cfg.types.map(t => t.action).join(', ') : 'None registered: the app cannot write events yet.'}
      </div>
      {cfg.can_manage_types && (
        <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
          <input className="input" placeholder="invoice.paid" value={newType} onChange={e => setNewType(e.target.value)} disabled={busy} />
          <button className="btn btn-sm" disabled={busy || !newType.trim()} onClick={addType}>Register</button>
        </div>
      )}
      {cfg.can_manage_streams && <AppAuditStreams slug={slug} onMsg={onMsg} />}
    </div>
  )
}
