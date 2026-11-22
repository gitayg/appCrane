import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { AppAuditEventsTable } from './AppAuditEventsTable'
import type { AppAuditPage } from './types'

// Settings > Security, platform admins: the app audit event policy
// (/api/app-audit/settings) and every app's events (/api/app-audit-events).

interface Settings { retention_days: number; min_days: number; max_days: number; owner_streams_enabled: boolean; owner_streams_private: boolean }
const EMPTY = { app: '', action: '', actor_type: '', actor_id: '', target_type: '', target_id: '', since: '', until: '' }

export function AppAuditPlatformCard() {
  const [s, setS] = useState<Settings | null>(null)
  const [days, setDays] = useState('')
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [filters, setFilters] = useState(EMPTY)
  const [applied, setApplied] = useState(EMPTY)
  const [page, setPage] = useState<AppAuditPage | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<Settings>('/api/app-audit/settings').then(r => { setS(r); setDays(String(r.retention_days)) }).catch(() => setS(null))
  }, [])

  const query = useCallback((before?: number) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(applied)) if (v) q.set(k, k === 'since' || k === 'until' ? new Date(v).toISOString() : v)
    if (before) q.set('before', String(before))
    return q
  }, [applied])

  const load = useCallback((before?: number) => {
    adminApi.get<AppAuditPage>(`/api/app-audit-events?${query(before)}`).then(setPage).catch((e: Error) => setMsg({ text: e.message, ok: false }))
  }, [query])
  useEffect(() => { if (s) load() }, [s, load])

  async function save(patch: Partial<Settings>) {
    setBusy(true)
    try { const r = await adminApi.put<Settings>('/api/app-audit/settings', patch); setS(x => x && { ...x, ...r }); setDays(String(r.retention_days)); setMsg({ text: 'Saved.', ok: true }) } catch (e) { setMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }

  async function exportAs(format: 'csv' | 'json') {
    const q = query()
    q.set('format', format)
    const r = await fetch(`/api/app-audit-events/export?${q}`, { headers: adminApi.authHeaders() })
    if (!r.ok) { setMsg({ text: `Export failed: HTTP ${r.status}`, ok: false }); return }
    const url = URL.createObjectURL(await r.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = `app-audit-events.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (!s) return null
  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement>) => setFilters(f => ({ ...f, [k]: e.target.value }))

  return (
    <div className="card" data-testid="app-audit-platform">
      <h3 style={{ marginTop: 0 }}>App audit events</h3>
      <p style={{ fontSize: '.85rem', color: 'var(--text-dim)', marginTop: 0 }}>
        Events hosted apps write about themselves with their service token. Kept apart from AppCrane's own audit log and sealed into the audit chain.
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, alignItems: 'center', marginBottom: 8, fontSize: '.9rem' }}>
        <label>Keep for{' '}
          <input className="input" type="number" min={s.min_days} max={s.max_days} value={days} onChange={e => setDays(e.target.value)} style={{ width: 90 }} /> days{' '}
          <button className="btn btn-xs" disabled={busy || Number(days) === s.retention_days} onClick={() => save({ retention_days: Number(days) })}>Save</button>
        </label>
        <label><input type="checkbox" checked={s.owner_streams_enabled} disabled={busy} onChange={e => save({ owner_streams_enabled: e.target.checked })} /> App owners may stream their app's events to a SIEM</label>
        <label><input type="checkbox" checked={s.owner_streams_private} disabled={busy || !s.owner_streams_enabled} onChange={e => save({ owner_streams_private: e.target.checked })} /> Owner streams may use the SIEM private allowlist</label>
      </div>
      {msg && <div style={{ fontSize: '.85rem', color: msg.ok ? 'var(--green)' : 'var(--red)', marginBottom: 6 }}>{msg.text}</div>}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
        <input className="input" placeholder="app slug" value={filters.app} onChange={set('app')} />
        <input className="input" placeholder="action or prefix." value={filters.action} onChange={set('action')} />
        <input className="input" placeholder="actor type" value={filters.actor_type} onChange={set('actor_type')} />
        <input className="input" placeholder="actor id" value={filters.actor_id} onChange={set('actor_id')} />
        <input className="input" placeholder="target type" value={filters.target_type} onChange={set('target_type')} />
        <input className="input" placeholder="target id" value={filters.target_id} onChange={set('target_id')} />
        <input className="input" type="datetime-local" value={filters.since} onChange={set('since')} title="from" />
        <input className="input" type="datetime-local" value={filters.until} onChange={set('until')} title="to" />
        <button className="btn btn-sm" onClick={() => setApplied(filters)}>Filter</button>
        <button className="btn btn-sm" onClick={() => exportAs('csv')}>CSV</button>
        <button className="btn btn-sm" onClick={() => exportAs('json')}>JSON</button>
      </div>
      {page && <AppAuditEventsTable events={page.events} showApp />}
      {page?.next_before && <button className="btn btn-xs" style={{ marginTop: 6 }} onClick={() => load(page.next_before!)}>Older</button>}
    </div>
  )
}
