import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { SiemOptions } from '../siem/siemTypes'
import { OwnerStreamForm } from './OwnerStreamForm'
import type { AppAuditStream } from './types'

// The app's own audit streams (/api/apps/:slug/audit-streams). Owner or
// platform admin; the server checks the destination is a public address.

interface Props { slug: string; onMsg: (m: { text: string; ok: boolean }) => void }
interface StreamList { streams: AppAuditStream[]; policy: { owner_streams_enabled: boolean }; options: SiemOptions }

export function AppAuditStreams({ slug, onMsg }: Props) {
  const base = `/api/apps/${encodeURIComponent(slug)}/audit-streams`
  const [data, setData] = useState<StreamList | null>(null)
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => { adminApi.get<StreamList>(base).then(setData).catch(() => setData(null)) }, [base])
  useEffect(() => { load() }, [load])

  async function run(fn: () => Promise<unknown>, ok: string) {
    setBusy(true)
    try { await fn(); onMsg({ text: ok, ok: true }); load() } catch (e) { onMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }

  async function test(id: number) {
    const r = await adminApi.post<{ ok: boolean; error?: string }>(`${base}/${id}/test`).catch((e: Error) => ({ ok: false, error: e.message }))
    onMsg({ text: r.ok ? 'Test event delivered.' : `Test failed: ${r.error}`, ok: r.ok })
  }

  if (!data) return null
  const disabled = !data.policy.owner_streams_enabled
  const label = (s: AppAuditStream) => s.type === 'https' ? (data.options.presets[s.preset]?.label || s.preset) : s.type === 's3' ? 'S3 export' : 'Syslog over TLS'

  return (
    <div style={{ marginTop: 14 }}>
      <h4 style={{ margin: '0 0 6px' }}>Streams to your SIEM</h4>
      {disabled && <div style={{ fontSize: '.85rem', color: 'var(--yellow, #f59e0b)' }}>A platform admin has turned app audit streams off; nothing is delivered.</div>}
      {data.streams.length === 0 && !disabled && <div style={{ fontSize: '.85rem', color: 'var(--text-dim)' }}>No streams.</div>}
      {data.streams.map(s => (
        <div key={s.id} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', fontSize: '.85rem', padding: '4px 0' }}>
          <strong>{s.name}</strong>
          <span style={{ color: 'var(--text-dim)' }}>{label(s)} - {s.delivered_count} sent{s.filters.actions.length ? ` - ${s.filters.actions.join(', ')}` : ''}</span>
          {s.last_error && <span style={{ color: 'var(--red)' }}>{s.last_error}</span>}
          <button className="btn btn-xs" disabled={busy || disabled} onClick={() => test(s.id)}>Test</button>
          <button className="btn btn-xs" disabled={busy} onClick={() => run(() => adminApi.del(`${base}/${s.id}`), 'Stream removed.')}>Remove</button>
        </div>
      ))}
      {!disabled && !adding && <button className="btn btn-sm" style={{ marginTop: 6 }} onClick={() => setAdding(true)}>Add stream</button>}
      {adding && <OwnerStreamForm base={base} options={data.options}
        onDone={(saved) => { setAdding(false); if (saved) { onMsg({ text: 'Stream added.', ok: true }); load() } }} />}
    </div>
  )
}
