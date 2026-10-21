import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { SinkForm } from './SinkForm'
import type { Sink, SiemList } from './siemTypes'

function describe(s: Sink): string {
  const c = s.config
  if (s.type === 'syslog') return `syslog ${c.transport === 'udp' ? 'UDP' : 'TLS'} ${c.host}:${c.port} (${s.format.toUpperCase()})`
  if (s.type === 's3') return `S3 export s3://${c.bucket}/${c.prefix || ''}`
  return `${s.preset} ${c.url || c.dce_url || c.site || ''} (${s.format.toUpperCase()})`
}

function status(s: Sink): { label: string; color: string } {
  if (!s.enabled) return { label: 'disabled', color: 'var(--dim)' }
  if (s.health.problem) return { label: 'failing', color: 'var(--danger, #c33)' }
  if (s.health.failing_since) return { label: 'retrying', color: 'var(--warning, #c90)' }
  return { label: 'ok', color: 'var(--success, #2a2)' }
}

export function SiemSinks() {
  const [data, setData] = useState<SiemList | null>(null)
  const [editing, setEditing] = useState<Sink | 'new' | null>(null)
  const [allow, setAllow] = useState('')
  const [msg, setMsg] = useState<Record<number | string, string>>({})

  const load = useCallback(() => {
    adminApi.get<SiemList>('/api/settings/siem').then(d => { setData(d); setAllow(d.private_allowlist.join('\n')) }).catch(() => {})
  }, [])
  useEffect(() => { load() }, [load])
  useEffect(() => { const t = setInterval(load, 15000); return () => clearInterval(t) }, [load])

  if (!data) return null
  const note = (k: number | string, m: string) => setMsg(x => ({ ...x, [k]: m }))
  const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))

  const test = (s: Sink) => {
    note(s.id, 'Sending test event...')
    adminApi.post<{ ok: boolean; error?: string; event_id?: string }>(`/api/settings/siem/${s.id}/test`)
      .then(r => note(s.id, r.ok ? `Test event accepted (${r.event_id})` : `Test failed: ${r.error}`))
      .catch(e => note(s.id, errText(e)))
  }
  const flush = (s: Sink) => {
    adminApi.post<{ ok: boolean; delivered?: number; error?: string }>(`/api/settings/siem/${s.id}/flush`)
      .then(r => { note(s.id, r.ok ? `Delivered ${r.delivered ?? 0} event(s)` : `Delivery failed: ${r.error}`); load() })
      .catch(e => note(s.id, errText(e)))
  }
  const remove = (s: Sink) => {
    if (!window.confirm(`Delete the SIEM destination "${s.name}"? Its cursor is lost.`)) return
    adminApi.del(`/api/settings/siem/${s.id}`).then(load).catch(e => note(s.id, errText(e)))
  }
  const saveAllow = () => {
    adminApi.put<{ private_allowlist: string[] }>('/api/settings/siem/network', { private_allowlist: allow.split(/[\s,]+/).filter(Boolean) })
      .then(r => { setAllow(r.private_allowlist.join('\n')); note('net', 'Saved') })
      .catch(e => note('net', errText(e)))
  }

  return (
    <div className="card">
      <h3>SIEM and log streaming</h3>
      <p style={{ color: 'var(--dim)', fontSize: '.82rem', margin: '4px 0 10px' }}>
        Streams the event store (sign-ins, secret reveals, audit, deploys, scans, alerts) to your SIEM, at least once,
        each event with a stable <code>event.id</code> to dedupe on. Credentials are encrypted and never shown again.
      </p>
      {data.sinks.length === 0 && <p style={{ color: 'var(--dim)' }}>No destinations yet.</p>}
      {data.sinks.map(s => {
        const st = status(s)
        return (
          <div key={s.id} style={{ borderTop: '1px solid var(--border)', padding: '8px 0' }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <strong>{s.name}</strong>
              <span className="badge" style={{ color: st.color }}>{st.label}</span>
              <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>{describe(s)}</span>
              {s.tls_skip_verify && <span className="badge" style={{ color: 'var(--danger, #c33)' }}>TLS not verified</span>}
            </div>
            <div style={{ fontSize: '.8rem', color: 'var(--dim)', margin: '4px 0' }}>
              Lag {String(s.health.lag_events)} event(s), {s.health.lag_seconds}s
              {' · '}delivered {s.delivered_count}
              {' · '}last success {s.health.last_success_at ?? 'never'}
              {s.health.last_error && <> · <span style={{ color: 'var(--danger, #c33)' }}>last error: {s.health.last_error}</span></>}
            </div>
            <button className="btn" onClick={() => test(s)}>Send test event</button>{' '}
            <button className="btn" onClick={() => flush(s)}>Deliver now</button>{' '}
            <button className="btn" onClick={() => setEditing(s)}>Edit</button>{' '}
            <button className="btn" onClick={() => remove(s)}>Delete</button>
            {msg[s.id] && <span style={{ marginLeft: 8, fontSize: '.8rem' }}>{msg[s.id]}</span>}
          </div>
        )
      })}
      {editing
        ? <SinkForm key={editing === 'new' ? 'new' : editing.id} sink={editing === 'new' ? null : editing} options={data.options}
            onDone={() => { setEditing(null); load() }} />
        : <button className="btn" style={{ marginTop: 8 }} onClick={() => setEditing('new')}>+ Add destination</button>}
      <h4 style={{ marginBottom: 4 }}>Private network allowlist</h4>
      <p style={{ color: 'var(--dim)', fontSize: '.8rem', margin: '0 0 6px' }}>
        Destinations on private or loopback addresses are refused unless listed here (IP, CIDR /8 or narrower, or host name).
        Link-local and cloud metadata addresses are always refused.
      </p>
      <textarea value={allow} onChange={e => setAllow(e.target.value)} placeholder="10.20.0.0/16"
        style={{ width: '100%', minHeight: 50, boxSizing: 'border-box', fontFamily: 'monospace' }} />
      <button className="btn" onClick={saveAllow}>Save allowlist</button> <span>{msg.net}</span>
    </div>
  )
}
