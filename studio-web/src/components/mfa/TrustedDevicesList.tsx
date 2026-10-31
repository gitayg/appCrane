import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// Settings -> Account, under two-factor sign-in: the browsers this person
// ticked "Remember this device" on. GET/DELETE /api/identity/mfa/trusted-devices
// (own devices only; the server scopes every call to the caller).

interface Device {
  id: string
  label: string | null
  ip: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  active: boolean
}

export function TrustedDevicesList() {
  const [data, setData] = useState<{ remember_device_days: number; devices: Device[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const load = () => adminApi.get<{ remember_device_days: number; devices: Device[] }>('/api/identity/mfa/trusted-devices')
    .then(setData).catch(e => setErr(e instanceof Error ? e.message : 'Could not read remembered devices'))
  useEffect(() => { load() }, [])

  async function forget(path: string) {
    setBusy(true)
    setErr('')
    try { await adminApi.del(path); await load() } catch (e) { setErr(e instanceof Error ? e.message : 'Request failed') } finally { setBusy(false) }
  }

  if (!data || (!data.devices.length && !data.remember_device_days)) return err ? <p style={{ color: 'var(--red)', fontSize: '.85rem' }}>{err}</p> : null

  return (
    <div style={{ marginTop: 12 }}>
      <h4 style={{ fontSize: '.85rem', margin: '0 0 6px' }}>Remembered devices</h4>
      {!data.devices.length && <p style={{ color: 'var(--dim)', fontSize: '.78rem' }}>None. Tick "Remember this device" at the code step to skip it on that browser.</p>}
      {data.devices.length > 0 && (
        <table style={{ fontSize: '.8rem', borderCollapse: 'collapse', width: '100%' }}>
          <thead>
            <tr style={{ color: 'var(--dim)', textAlign: 'left' }}>
              <th style={{ padding: '2px 8px 2px 0' }}>Device</th>
              <th style={{ padding: '2px 8px 2px 0' }}>Remembered</th>
              <th style={{ padding: '2px 8px 2px 0' }}>Last used</th>
              <th style={{ padding: '2px 8px 2px 0' }}>Until</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {data.devices.map(d => (
              <tr key={d.id} style={{ opacity: d.active ? 1 : 0.5 }}>
                <td style={{ padding: '2px 8px 2px 0' }}>{d.label || 'Unknown'}{d.ip ? ` (${d.ip})` : ''}</td>
                <td style={{ padding: '2px 8px 2px 0' }}>{d.created_at.slice(0, 10)}</td>
                <td style={{ padding: '2px 8px 2px 0' }}>{d.last_used_at ? d.last_used_at.slice(0, 10) : 'never'}</td>
                <td style={{ padding: '2px 8px 2px 0' }}>{d.active && d.expires_at ? d.expires_at.slice(0, 10) : 'expired'}</td>
                <td><button className="btn btn-xs" disabled={busy} onClick={() => forget(`/api/identity/mfa/trusted-devices/${encodeURIComponent(d.id)}`)}>Forget</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data.devices.length > 1 && (
        <button className="btn btn-xs" disabled={busy} style={{ marginTop: 6 }} onClick={() => forget('/api/identity/mfa/trusted-devices')}>Forget all</button>
      )}
      {err && <p style={{ color: 'var(--red)', fontSize: '.85rem' }}>{err}</p>}
    </div>
  )
}
