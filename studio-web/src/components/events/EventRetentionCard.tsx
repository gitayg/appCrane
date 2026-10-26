import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

type Retention = { info: number; warning: number; critical: number }

export function EventRetentionCard() {
  const [r, setR] = useState<Retention | null>(null)
  const [msg, setMsg] = useState('')
  useEffect(() => { adminApi.get<{ retention: Retention }>('/api/events/retention').then(d => setR(d.retention)).catch(() => {}) }, [])
  if (!r) return null
  const save = () => adminApi.put('/api/events/retention', r).then(() => setMsg('Saved')).catch(e => setMsg(String(e?.message || e)))
  return (
    <div className="card">
      <h3>Event retention</h3>
      <p style={{ color: 'var(--dim)', fontSize: '.82rem', margin: '4px 0 10px' }}>How long the Events timeline keeps each severity, in days.</p>
      {(['info', 'warning', 'critical'] as const).map(s => (
        <label key={s} style={{ marginRight: 14 }}>{s}{' '}
          <input type="number" min={1} max={3650} value={r[s]} onChange={e => setR({ ...r, [s]: Number(e.target.value) })} style={{ width: 80 }} />
        </label>
      ))}
      <button className="btn" onClick={save}>Save</button> <span>{msg}</span>
    </div>
  )
}
