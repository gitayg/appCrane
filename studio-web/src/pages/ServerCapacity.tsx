import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { useFlash } from '../components/formHelpers'

type Mode = 'refuse' | 'warn' | 'off'
type Level = 'ok' | 'warning' | 'critical' | 'unknown'

interface Thresholds {
  mem_warn_pct: number; mem_crit_pct: number; mem_floor_mb: number
  disk_warn_pct: number; disk_crit_pct: number; disk_floor_gb: number
}

interface Resource {
  id: string; label: string; level: Level; error?: string
  freeBytes?: number; totalBytes?: number; committedBytes?: number; capacityBytes?: number
}

interface Capacity {
  settings: { mode: Mode; reserveMb: number | null; thresholds: Thresholds }
  memory: {
    total_mb: number; total_source: 'docker' | 'os'; reserve_mb: number; reserve_source: string
    capacity_mb: number; committed_mb: number; error: string | null
    containers: { name: string; label: string; cap_mb: number | null; counted_mb: number; counted_from: string }[]
  }
  host: { at: string; overall: Level; resources: Resource[] } | null
}

const LEVEL_COLOR: Record<Level, string> = {
  ok: 'var(--green)', warning: 'var(--orange)', critical: 'var(--red)', unknown: 'var(--dim)',
}

const THRESHOLD_FIELDS: [keyof Thresholds, string][] = [
  ['mem_warn_pct', 'Memory warning below %'], ['mem_crit_pct', 'Memory critical below %'], ['mem_floor_mb', 'Memory critical below MB'],
  ['disk_warn_pct', 'Disk warning below %'], ['disk_crit_pct', 'Disk critical below %'], ['disk_floor_gb', 'Disk critical below GB'],
]

function gb(bytes?: number) {
  return bytes == null ? '-' : `${(bytes / 1024 ** 3).toFixed(1)} GB`
}

function resourceText(r: Resource) {
  if (r.level === 'unknown') return `unknown${r.error ? ` (${r.error})` : ''}`
  if (r.id === 'committed') return `${gb(r.committedBytes)} of ${gb(r.capacityBytes)}`
  const pct = r.totalBytes ? ((r.freeBytes! / r.totalBytes) * 100).toFixed(1) : '?'
  return `${gb(r.freeBytes)} of ${gb(r.totalBytes)} (${pct}%)`
}

export function ServerCapacity() {
  const [data, setData] = useState<Capacity | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<Mode>('refuse')
  const [reserve, setReserve] = useState('')
  const [thresholds, setThresholds] = useState<Thresholds | null>(null)
  const [saved, flashSaved] = useFlash()

  const load = useCallback((fresh = false) => {
    adminApi.get<Capacity>(`/api/settings/server-capacity${fresh ? '?fresh=1' : ''}`)
      .then(r => {
        setData(r); setError(null)
        setMode(r.settings.mode)
        setReserve(r.settings.reserveMb == null ? '' : String(r.settings.reserveMb))
        setThresholds(r.settings.thresholds)
      })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])
  useEffect(() => { load() }, [load])

  async function save() {
    setError(null)
    try {
      await adminApi.put('/api/settings/server-capacity', {
        mode,
        reserve_mb: reserve.trim() === '' ? null : Number(reserve),
        thresholds,
      })
      flashSaved()
      load(true)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const m = data?.memory
  const pct = m && m.capacity_mb > 0 ? Math.round((m.committed_mb / m.capacity_mb) * 100) : 0
  const over = !!m && m.committed_mb > m.capacity_mb

  return (
    <div style={{ marginBottom: 28 }}>
      <h3>Server capacity</h3>
      <p className="settings-hint">
        Every container runs with a memory cap. A deploy, coder session or new managed database is refused when the
        caps of all running containers would add up to more than the server's memory minus a reserve for the host.
        A start that does not raise the total, like a same-size redeploy or rollback, is always allowed.
      </p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      {m && (
        <>
          <p style={{ fontWeight: 600, color: m.error ? 'var(--dim)' : over ? 'var(--red)' : 'var(--green)', margin: '6px 0' }}>
            {m.error ? `Memory committed: unknown (${m.error})` : `Memory committed: ${m.committed_mb} of ${m.capacity_mb} MB (${pct}%)`}
          </p>
          {!m.error && (
            <div style={{ height: 8, borderRadius: 4, background: 'var(--border)', overflow: 'hidden', maxWidth: 480 }}
              role="meter" aria-valuemin={0} aria-valuemax={m.capacity_mb} aria-valuenow={m.committed_mb} aria-label="Memory committed">
              <div style={{ width: `${Math.min(100, pct)}%`, height: '100%', background: over ? 'var(--red)' : pct > 85 ? 'var(--orange)' : 'var(--green)' }} />
            </div>
          )}
          <p style={{ color: 'var(--dim)', fontSize: '.78rem', margin: '6px 0 0' }}>
            {m.total_mb} MB {m.total_source === 'docker' ? 'reported by Docker' : 'on this machine (docker info failed)'} minus a {m.reserve_mb} MB
            reserve ({m.reserve_source === 'setting' ? 'set below' : 'default: 1 GB or 10%, whichever is larger'}).
          </p>
          {m.containers.length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ cursor: 'pointer', fontSize: '.85rem' }}>Largest commitments</summary>
              <table style={{ fontSize: '.8rem', marginTop: 6 }}>
                <tbody>
                  {m.containers.map(c => (
                    <tr key={c.name}>
                      <td style={{ padding: '2px 12px 2px 0' }}>{c.label}</td>
                      <td style={{ padding: '2px 12px 2px 0' }}>{c.cap_mb == null ? 'no limit' : `${c.cap_mb} MB cap`}</td>
                      <td style={{ color: 'var(--dim)' }}>{c.cap_mb == null ? `counted ${c.counted_mb} MB (${c.counted_from === 'usage' ? 'current use' : 'default'})` : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </>
      )}
      {data?.host && (
        <ul style={{ margin: '10px 0 0', paddingLeft: 18, fontSize: '.85rem' }}>
          {data.host.resources.map(r => (
            <li key={r.id}>
              <span style={{ color: LEVEL_COLOR[r.level], fontWeight: 600 }}>{r.level}</span> {r.label}: {resourceText(r)}
            </li>
          ))}
        </ul>
      )}

      {data && (
        <div style={{ marginTop: 14 }}>
          <label htmlFor="mem-admission-mode">When a start does not fit</label>
          <select id="mem-admission-mode" value={mode} onChange={e => setMode(e.target.value as Mode)}>
            <option value="refuse">Refuse it (the running version keeps serving)</option>
            <option value="warn">Start it and e-mail platform admins</option>
            <option value="off">Off (no check)</option>
          </select>
          <label htmlFor="mem-reserve">Reserve for the host, MB (blank for the default)</label>
          <input id="mem-reserve" type="number" min={0} value={reserve} onChange={e => setReserve(e.target.value)} />
          {thresholds && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 8, marginTop: 8 }}>
              {THRESHOLD_FIELDS.map(([k, label]) => (
                <div key={k}>
                  <label htmlFor={`thr-${k}`} style={{ fontSize: '.78rem' }}>{label}</label>
                  <input id={`thr-${k}`} type="number" min={0} value={thresholds[k]}
                    onChange={e => setThresholds({ ...thresholds, [k]: Number(e.target.value) })} />
                </div>
              ))}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10 }}>
            <button className="btn" onClick={save}>Save</button>
            <button className="btn" onClick={() => load(true)}>Measure now</button>
            {saved && <span style={{ color: 'var(--green)' }}>Saved</span>}
          </div>
        </div>
      )}
    </div>
  )
}
