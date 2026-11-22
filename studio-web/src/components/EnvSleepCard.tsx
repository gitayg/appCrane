import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Environment sleep for one app (/api/apps/:slug/sleep): each environment's
// state (awake, sleeping, waking) with a Wake button, and the settings —
// sandbox idle minutes, sandbox schedule, and the long-inactivity days that
// also apply to production. Blank fields inherit the platform default.
// Members see the state; owners, app admins and platform admins can edit.

type EnvName = 'sandbox' | 'production'
interface Schedule { days: number[]; start: string; end: string; tz: string }
type ScheduleValue = Schedule | 'off' | null
interface Policy { sandbox_idle_minutes: number | null; sandbox_schedule: ScheduleValue; inactive_days: number | null }
interface EnvState {
  state: 'awake' | 'sleeping' | 'waking'
  reason: string | null
  slept_at: string | null
  woke_at: string | null
  last_error: string | null
  last_request_at: string | null
  not_eligible: string[]
}
interface SleepResp {
  override: Policy
  platform: Policy
  effective: { sandbox_idle_minutes: number; sandbox_schedule: Schedule | null; inactive_days: number }
  envs: Record<EnvName, EnvState>
  limits: { sandbox_idle_minutes: [number, number]; inactive_days: [number, number]; out_of_window_idle_minutes: number }
  can_edit: boolean
}

interface Props {
  slug: string
  reload?: number
  onMsg?: (m: { text: string; ok: boolean }) => void
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const REASONS: Record<string, string> = { idle: 'idle', schedule: 'outside its schedule', inactive: 'unused for days' }

function when(iso: string | null): string {
  if (!iso) return 'never'
  const t = Date.parse(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z')
  return Number.isFinite(t) ? new Date(t).toLocaleString() : iso
}

function numOrNull(s: string): number | null {
  return s.trim() === '' ? null : Number(s)
}

export function EnvSleepCard({ slug, reload = 0, onMsg }: Props) {
  const [data, setData] = useState<SleepResp | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [idle, setIdle] = useState('')
  const [days, setDays] = useState('')
  const [schedMode, setSchedMode] = useState<'inherit' | 'off' | 'on'>('inherit')
  const [sched, setSched] = useState<Schedule>({ days: [1, 2, 3, 4, 5], start: '08:00', end: '19:00', tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' })

  const msg = (text: string, ok: boolean) => { if (onMsg) onMsg({ text, ok }); else if (!ok) setError(text) }

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await fetch(`/api/apps/${encodeURIComponent(slug)}/sleep`, { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 404) { setHidden(true); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      const d = body as SleepResp
      setHidden(false)
      setData(d)
      setIdle(d.override.sandbox_idle_minutes == null ? '' : String(d.override.sandbox_idle_minutes))
      setDays(d.override.inactive_days == null ? '' : String(d.override.inactive_days))
      const s = d.override.sandbox_schedule
      if (s == null) setSchedMode('inherit')
      else if (s === 'off') setSchedMode('off')
      else { setSchedMode('on'); setSched(s) }
    } catch (e) {
      setError((e as Error).message || 'Cannot load sleep settings')
    }
  }, [slug])

  useEffect(() => { void load() }, [load, reload])

  if (hidden) return null

  async function save() {
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${encodeURIComponent(slug)}/sleep`, {
        sandbox_idle_minutes: numOrNull(idle),
        inactive_days: numOrNull(days),
        sandbox_schedule: schedMode === 'inherit' ? null : schedMode === 'off' ? 'off' : sched,
      })
      msg('Sleep settings saved', true)
      void load()
    } catch (e) {
      msg((e as Error).message, false)
    } finally {
      setBusy(false)
    }
  }

  async function wake(env: EnvName) {
    setBusy(true)
    try {
      await adminApi.post(`/api/apps/${encodeURIComponent(slug)}/sleep/${env}/wake`, {})
      msg(`${env} is awake`, true)
      void load()
    } catch (e) {
      msg((e as Error).message, false)
    } finally {
      setBusy(false)
    }
  }

  const toggleDay = (d: number) => setSched(s => ({
    ...s, days: s.days.includes(d) ? s.days.filter(x => x !== d) : [...s.days, d].sort(),
  }))

  const envRow = (env: EnvName) => {
    const e = data!.envs[env]
    const label = e.state === 'sleeping' ? 'Sleeping' : e.state === 'waking' ? 'Waking' : 'Awake'
    const color = e.state === 'awake' ? 'var(--green)' : e.state === 'waking' ? 'var(--yellow, #eab308)' : 'var(--dim)'
    return (
      <tr key={env}>
        <td style={{ textTransform: 'capitalize' }}>{env}</td>
        <td>
          <span style={{ color, fontWeight: 600 }}>{label}</span>
          {e.state === 'sleeping' && e.reason && <span style={{ color: 'var(--dim)' }}> ({REASONS[e.reason] || e.reason}, since {when(e.slept_at)})</span>}
          {e.last_error && <div style={{ color: 'var(--red)', fontSize: '.75rem' }}>{e.last_error}</div>}
          {e.not_eligible.length > 0 && <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>Never put to sleep: {e.not_eligible.join('; ')}</div>}
        </td>
        <td style={{ color: 'var(--dim)' }}>{when(e.last_request_at)}</td>
        <td>{e.state !== 'awake' && <button className="btn btn-sm" disabled={busy} onClick={() => wake(env)}>Wake</button>}</td>
      </tr>
    )
  }

  const eff = data?.effective
  const lim = data?.limits

  return (
    <>
      <h2 className="am-h2">Sleep</h2>
      <div className="am-card">
        <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 8 }}>
          A sleeping environment's container is stopped to free memory. The first request wakes it: the visitor waits a few seconds
          and lands where they were going. Deploys wake it too. Production is only put to sleep after days without any use.
        </div>
        {error ? (
          <span style={{ color: 'var(--red)' }}>{error}</span>
        ) : !data ? 'Loading...' : (
          <>
            <table>
              <thead><tr><th>Environment</th><th>State</th><th>Last request</th><th /></tr></thead>
              <tbody>{envRow('sandbox')}{envRow('production')}</tbody>
            </table>
            <div style={{ fontSize: '.8rem', margin: '10px 0', color: 'var(--dim)' }}>
              In effect: sandbox idle {eff!.sandbox_idle_minutes ? `${eff!.sandbox_idle_minutes} min` : 'off'}
              {' · '}schedule {eff!.sandbox_schedule ? `${eff!.sandbox_schedule.days.map(d => DAYS[d]).join(' ')} ${eff!.sandbox_schedule.start}-${eff!.sandbox_schedule.end} ${eff!.sandbox_schedule.tz}` : 'off'}
              {' · '}unused {eff!.inactive_days ? `${eff!.inactive_days} days` : 'off'}
            </div>
            {data.can_edit && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <label>Sandbox idle minutes ({lim!.sandbox_idle_minutes[0]}-{lim!.sandbox_idle_minutes[1]}, 0 off, blank = platform default {data.platform.sandbox_idle_minutes || 'off'})
                  <input className="am-input" inputMode="numeric" value={idle} onChange={e => setIdle(e.target.value)} />
                </label>
                <label>Days unused before any environment sleeps ({lim!.inactive_days[0]}-{lim!.inactive_days[1]}, 0 off, blank = platform default {data.platform.inactive_days || 'off'})
                  <input className="am-input" inputMode="numeric" value={days} onChange={e => setDays(e.target.value)} />
                </label>
                <label>Sandbox schedule
                  <select className="am-input" value={schedMode} onChange={e => setSchedMode(e.target.value as 'inherit' | 'off' | 'on')}>
                    <option value="inherit">Platform default</option>
                    <option value="off">No schedule</option>
                    <option value="on">Awake only in a window</option>
                  </select>
                </label>
                {schedMode === 'on' && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                    {DAYS.map((n, i) => (
                      <label key={n} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <input type="checkbox" checked={sched.days.includes(i)} onChange={() => toggleDay(i)} />{n}
                      </label>
                    ))}
                    <input className="am-input" style={{ width: 90 }} value={sched.start} onChange={e => setSched(s => ({ ...s, start: e.target.value }))} />
                    to
                    <input className="am-input" style={{ width: 90 }} value={sched.end} onChange={e => setSched(s => ({ ...s, end: e.target.value }))} />
                    <input className="am-input" style={{ width: 200 }} value={sched.tz} onChange={e => setSched(s => ({ ...s, tz: e.target.value }))} />
                    <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
                      Outside the window a request still wakes it; it sleeps again after {lim!.out_of_window_idle_minutes} idle minutes.
                    </span>
                  </div>
                )}
                <div><button className="btn btn-sm" disabled={busy} onClick={save}>Save</button></div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  )
}
