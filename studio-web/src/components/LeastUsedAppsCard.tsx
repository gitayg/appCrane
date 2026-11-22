import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Platform admins: every app, least used first (/api/usage/apps), with its last
// signed-in request, 30-day active users, how much of its traffic AppCrane can
// see, and what the inactivity sleep would do to each live environment and
// when. An app AppCrane cannot see is marked so, never shown as unused.

interface Reason { env: string; level: 'partial' | 'none'; code: string; message: string }
interface EnvForecast {
  env: 'sandbox' | 'production'
  state: 'awake' | 'sleeping' | 'waking'
  inactive_days: number
  not_eligible: string[]
  idle_since: string | null
  sleeps_at: string | null
  due: boolean
}
interface AppRow {
  slug: string
  name: string
  last_use_at: string | null
  active_users_30d: number
  requests_30d: number
  coverage: 'full' | 'partial' | 'none'
  coverage_reasons: Reason[]
  tracking_since: string | null
  envs: EnvForecast[]
}
interface Resp { now: string; window_days: number; apps: AppRow[] }

function when(iso: string | null): string {
  if (!iso) return 'none on record'
  const t = Date.parse(iso)
  return Number.isFinite(t) ? new Date(t).toLocaleDateString() : iso
}

function forecast(e: EnvForecast): { text: string; color: string; title?: string } {
  if (e.state !== 'awake') return { text: `${e.env}: ${e.state}`, color: 'var(--dim)' }
  if (!e.inactive_days) return { text: `${e.env}: inactivity sleep off`, color: 'var(--dim)' }
  if (e.not_eligible.length) return { text: `${e.env}: never slept`, color: 'var(--dim)', title: e.not_eligible.join('; ') }
  if (e.due) return { text: `${e.env}: sleeps at the next pass`, color: 'var(--red)' }
  return { text: `${e.env}: sleeps ${when(e.sleeps_at)}`, color: 'var(--yellow, #eab308)', title: `Idle since ${when(e.idle_since)}, ${e.inactive_days} days allowed` }
}

export function LeastUsedAppsCard({ reload = 0, limit = 25 }: { reload?: number; limit?: number }) {
  const [data, setData] = useState<Resp | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showAll, setShowAll] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await fetch('/api/usage/apps', { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 401) { setHidden(true); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      setHidden(false)
      setData(body as Resp)
    } catch (e) {
      setError((e as Error).message || 'Cannot load app usage')
    }
  }, [])

  useEffect(() => { void load() }, [load, reload])

  if (hidden) return null
  const rows = data ? (showAll ? data.apps : data.apps.slice(0, limit)) : []

  return (
    <>
      <h2 className="am-h2">Least-used apps</h2>
      <div className="am-card">
        <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 8 }}>
          Signed-in use over the last 30 days, least first. Where AppCrane cannot see an app's traffic the row says so: its zero is
          unknown, not idle, and the inactivity sleep never acts on it.
        </div>
        {error ? <span style={{ color: 'var(--red)' }}>{error}</span> : !data ? 'Loading...' : (
          <>
            <table>
              <thead><tr><th>App</th><th>Last use</th><th>Users (30d)</th><th>Requests (30d)</th><th>Visibility</th><th>Inactivity sleep</th></tr></thead>
              <tbody>
                {rows.map(a => {
                  const blind = a.coverage === 'none'
                  return (
                    <tr key={a.slug}>
                      <td>{a.name} <span style={{ color: 'var(--dim)' }}>{a.slug}</span></td>
                      <td>{blind ? 'unknown' : when(a.last_use_at)}</td>
                      <td>{blind ? '-' : a.active_users_30d}</td>
                      <td>{blind ? '-' : a.requests_30d}</td>
                      <td title={a.coverage_reasons.map(r => `${r.env}: ${r.message}`).join('\n')}
                        style={{ color: blind ? 'var(--red)' : a.coverage === 'partial' ? 'var(--yellow, #eab308)' : 'var(--green)' }}>
                        {blind ? 'not visible' : a.coverage}
                      </td>
                      <td style={{ fontSize: '.75rem' }}>
                        {a.envs.length === 0 ? <span style={{ color: 'var(--dim)' }}>nothing live</span> : a.envs.map(e => {
                          const f = forecast(e)
                          return <div key={e.env} style={{ color: f.color }} title={f.title}>{f.text}</div>
                        })}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {data.apps.length > limit && (
              <button className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => setShowAll(s => !s)}>
                {showAll ? 'Show fewer' : `Show all ${data.apps.length}`}
              </button>
            )}
          </>
        )}
      </div>
    </>
  )
}
