import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { BarChart, Funnel, LineChart } from './UsageCharts'

// Usage of one app over time (/api/apps/:slug/usage): DAU, WAU and MAU, daily
// requests, new vs returning users per week, the adoption funnel and the top
// users. Owners, app admins and platform admins only; others get 403 and the
// card hides. Counts come from AppCrane sign-in, so when coverage is not full
// the card says what it cannot see rather than presenting zeros as fact.

type Env = 'production' | 'sandbox' | 'all'
interface Reason { env: string; level: 'partial' | 'none'; code: string; message: string }
interface Day { day: string; requests: number; dau: number; wau: number; mau: number; stickiness: number | null }
interface Week { week_start: string; active: number; new: number; returning: number; partial_week: boolean; first_tracked_week: boolean }
interface TopUser { user_id: number; name: string | null; email: string | null; requests: number; active_days: number; last_seen: string }
interface UsageResp {
  range: { from: string; to: string; clamped: boolean; retention_days: number }
  coverage: 'full' | 'partial' | 'none'
  coverage_reasons: Reason[]
  tracking_since: string | null
  summary: { requests: number; dau: number; wau: number; mau: number; stickiness: number | null }
  daily: Day[]
  weeks: Week[]
  funnel: { granted: number; signed_in: number; active_3_days_in_30: number; active_this_week: number; active_without_grant: number }
  top_users: TopUser[] | null
  aggregates_only: boolean
}

interface Props {
  slug: string
  reload?: number
  onMsg?: (m: { text: string; ok: boolean }) => void
}

const RANGES = [30, 90, 180, 365]

function isoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10)
}

function Tile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', minWidth: 90 }} title={hint}>
      <div style={{ fontSize: '.7rem', color: 'var(--dim)' }}>{label}</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600 }}>{value}</div>
    </div>
  )
}

export function UsageCard({ slug, reload = 0, onMsg }: Props) {
  const [data, setData] = useState<UsageResp | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [env, setEnv] = useState<Env>('production')
  const [days, setDays] = useState(90)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    const now = Date.now()
    const qs = new URLSearchParams({ env, from: isoDay(now - (days - 1) * 86_400_000), to: isoDay(now) })
    try {
      const r = await fetch(`/api/apps/${encodeURIComponent(slug)}/usage?${qs}`, { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 404) { setHidden(true); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      setHidden(false)
      setData(body as UsageResp)
    } catch (e) {
      setError((e as Error).message || 'Cannot load usage')
    }
  }, [slug, env, days])

  useEffect(() => { void load() }, [load, reload])

  if (hidden) return null

  async function setAggregatesOnly(on: boolean) {
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${encodeURIComponent(slug)}/usage/settings`, { aggregates_only: on })
      onMsg?.({ text: on ? 'Usage now shows counts only' : 'Usage shows per-user rows again', ok: true })
      void load()
    } catch (e) {
      const text = (e as Error).message
      if (onMsg) onMsg({ text, ok: false }); else setError(text)
    } finally {
      setBusy(false)
    }
  }

  const blind = data?.coverage === 'none'
  const labels = data ? data.daily.map(d => d.day.slice(5)) : []
  const pct = (x: number | null) => (x == null ? '-' : `${Math.round(x * 100)}%`)

  return (
    <>
      <h2 className="am-h2">Usage</h2>
      <div className="am-card">
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
          <select className="am-input" style={{ width: 150 }} value={env} onChange={e => setEnv(e.target.value as Env)}>
            <option value="production">Production</option>
            <option value="sandbox">Sandbox</option>
            <option value="all">Both environments</option>
          </select>
          <select className="am-input" style={{ width: 130 }} value={days} onChange={e => setDays(Number(e.target.value))}>
            {RANGES.map(n => <option key={n} value={n}>Last {n} days</option>)}
          </select>
          {data && (
            <label style={{ display: 'flex', gap: 4, alignItems: 'center', fontSize: '.8rem', marginLeft: 'auto' }}>
              <input type="checkbox" checked={data.aggregates_only} disabled={busy} onChange={e => setAggregatesOnly(e.target.checked)} />
              Counts only (hide the per-user table)
            </label>
          )}
        </div>
        {error ? (
          <span style={{ color: 'var(--red)' }}>{error}</span>
        ) : !data ? 'Loading...' : (
          <>
            {data.coverage !== 'full' && (
              <div style={{ border: `1px solid ${blind ? 'var(--red)' : 'var(--yellow, #eab308)'}`, borderRadius: 6, padding: '6px 10px', fontSize: '.8rem', marginBottom: 8 }}>
                <strong>{blind ? 'AppCrane cannot see this app\'s use.' : 'Some use is not counted.'}</strong>{' '}
                {blind ? 'The numbers below are not evidence that nobody uses it.' : 'Treat low numbers as a lower bound.'}
                <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                  {data.coverage_reasons.map(r => <li key={r.env + r.code}>{r.env}: {r.message}</li>)}
                </ul>
              </div>
            )}
            {data.range.clamped && (
              <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 6 }}>
                Per-day records are kept {data.range.retention_days} days; the range starts at {data.range.from}.
              </div>
            )}
            {blind ? null : (
              <>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                  <Tile label="DAU" value={String(data.summary.dau)} hint={`Signed-in users on ${data.range.to}`} />
                  <Tile label="WAU" value={String(data.summary.wau)} hint="Distinct users in the 7 days ending today" />
                  <Tile label="MAU" value={String(data.summary.mau)} hint="Distinct users in the 30 days ending today" />
                  <Tile label="Stickiness" value={pct(data.summary.stickiness)} hint="Average DAU over the last 30 days / MAU" />
                  <Tile label="Requests" value={String(data.summary.requests)} hint={`${data.range.from} to ${data.range.to}`} />
                </div>
                <div style={{ fontSize: '.8rem', fontWeight: 600 }}>Active users</div>
                <LineChart labels={labels} series={[
                  { name: 'DAU', color: 'var(--accent)', values: data.daily.map(d => d.dau) },
                  { name: 'WAU', color: 'var(--green)', values: data.daily.map(d => d.wau) },
                  { name: 'MAU', color: 'var(--orange, #f97316)', values: data.daily.map(d => d.mau) },
                ]} />
                <div style={{ fontSize: '.8rem', fontWeight: 600, marginTop: 8 }}>Requests per day</div>
                <BarChart labels={labels} series={[{ name: 'Requests', color: 'var(--accent)', values: data.daily.map(d => d.requests) }]} />
                <div style={{ fontSize: '.8rem', fontWeight: 600, marginTop: 8 }}>New and returning users per week</div>
                <BarChart labels={data.weeks.map(w => w.week_start.slice(5))} series={[
                  { name: 'Returning', color: 'var(--green)', values: data.weeks.map(w => w.returning) },
                  { name: 'New', color: 'var(--accent)', values: data.weeks.map(w => w.new) },
                ]} />
                {data.weeks.some(w => w.first_tracked_week) && (
                  <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>
                    Tracking started {data.tracking_since}: everyone active in that week reads as new.
                  </div>
                )}
                <div style={{ fontSize: '.8rem', fontWeight: 600, margin: '10px 0 4px' }}>Adoption</div>
                <Funnel stages={[
                  { label: 'Granted access', value: data.funnel.granted },
                  { label: 'Signed in at least once', value: data.funnel.signed_in },
                  { label: 'Active 3+ days of the last 30', value: data.funnel.active_3_days_in_30 },
                  { label: 'Active this week', value: data.funnel.active_this_week },
                ]} />
                {data.funnel.active_without_grant > 0 && (
                  <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 4 }}>
                    {data.funnel.active_without_grant} active user(s) in the last 30 days have no grant on this app (platform admins, for example).
                  </div>
                )}
                <div style={{ fontSize: '.8rem', fontWeight: 600, margin: '10px 0 4px' }}>Top users</div>
                {data.top_users == null ? (
                  <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>This app shows counts only; the per-user table is hidden.</div>
                ) : data.top_users.length === 0 ? (
                  <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>No signed-in use in this range.</div>
                ) : (
                  <table>
                    <thead><tr><th>User</th><th>Requests</th><th>Active days</th><th>Last seen</th></tr></thead>
                    <tbody>
                      {data.top_users.map(u => (
                        <tr key={u.user_id}>
                          <td>{u.name || u.email || `#${u.user_id}`}{u.name && u.email ? <span style={{ color: 'var(--dim)' }}> {u.email}</span> : null}</td>
                          <td>{u.requests}</td>
                          <td>{u.active_days}</td>
                          <td>{u.last_seen}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </>
        )}
      </div>
    </>
  )
}
