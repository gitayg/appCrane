import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { fmtBytes, relTime } from './format'
import type { EnvName } from './types'

export interface Incident {
  id: number
  env: EnvName
  trigger: string
  action: string
  kind: string
  summary: string
  created_at: string
  memory: { current: number | null; max: number | null; source: string | null; oom_kill: number | null } | null
  exit_state: { status?: string; exit_code?: number; oom_killed?: boolean; error?: string | null; started_at?: string | null; finished_at?: string | null } | null
  not_captured: string[]
  log_tail?: string[]
}
export interface IncidentEnv {
  unstable: boolean
  since?: string
  rule?: string
  next_restart_at?: string
  last_incident: { summary: string; created_at: string; trigger: string; action: string } | null
  last_7_days: { unplanned: number; planned: number; by_trigger: Record<string, number> }
}
export interface IncidentsData { incidents: Incident[]; envs: Partial<Record<EnvName, IncidentEnv>>; log_tail_visible: boolean }

/** GET /api/apps/:slug/incidents, once per reload. null while loading or when unavailable. */
export function useIncidents(slug: string, reload: number): IncidentsData | null {
  const [d, setD] = useState<IncidentsData | null>(null)
  useEffect(() => {
    let off = false
    adminApi.get<IncidentsData>(`/api/apps/${slug}/incidents?limit=30`).then(r => { if (!off) setD(r) }).catch(() => {})
    return () => { off = true }
  }, [slug, reload])
  return d
}

const hhmm = (s: string) => serverDate(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
const VERB: Record<string, string> = { restarted: 'restarted', skipped: 'restart skipped', observed: 'stopped', recovered: 'recovered', failed: 'restart failed' }

/** "restarted 14:11: memory 99% of 512 MB" plus an Unstable pill, for the Status row. */
export function IncidentLine({ env }: { env?: IncidentEnv }) {
  if (!env) return null
  const last = env.last_incident
  return (
    <>
      {env.unstable && <span className="am2-pill bad" title={`Restart loop (${env.rule}). Automatic restarts back off; next not before ${env.next_restart_at} UTC. A deploy or manual restart clears it.`}>Unstable</span>}
      {last && <span className="am2-small am2-dim" title={last.created_at + ' UTC'}>{VERB[last.action] || last.action} {hhmm(last.created_at)}: {last.summary}</span>}
    </>
  )
}

function IncidentRow({ i, logsVisible }: { i: Incident; logsVisible: boolean }) {
  const [open, setOpen] = useState(false)
  const m = i.memory
  return (
    <li style={{ padding: '6px 0', borderTop: '1px solid var(--border)' }}>
      <div className="am2-row" style={{ cursor: 'pointer' }} onClick={() => setOpen(!open)}>
        <span className="am2-small am2-dim" title={i.created_at + ' UTC'}>{relTime(i.created_at)}</span>
        <span className="am2-pill">{i.env}</span>
        <span className={'am2-pill' + (i.kind === 'memory' ? ' bad' : i.kind === 'planned' ? '' : ' warn')}>{i.trigger}</span>
        <span>{i.summary}</span>
        <span className="am2-dim">{open ? '▾' : '▸'}</span>
      </div>
      {open && (
        <div className="am2-small" style={{ marginTop: 6 }}>
          {m && <div>Memory: {fmtBytes(m.current)} of {m.max ? fmtBytes(m.max) : 'no limit'}{m.oom_kill ? `, ${m.oom_kill} OOM kill(s)` : ''} <span className="am2-dim">({m.source})</span></div>}
          {i.exit_state && <div>Container: {i.exit_state.status}{i.exit_state.exit_code != null ? `, exit ${i.exit_state.exit_code}` : ''}{i.exit_state.oom_killed ? ', OOM-killed' : ''}{i.exit_state.error ? `, ${i.exit_state.error}` : ''}{i.exit_state.started_at ? `, started ${i.exit_state.started_at}` : ''}</div>}
          {i.not_captured.length > 0 && <div className="am2-dim">Not captured: {i.not_captured.join('; ')}</div>}
          {logsVisible
            ? (i.log_tail?.length
              ? <pre className="am2-mono" style={{ maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', marginTop: 6 }}>{i.log_tail.join('\n')}</pre>
              : <div className="am2-dim">No log lines captured.</div>)
            : <div className="am2-dim">Log lines are visible to the app owner and platform admins.</div>}
        </div>
      )}
    </li>
  )
}

/** Recent restarts and stops with what was captured before each one. */
export function IncidentsCard({ data }: { data: IncidentsData | null }) {
  if (!data) return null
  const envs = Object.entries(data.envs) as [EnvName, IncidentEnv][]
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>Restarts</h3>
      <div className="am2-row am2-small" style={{ marginBottom: 8 }}>
        {envs.map(([env, e]) => (
          <span key={env}>
            <strong>{env}</strong>: {e.last_7_days.unplanned} unplanned, {e.last_7_days.planned} planned in 7 days
            {e.unstable && <span className="am2-pill bad" style={{ marginLeft: 6 }}>Unstable</span>}
          </span>
        ))}
      </div>
      {data.incidents.length === 0
        ? <div className="am2-dim am2-small">No restarts recorded.</div>
        : <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>{data.incidents.map(i => <IncidentRow key={i.id} i={i} logsVisible={data.log_tail_visible} />)}</ul>}
    </div>
  )
}
