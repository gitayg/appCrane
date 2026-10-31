import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import { HostLimitsCard } from '../components/HostLimitsCard'

type JobStatus = 'ok' | 'warning' | 'late' | 'failing' | 'never-run' | 'disabled'

interface JobRun {
  started_at: string
  finished_at: string
  ok: boolean
  duration_ms: number
  error: string | null
}

interface Job {
  id: string
  label: string
  cadence_ms: number | null
  status: JobStatus
  running: boolean
  last_run: JobRun | null
  next_expected_run: string | null
  late_after: string | null
  last_error: string | null
  since_boot: { runs: number; failures: number }
  history: JobRun[]
  can_run_now: boolean
  queue?: { queued: number; sending: number; failed: number; oldest_queued_at: string | null } | null
  detail?: { message?: string; severity?: string } | null
}

const REFRESH_MS = 30_000

const STATUS_STYLE: Record<JobStatus, { label: string; color: string }> = {
  ok:          { label: 'OK',        color: 'var(--green)' },
  warning:     { label: 'Warning',   color: 'var(--orange)' },
  late:        { label: 'Late',      color: 'var(--orange)' },
  failing:     { label: 'Failing',   color: 'var(--red)' },
  'never-run': { label: 'Never run', color: 'var(--dim)' },
  disabled:    { label: 'Disabled',  color: 'var(--dim)' },
}

const ORDER: JobStatus[] = ['failing', 'late', 'warning', 'never-run', 'ok', 'disabled']

function StatusPill({ status, running }: { status: JobStatus; running: boolean }) {
  const s = STATUS_STYLE[status]
  return (
    <span className="badge" style={{
      color: s.color,
      background: `color-mix(in srgb, ${s.color} 14%, transparent)`,
      whiteSpace: 'nowrap',
    }}>
      {running ? 'Running' : s.label}
    </span>
  )
}

function cadence(ms: number | null): string {
  if (ms == null) return 'once per release'
  if (ms < 60_000) return `every ${Math.round(ms / 1000)}s`
  if (ms < 3_600_000) return `every ${Math.round(ms / 60_000)} min`
  if (ms < 86_400_000) return `every ${Math.round(ms / 3_600_000)} h`
  return 'daily'
}

function relative(iso: string | null): string {
  if (!iso) return '-'
  const diff = Date.parse(iso) - Date.now()
  const abs = Math.abs(diff)
  const unit = abs < 60_000 ? [Math.round(abs / 1000), 's']
    : abs < 3_600_000 ? [Math.round(abs / 60_000), 'min']
    : abs < 86_400_000 ? [Math.round(abs / 3_600_000), 'h']
    : [Math.round(abs / 86_400_000), 'd']
  return diff < 0 ? `${unit[0]} ${unit[1]} ago` : `in ${unit[0]} ${unit[1]}`
}

function duration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`
}

function JobRow({ job, onRun }: { job: Job; onRun: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  const last = job.last_run
  return (
    <>
      <tr style={{ borderTop: '1px solid var(--border)' }}>
        <td style={{ padding: '8px 6px' }}><StatusPill status={job.status} running={job.running} /></td>
        <td style={{ padding: '8px 6px' }}>
          <div style={{ fontWeight: 600 }}>{job.label}</div>
          <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
            {cadence(job.cadence_ms)}
            {job.queue && <> | queue: {job.queue.queued} queued, {job.queue.sending} sending, {job.queue.failed} failed</>}
          </div>
          {typeof job.detail?.message === 'string' && (
            <div style={{ color: job.detail.severity === 'warning' ? 'var(--orange)' : 'var(--dim)', fontSize: '.75rem' }}>{job.detail.message}</div>
          )}
        </td>
        <td style={{ padding: '8px 6px' }} title={last?.finished_at || ''}>
          {last ? <>{relative(last.finished_at)} <span style={{ color: 'var(--dim)' }}>({duration(last.duration_ms)})</span></> : '-'}
        </td>
        <td style={{ padding: '8px 6px' }} title={job.next_expected_run || ''}>{relative(job.next_expected_run)}</td>
        <td style={{ padding: '8px 6px', whiteSpace: 'nowrap', textAlign: 'right' }}>
          {(job.last_error || job.history.length > 0) && (
            <button className="btn" onClick={() => setOpen(o => !o)} aria-expanded={open}>
              {open ? 'Hide' : job.last_error ? 'Error' : 'History'}
            </button>
          )}
          {job.can_run_now && (
            <button className="btn" style={{ marginLeft: 6 }} disabled={job.running} onClick={() => onRun(job.id)}>
              Run now
            </button>
          )}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5} style={{ padding: '4px 6px 12px' }}>
            {job.last_error && (
              <pre style={{
                whiteSpace: 'pre-wrap', margin: '0 0 8px', padding: 8, borderRadius: 6,
                border: '1px solid var(--red)', background: 'color-mix(in srgb, var(--red) 8%, transparent)',
                fontSize: '.8rem',
              }}>{job.last_error}</pre>
            )}
            <div style={{ color: 'var(--dim)', fontSize: '.75rem', marginBottom: 4 }}>
              Since this process started: {job.since_boot.runs} run(s), {job.since_boot.failures} failure(s).
              Recent history (frequent jobs record a run when the outcome changes and at most every 10 minutes otherwise):
            </div>
            <table style={{ width: '100%', fontSize: '.8rem' }}>
              <tbody>
                {job.history.map((h, i) => (
                  <tr key={i}>
                    <td style={{ width: 70 }}><span style={{ color: h.ok ? 'var(--green)' : 'var(--red)' }}>{h.ok ? 'ok' : 'failed'}</span></td>
                    <td style={{ width: 200 }} title={h.finished_at}>{serverDate(h.finished_at).toLocaleString()}</td>
                    <td style={{ width: 80 }}>{duration(h.duration_ms)}</td>
                    <td style={{ color: 'var(--dim)' }}>{h.error || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </td>
        </tr>
      )}
    </>
  )
}

export function JobHealth() {
  const [jobs, setJobs] = useState<Job[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loadedAt, setLoadedAt] = useState<Date | null>(null)

  const load = useCallback(() => {
    adminApi.get<{ jobs: Job[] }>('/api/settings/job-health')
      .then(r => { setJobs(r.jobs); setError(null); setLoadedAt(new Date()) })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [load])

  async function runNow(id: string) {
    try {
      await adminApi.post(`/api/settings/job-health/${encodeURIComponent(id)}/run`)
      setTimeout(load, 1500)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const sorted = jobs ? [...jobs].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status)) : []
  const unhealthy = sorted.filter(j => j.status === 'failing' || j.status === 'late' || j.status === 'warning').length

  return (
    <div>
      <h3>Job Health</h3>
      <p className="settings-hint">
        AppCrane's background jobs: when each last ran, when the next run is expected, and whether it worked.
        A job is <b>late</b> when it has not run within its expected window, and <b>failing</b> when its last run failed.
        Platform admins are e-mailed once a day per job when it turns failing or late. Refreshes every 30 seconds.
      </p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      {jobs === null && !error && <p style={{ color: 'var(--dim)' }}>Loading...</p>}
      {jobs && (
        <>
          <p style={{ fontWeight: 600, color: unhealthy ? 'var(--red)' : 'var(--green)' }}>
            {unhealthy ? `${unhealthy} job(s) need attention` : 'All running jobs are healthy'}
            {loadedAt && <span style={{ color: 'var(--dim)', fontWeight: 400 }}> | updated {loadedAt.toLocaleTimeString()}</span>}
          </p>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                <th style={{ padding: '6px' }}>Status</th>
                <th style={{ padding: '6px' }}>Job</th>
                <th style={{ padding: '6px' }}>Last run</th>
                <th style={{ padding: '6px' }}>Next expected</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sorted.map(j => <JobRow key={j.id} job={j} onRun={runNow} />)}
            </tbody>
          </table>
        </>
      )}
      <HostLimitsCard />
    </div>
  )
}
