import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { useJobsList } from '../../hooks/useJobsList'

interface Props {
  slug: string | null | undefined
}

const STATUS_LABELS: Record<string, string> = {
  new: 'New',
  selected: 'Queued for review',
  planning: 'Generating plan…',
  pending_user_review_plan: 'Plan ready — review needed',
  plan_approved: 'Coding queued',
  coding: 'Writing code…',
  pushing: 'Pushed to GitHub ✓',
  building: 'Building sandbox…',
  sandbox_ready: 'Sandbox ready ✓',
  done: 'Done',
  merged: 'Merged',
  auto_failed: 'Failed',
}

const RUNNING_STATES = new Set([
  'planning', 'pending_user_review_plan', 'plan_approved',
  'coding', 'building',
])

function statusClass(status: string): string {
  if (RUNNING_STATES.has(status)) return 'job-status-running'
  if (status === 'done' || status === 'merged') return ''
  return 'job-status-queued'
}

export function JobsButton({ slug }: Props) {
  const [open, setOpen] = useState(false)
  const jobs = useJobsList(slug, open)

  async function deleteRequest(id: number) {
    if (!confirm('Delete this enhancement request?')) return
    try {
      await adminApi.post(`/api/enhancements/${id}/delete`)
      jobs.refresh()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Delete failed')
    }
  }

  const badgeText = jobs.activeCount > 0 ? String(jobs.activeCount) : ''

  return (
    <div className="jobs-wrap">
      <button
        type="button"
        className={'crane-topbar-btn jobs-btn' + (open ? ' active' : '')}
        onClick={() => setOpen(o => !o)}
        title="Active jobs and your enhancement requests"
      >
        📋 Jobs
        {badgeText && <span className="jobs-badge has-jobs">{badgeText}</span>}
      </button>
      {open && (
        <div className="jobs-panel open">
          <div className="jobs-panel-header">
            <span>Jobs &amp; requests</span>
            <button className="jobs-panel-close" onClick={() => setOpen(false)} title="Close">×</button>
          </div>
          <div className="jobs-list">
            {jobs.active_jobs.length > 0 && (
              <>
                <div className="jobs-section-hdr">Active (all users)</div>
                {jobs.active_jobs.map(j => (
                  <div className="job-row" key={`active-${j.id}`}>
                    <div className="job-row-top">
                      <span className="job-slug">{j.app_slug || ''}</span>
                      <span className="job-phase">{j.phase || ''}</span>
                      <span className={statusClass(j.status)}>
                        {STATUS_LABELS[j.status] || j.status}
                      </span>
                      <span className="job-id">#{String(j.id).padStart(4, '0')}</span>
                    </div>
                    <div className="job-msg">{j.enhancement_message || ''}</div>
                  </div>
                ))}
              </>
            )}

            {jobs.my_requests.length > 0 && (
              <>
                <div className="jobs-section-hdr" style={{ marginTop: 4 }}>My requests</div>
                {jobs.my_requests.map(r => {
                  const cls = statusClass(r.status)
                  const jobActive = r.job_status === 'queued' || r.job_status === 'running'
                  return (
                    <div className="job-row" key={`my-${r.id}`}>
                      <div className="job-row-top">
                        <span className="job-slug">{r.app_slug || ''}</span>
                        <span className="job-phase">{r.phase || ''}</span>
                        <span className={cls}>{STATUS_LABELS[r.status] || r.status}</span>
                        {r.job_id && <span className="job-id">#{String(r.job_id).padStart(4, '0')}</span>}
                        <button
                          type="button"
                          className="job-del"
                          onClick={() => deleteRequest(r.id)}
                          disabled={jobActive}
                          title={jobActive ? 'Cannot delete — a job is running' : 'Delete this request'}
                        >✕</button>
                      </div>
                      <div className="job-msg">{r.message}</div>
                    </div>
                  )
                })}
              </>
            )}

            {jobs.app_requests.length > 0 && (
              <>
                <div className="jobs-section-hdr" style={{ marginTop: 4 }}>
                  {(slug ?? '') + ' — Requests'}
                </div>
                {jobs.app_requests.map(r => (
                  <div className="job-row" key={`app-${r.id}`}>
                    <div className="job-row-top">
                      <span className="job-slug">{r.user_name || ''}</span>
                      <span className="job-phase">{r.phase || ''}</span>
                      <span className={statusClass(r.status)}>
                        {STATUS_LABELS[r.status] || r.status}
                      </span>
                      <span className="job-id">#{String(r.id).padStart(4, '0')}</span>
                    </div>
                    <div className="job-msg">{r.message}</div>
                  </div>
                ))}
              </>
            )}

            {!jobs.active_jobs.length && !jobs.my_requests.length && !jobs.app_requests.length && (
              <div className="jobs-empty">No requests yet</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
