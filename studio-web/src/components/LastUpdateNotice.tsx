import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { isConnectionDrop, waitForNewVersion } from './selfUpdateFlow'

// The outcome of the last AppCrane self-update (GET /api/self-update/status),
// under the version pill: rolled back and why, still being health-checked, or
// updated with a way back to the version it replaced.
interface UpdateStatus {
  current_version: string
  outcome?: 'verifying' | 'updated' | 'rolled_back' | 'failed'
  previous_version?: string
  target_version?: string
  rollback_reason?: string
  rolled_back_at?: string
  db_restored?: boolean
  pending_migrations?: string[]
  rollback_available?: boolean
}

export function LastUpdateNotice() {
  const [status, setStatus] = useState<UpdateStatus | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<UpdateStatus>('/api/self-update/status').then(setStatus).catch(() => {})
  }, [])

  if (!status?.outcome) return null

  async function rollBack() {
    if (!status) return
    const migrations = status.pending_migrations?.length ?? 0
    const ask = `Roll AppCrane back from v${status.current_version} to v${status.previous_version}?\n\n`
      + 'The previous code, dependencies and admin UI are restored and the server restarts.'
      + (migrations ? `\n\nThe update applied ${migrations} database migration(s). The database keeps them; restoring the pre-update snapshot (losing everything written since) is available from the API with restore_db=1.` : '')
    if (!confirm(ask)) return
    setBusy(true)
    try {
      await adminApi.post('/api/self-update/rollback?confirm=1', {})
    } catch (err) {
      if (!isConnectionDrop(err)) {
        alert('Rollback refused: ' + (err instanceof Error ? err.message : String(err)))
        setBusy(false)
        return
      }
    }
    const next = await waitForNewVersion(status.current_version)
    if (next) window.location.reload()
    else { alert('AppCrane has not come back on another version yet; check the server log.'); setBusy(false) }
  }

  if (status.outcome === 'rolled_back') {
    return (
      <div className="sidebar-update-notice sidebar-update-notice-bad" title={status.rollback_reason}>
        Update to v{status.target_version} was rolled back{status.db_restored ? ' (database restored)' : ''}: {status.rollback_reason}
      </div>
    )
  }
  if (status.outcome === 'verifying') {
    return <div className="sidebar-update-notice">Checking that v{status.target_version} is healthy…</div>
  }
  if (status.outcome === 'updated' && status.rollback_available) {
    return (
      <div className="sidebar-update-notice">
        <button type="button" className="btn-link" disabled={busy} onClick={rollBack}>
          {busy ? 'Rolling back…' : `Roll back to v${status.previous_version}`}
        </button>
      </div>
    )
  }
  return null
}
