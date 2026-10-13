import { formatAge, type BuildsInFlight } from './selfUpdateFlow'

interface Props {
  blocked: BuildsInFlight
  onWait: () => void
  onForce: () => void
  onClose: () => void
}

// Shown when self-update is refused because deployments are still running.
// Before this, the refusal surfaced as a raw alert with no way to override it,
// so a single hung build blocked every update until someone hand-wrote a
// forced POST in the browser console.
export function UpdateBlockedDialog({ blocked, onWait, onForce, onClose }: Props) {
  const n = blocked.inFlight.length
  return (
    <div className="whatsnew-overlay" onClick={onClose}>
      <div className="whatsnew-modal" onClick={e => e.stopPropagation()} role="dialog" aria-label="Update waiting on deployments">
        <div className="whatsnew-header">
          <span className="whatsnew-title">Update waiting on {n} deployment{n === 1 ? '' : 's'}</span>
          <button className="whatsnew-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="whatsnew-body">
          <ul className="whatsnew-list">
            {blocked.inFlight.map(d => (
              <li key={d.id} className="whatsnew-item">
                <div className="whatsnew-item-head">
                  <span className="whatsnew-item-ver">{d.app_name || d.app_slug || `app #${d.app_id}`}</span>
                  <span className="whatsnew-item-date">{d.env} · {d.status} · running {formatAge(d.age_seconds)}</span>
                </div>
              </li>
            ))}
          </ul>
          {blocked.stale.length > 0 && (
            <div style={{ padding: '8px 12px', color: 'var(--dim)', fontSize: 12 }}>
              Not waiting on {blocked.stale.length} stale deployment{blocked.stale.length === 1 ? '' : 's'} (in progress
              longer than {blocked.staleAfterMinutes ?? 60} min):{' '}
              {blocked.stale.map(d => `${d.app_name || d.app_slug} (${d.env}, ${formatAge(d.age_seconds)})`).join(', ')}
            </div>
          )}
          <div style={{ padding: '8px 12px', color: 'var(--dim)', fontSize: 12 }}>
            Force update interrupts these builds; those apps will need redeploying.
          </div>
        </div>
        <div className="whatsnew-footer">
          <button className="btn" onClick={onWait} title="Close and start the update automatically once these finish (re-checks every 30 s)">Wait</button>
          <button className="btn btn-danger" onClick={onForce}>Force update</button>
        </div>
      </div>
    </div>
  )
}
