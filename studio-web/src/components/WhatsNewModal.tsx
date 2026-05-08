import { useEffect } from 'react'
import { adminApi } from '../adminApi'

export interface WhatsNewChange {
  version:        string | null
  commit_hash:    string | null
  commit_message: string | null
  finished_at:    string | null
}

interface Props {
  slug:           string
  appName:        string
  currentVersion: string | null
  changes:        WhatsNewChange[]
  onClose:        () => void
}

/**
 * Modal that surfaces the deployments a user has missed since they last
 * opened a given app. Shown when GET /api/apps/:slug/whats-new returns a
 * non-empty `changes` array — see WhatsNewProbe below for the trigger.
 *
 * Dismissing the modal POSTs to /whats-new/seen which records the current
 * live version; on the next open the same version no longer triggers it.
 */
export function WhatsNewModal({ slug, appName, currentVersion, changes, onClose }: Props) {
  function dismiss() {
    adminApi.post(`/api/apps/${encodeURIComponent(slug)}/whats-new/seen`, {}).catch(() => {})
    onClose()
  }

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') dismiss() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="whatsnew-overlay" onClick={dismiss}>
      <div className="whatsnew-modal" onClick={e => e.stopPropagation()} role="dialog" aria-label="What's new">
        <div className="whatsnew-header">
          <span className="whatsnew-title">✨ What's new in {appName}</span>
          {currentVersion && <span className="whatsnew-version">v{currentVersion}</span>}
          <button className="whatsnew-close" onClick={dismiss} aria-label="Close">×</button>
        </div>
        <div className="whatsnew-body">
          {changes.length === 0 ? (
            <div style={{ padding: 12, color: 'var(--dim)' }}>You're up to date.</div>
          ) : (
            <ul className="whatsnew-list">
              {changes.map((c, i) => (
                <li key={`${c.version || 'x'}-${i}`} className="whatsnew-item">
                  <div className="whatsnew-item-head">
                    {c.version && <span className="whatsnew-item-ver">v{c.version}</span>}
                    {c.finished_at && (
                      <span className="whatsnew-item-date">{c.finished_at.replace('T', ' ').slice(0, 16)}</span>
                    )}
                    {c.commit_hash && (
                      <span className="whatsnew-item-sha">{c.commit_hash.slice(0, 7)}</span>
                    )}
                  </div>
                  {c.commit_message && (
                    <div className="whatsnew-item-msg">{c.commit_message}</div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="whatsnew-footer">
          <button className="btn btn-accent" onClick={dismiss}>Got it</button>
        </div>
      </div>
    </div>
  )
}
