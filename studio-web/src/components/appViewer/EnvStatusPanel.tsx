import { statusHeadline, type EnvStatus } from './envStatus'

interface Props {
  env: string
  status: EnvStatus
  /** The frame loaded AppCrane's "unavailable" page instead of the app. */
  frameFailed?: boolean
  manageUrl?: string
  onRetry: () => void
  onOpenAnyway: () => void
}

/** Shown in place of the app's iframe while its environment is down or restarting. */
export function EnvStatusPanel({ env, status, frameFailed, manageUrl, onRetry, onOpenAnyway }: Props) {
  const headline = frameFailed && !status.block
    ? statusHeadline(env, { ...status, phase: 'unknown' })
    : statusHeadline(env, status)
  return (
    <div className="lstage-empty" role="status" aria-live="polite">
      <div className="lstage-empty-inner" style={{ maxWidth: 460, padding: '0 16px' }}>
        <div className="lstage-empty-glyph">{status.phase === 'down' ? '⏸' : '↻'}</div>
        <h3>{headline}</h3>
        <p>
          {status.nextCheckSec != null
            ? `AppCrane checks it again in about ${status.nextCheckSec}s and opens the app here as soon as it answers.`
            : 'AppCrane opens the app here as soon as it answers.'}
        </p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 14, flexWrap: 'wrap' }}>
          <button type="button" className="btn btn-primary btn-sm" onClick={onRetry}>Check now</button>
          <button type="button" className="btn btn-sm" onClick={onOpenAnyway}>Open anyway</button>
          {manageUrl && <a className="btn btn-sm" href={manageUrl}>Logs and restarts</a>}
        </div>
      </div>
    </div>
  )
}

/** A thin notice above an app that is up but has been restarting. */
export function EnvUnstableBanner({ env, status }: { env: string; status: EnvStatus }) {
  return (
    <div className="env-notice" role="status" style={{ position: 'static', margin: 0, borderRadius: 0 }}>
      {statusHeadline(env, status)}
    </div>
  )
}
