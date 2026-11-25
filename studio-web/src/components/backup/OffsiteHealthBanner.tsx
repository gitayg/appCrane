// Settings > Backup: the same verdict Job Health records as
// 'platform-backup-offsite', in the server's own words (backupScheduler.js
// offSiteHealth). Red whenever no off-site destination is configured or the
// last successful upload is older than the limit; orange while the off-site
// copy is fine but the recovery key for the current key was never downloaded.

export type OffsiteHealth = {
  ok: boolean
  severity?: 'ok' | 'warning' | 'failing'
  reason: string
  message: string
  fix?: string | null
  warnings?: string[]
  last_success_at: string | null
  age_hours: number | null
  max_age_hours: number
}

export function OffsiteHealthBanner({ health }: { health?: OffsiteHealth }) {
  if (!health) return null
  const warning = health.ok && (health.severity === 'warning' || (health.warnings || []).length > 0)
  const color = !health.ok ? 'var(--red)' : warning ? 'var(--orange)' : 'var(--green)'
  const title = !health.ok ? 'FAILING' : warning ? 'WARNING' : 'OK'
  return (
    <div role={health.ok && !warning ? 'status' : 'alert'} style={{
      margin: '8px 0 14px', padding: '10px 12px', borderRadius: 6,
      border: `1px solid ${color}`, background: `color-mix(in srgb, ${color} 12%, transparent)`,
    }}>
      <div style={{ fontWeight: 700 }}>Off-site copy of the platform backup: {title}</div>
      <div style={{ marginTop: 4 }}>{health.message}</div>
      {(health.warnings || []).map(w => (
        <div key={w} style={{ marginTop: 4, fontWeight: 600 }}>{w}</div>
      ))}
      {!health.ok && (
        <>
          {health.fix && <pre style={{ marginTop: 6, whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>{health.fix}</pre>}
          <div className="settings-hint" style={{ marginTop: 4 }}>
            Job Health shows this as failing and platform admins get one e-mail a day until it is fixed.
          </div>
        </>
      )}
      {warning && (
        <div className="settings-hint" style={{ marginTop: 4 }}>
          Job Health shows this as a warning until the recovery key below is downloaded.
        </div>
      )}
    </div>
  )
}
