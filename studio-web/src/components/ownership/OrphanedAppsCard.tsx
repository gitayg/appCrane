import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'
import { REASON_LABEL, ageText, type OrphanedApp } from './types'

// Platform admins: every app without an active owner, oldest first.
export function OrphanedAppsCard() {
  const [apps, setApps] = useState<OrphanedApp[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    adminApi.get<{ apps: OrphanedApp[] }>('/api/admin/orphaned-apps')
      .then(d => setApps(d.apps))
      .catch(e => { if ((e as { status?: number }).status !== 403) setError((e as Error).message) })
  }, [])

  if (error) return <div className="am-card" style={{ color: 'var(--red)' }}>Apps without an owner: {error}</div>
  if (!apps) return null
  return (
    <div className="am-card" style={{ marginBottom: 16 }}>
      <h3 style={{ marginBottom: 6 }}>Apps without an owner ({apps.length})</h3>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 8 }}>
        An app whose last active owner left (deprovisioned, deleted or demoted). It keeps running.
        Open the app to nominate or assign a new owner.
      </div>
      {apps.length === 0 ? <div style={{ color: 'var(--green)' }}>Every app has an owner.</div> : (
        <table style={{ width: '100%', fontSize: '.85rem' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
              <th>App</th><th>Without owner for</th><th>Why</th><th>Detected by</th><th>Nomination</th>
            </tr>
          </thead>
          <tbody>
            {apps.map(a => (
              <tr key={a.orphan_id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: 6 }}><a href={`/app?slug=${encodeURIComponent(a.slug)}`}>{a.name || a.slug}</a></td>
                <td style={{ padding: 6 }} title={serverDate(a.orphaned_at).toLocaleString()}>{ageText(a.age_seconds)}</td>
                <td style={{ padding: 6 }}>{REASON_LABEL[a.detail?.reason || ''] || (a.cause === 'present-at-upgrade' ? 'Already without an owner' : 'No active owner')}</td>
                <td style={{ padding: 6 }}>{a.cause}</td>
                <td style={{ padding: 6 }}>
                  {a.transfer_id
                    ? `Waiting for ${a.nominee_name || a.nominee_email || `#${a.nominee_user_id}`}`
                    : <span style={{ color: 'var(--orange)' }}>None</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
