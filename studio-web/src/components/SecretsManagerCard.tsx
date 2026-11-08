import { useEffect, useState, type CSSProperties } from 'react'
import { loadSecretsProviderStatus, type SecretsProviderStatus } from './env/envVarsApi'

// Read-only: the provider is set in .env, so this card has no write controls.
// The status endpoint is platform admin only; anyone else sees no card.

const dim: CSSProperties = { color: 'var(--dim)', fontSize: '.8rem' }

const row = (label: string, value: string) => (
  <tr key={label}>
    <td style={{ ...dim, padding: '2px 16px 2px 0' }}>{label}</td>
    <td style={{ fontSize: '.8rem', padding: '2px 0' }}>{value}</td>
  </tr>
)

export function SecretsManagerCard() {
  const [s, setS] = useState<SecretsProviderStatus | null>(null)

  useEffect(() => {
    loadSecretsProviderStatus().then(setS).catch(() => setS(null))
  }, [])

  if (!s) return null

  return (
    <div className="card" data-secrets-manager-card>
      <h3>Secrets Manager</h3>
      <table style={{ borderCollapse: 'collapse', margin: '8px 0' }}>
        <tbody>
          {row('Status', s.active ? 'On' : 'Off')}
          {s.active && row('Region', s.region || 'AWS SDK default')}
          {row('Platform keys', s.platform_secret_configured ? 'Loaded from Secrets Manager' : 'Not loaded from Secrets Manager')}
          {s.active && s.app_prefix && row('App secret path', `${s.app_prefix}/<app namespace>/<environment>/<name>`)}
        </tbody>
      </table>
      {!s.active && (
        <p style={{ ...dim, margin: 0 }}>
          Run <code>crane secrets migrate</code> on this server to move AppCrane's keys out of .env and into AWS Secrets Manager.
        </p>
      )}
    </div>
  )
}
