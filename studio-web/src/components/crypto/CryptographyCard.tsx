import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

type Check = { name: string; ok: boolean; detail: string }
type Legacy = { id: string; count: number; detail: string }
export type CryptoStatus = {
  mode: 'off' | 'prefer' | 'require' | 'invalid'
  modeError: string | null
  fipsActive: boolean
  provider: string
  openssl: string
  node: string
  selfCheck: { ok: boolean; md5Available: boolean; checks: Check[] }
  scryptAvailable: boolean
  mariadbKeyFileKdf: string | null
  legacy: Legacy[]
  documentedExceptions: { id: string; detail: string }[]
  claimable: boolean
}

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

export function CryptographyCard() {
  const [s, setS] = useState<CryptoStatus | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    adminApi.get<CryptoStatus>('/api/settings/crypto').then(setS).catch(e => setErr(String(e?.message || e)))
  }, [])
  if (err) return <div className="card"><h3>Cryptography</h3><p style={dim}>{err}</p></div>
  if (!s) return null
  const row = (label: string, value: string, good?: boolean) => (
    <tr>
      <td style={{ ...dim, paddingRight: 14 }}>{label}</td>
      <td style={good === undefined ? undefined : { color: good ? 'var(--green, #2e7d32)' : 'var(--red, #c62828)' }}>{value}</td>
    </tr>
  )
  return (
    <div className="card">
      <h3>Cryptography</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        FIPS 140-3 mode is set by APPCRANE_FIPS (off, prefer, require) and needs a Node built against a validated OpenSSL FIPS provider. See docs/FIPS.md.
      </p>
      <table style={{ borderCollapse: 'collapse', marginBottom: 10 }}>
        <tbody>
          {row('APPCRANE_FIPS', s.modeError ? `invalid: ${s.modeError}` : s.mode)}
          {row('FIPS provider active', s.fipsActive ? 'yes' : 'no', s.fipsActive)}
          {row('Provider', s.provider)}
          {row('OpenSSL', s.openssl)}
          {row('Node', s.node)}
          {row('Self-check', s.selfCheck.ok ? 'passed' : 'FAILED', s.selfCheck.ok)}
          {row('MD5 refused', s.selfCheck.md5Available ? 'no' : 'yes', !s.selfCheck.md5Available)}
          {row('MariaDB key file KDF', s.mariadbKeyFileKdf || 'n/a')}
        </tbody>
      </table>
      {s.selfCheck.checks.some(c => !c.ok) && (
        <ul style={dim}>{s.selfCheck.checks.filter(c => !c.ok).map(c => <li key={c.name}>{c.name}: {c.detail}</li>)}</ul>
      )}
      <h4 style={{ margin: '8px 0 4px' }}>Still on a non-approved algorithm</h4>
      {s.legacy.length === 0
        ? <p style={dim}>Nothing.</p>
        : <ul style={{ margin: 0 }}>{s.legacy.map(l => <li key={l.id}>{l.detail}</li>)}</ul>}
      <h4 style={{ margin: '8px 0 4px' }}>Documented exceptions</h4>
      <ul style={{ ...dim, margin: 0 }}>{s.documentedExceptions.map(x => <li key={x.id}>{x.detail}</li>)}</ul>
      <p style={{ ...dim, marginTop: 10 }}>
        {s.claimable
          ? 'This process runs with a FIPS provider, its self-check passed, and nothing is on a legacy algorithm. Whether the provider is a CMVP-validated module, and whether Caddy, the database images and the host are in FIPS mode, is not visible from here.'
          : 'Do not claim FIPS 140-3 mode for this deployment yet.'}
      </p>
    </div>
  )
}
