import { useState } from 'react'
import { QrCode } from './QrCode'

export interface EnrollmentStart { secret: string; algorithm: 'SHA1' | 'SHA256'; otpauth_uri: string }

// Scan (or type) the secret, then prove it with one code. Used by the sign-in
// screen's forced enrollment and by Settings -> Account.
export function EnrollPanel({ start, onConfirm, busy, error }: {
  start: EnrollmentStart
  onConfirm: (code: string) => void
  busy?: boolean
  error?: string
}) {
  const [code, setCode] = useState('')
  const grouped = start.secret.replace(/(.{4})/g, '$1 ').trim()
  return (
    <div>
      <p style={{ fontSize: '.85rem', margin: '0 0 10px' }}>
        Scan this with an authenticator app (any TOTP app), then enter the 6-digit code it shows.
      </p>
      <div style={{ display: 'flex', justifyContent: 'center', margin: '8px 0' }}>
        <QrCode value={start.otpauth_uri} />
      </div>
      <details style={{ fontSize: '.78rem', color: 'var(--dim)', margin: '6px 0 10px' }}>
        <summary>Can't scan? Enter the key instead</summary>
        <code style={{ display: 'block', marginTop: 6, wordBreak: 'break-all', fontSize: '.85rem' }}>{grouped}</code>
        <span>Time-based, 6 digits, 30 seconds, {start.algorithm === 'SHA256' ? 'SHA-256' : 'SHA-1'}.</span>
      </details>
      {error && <div className="login-error">{error}</div>}
      <form onSubmit={e => { e.preventDefault(); if (code.trim()) onConfirm(code.trim()) }}>
        <input
          type="text" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" maxLength={6}
          value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} autoFocus
          style={{ width: '100%', marginBottom: 10, letterSpacing: 4, textAlign: 'center', fontSize: '1.1rem' }}
        />
        <button className="btn btn-accent" type="submit" disabled={busy || code.length !== 6} style={{ width: '100%', padding: 10 }}>
          {busy ? 'Checking...' : 'Turn on two-factor sign-in'}
        </button>
      </form>
    </div>
  )
}
