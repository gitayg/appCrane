import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import { EnrollPanel, type EnrollmentStart } from './EnrollPanel'
import { RecoveryCodes } from './RecoveryCodes'

// Settings -> Account: the signed-in person's own two-factor sign-in for
// password logins. Backed by /api/identity/mfa/* (server/routes/mfa.js).
// SSO accounts get their MFA from the identity provider, so there is nothing
// to manage here for them.

export interface MfaStatus {
  enrolled: boolean
  algorithm: 'SHA1' | 'SHA256' | null
  enabled_at: string | null
  recovery_codes_remaining: number
  required: boolean
  required_level: 'off' | 'admins' | 'everyone'
  has_password: boolean
}

type Mode = 'idle' | 'password' | 'enroll' | 'codes' | 'disable' | 'regen'

const labelStyle: React.CSSProperties = { fontSize: '.78rem', color: 'var(--dim)', marginBottom: 4, display: 'block' }

export function TwoFactorCard() {
  const [status, setStatus] = useState<MfaStatus | null>(null)
  const [mode, setMode] = useState<Mode>('idle')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [algorithm, setAlgorithm] = useState<'SHA1' | 'SHA256'>('SHA1')
  const [start, setStart] = useState<EnrollmentStart | null>(null)
  const [codes, setCodes] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const load = () => adminApi.get<MfaStatus>('/api/identity/mfa/status').then(setStatus)
    .catch(e => setMsg({ ok: false, text: e instanceof Error ? e.message : 'Could not read two-factor status' }))
  useEffect(() => { load() }, [])

  function reset(next: Mode = 'idle') {
    setMode(next); setPassword(''); setCode(''); setStart(null); setMsg(null)
  }

  async function run<T>(fn: () => Promise<T>, after: (r: T) => void) {
    setBusy(true)
    setMsg(null)
    try { after(await fn()) } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : 'Request failed' }) } finally { setBusy(false) }
  }

  const beginSetup = () => run(
    () => adminApi.post<EnrollmentStart>('/api/identity/mfa/setup', { password, algorithm, ...(status?.enrolled ? { current_code: code } : {}) }),
    r => { setStart(r); setMode('enroll'); setPassword(''); setCode('') },
  )
  const confirm = (c: string) => run(
    () => adminApi.post<{ recovery_codes: string[] }>('/api/identity/mfa/activate', { code: c }),
    r => { setCodes(r.recovery_codes); setMode('codes'); setStart(null); load() },
  )
  const disable = () => run(
    () => adminApi.post('/api/identity/mfa/disable', { password, code }),
    () => { reset(); setMsg({ ok: true, text: 'Two-factor sign-in is off.' }); load() },
  )
  const regen = () => run(
    () => adminApi.post<{ recovery_codes: string[] }>('/api/identity/mfa/recovery-codes', { code }),
    r => { setCodes(r.recovery_codes); setMode('codes'); setCode(''); load() },
  )

  const codeInput = (
    <>
      <label style={labelStyle}>Code from your authenticator app, or a recovery code</label>
      <input type="text" autoComplete="one-time-code" value={code} onChange={e => setCode(e.target.value)}
        style={{ width: '100%', marginBottom: 8, fontFamily: 'monospace' }} />
    </>
  )
  const passwordInput = status?.has_password ? (
    <>
      <label style={labelStyle}>Current password</label>
      <PasswordInput label="current password" value={password} onChange={e => setPassword(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
    </>
  ) : null

  return (
    <div className="setting-card">
      <h3>Two-factor sign-in</h3>
      {!status && !msg && <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>Loading...</p>}
      {status && !status.has_password && !status.enrolled && (
        <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
          You sign in with single sign-on, so your identity provider handles two-factor sign-in.
          This applies only if you later set a password here.
        </p>
      )}
      {status && (status.has_password || status.enrolled) && (
        <>
          <p style={{ fontSize: '.85rem' }}>
            {status.enrolled
              ? <>On since {status.enabled_at?.slice(0, 10)} ({status.algorithm === 'SHA256' ? 'SHA-256' : 'SHA-1'}). {status.recovery_codes_remaining} recovery code(s) left.</>
              : 'Off. Password sign-ins ask only for your password.'}
            {status.required && ' Required for your account on this instance.'}
          </p>
          <p style={{ color: 'var(--dim)', fontSize: '.78rem' }}>
            Applies to password sign-in. Single sign-on and API keys are not affected.
          </p>

          {mode === 'idle' && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button className="btn btn-accent" onClick={() => reset('password')}>{status.enrolled ? 'Move to a new device' : 'Turn on'}</button>
              {status.enrolled && <button className="btn" onClick={() => reset('regen')}>New recovery codes</button>}
              {status.enrolled && !status.required && <button className="btn" onClick={() => reset('disable')}>Turn off</button>}
            </div>
          )}

          {mode === 'password' && (
            <form onSubmit={e => { e.preventDefault(); beginSetup() }}>
              {passwordInput}
              {status.enrolled && codeInput}
              <label style={labelStyle}>Algorithm</label>
              <select value={algorithm} onChange={e => setAlgorithm(e.target.value as 'SHA1' | 'SHA256')} style={{ marginBottom: 10 }}>
                <option value="SHA1">SHA-1 (works with every authenticator app)</option>
                <option value="SHA256">SHA-256 (only apps that support it)</option>
              </select>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-accent" type="submit" disabled={busy}>Continue</button>
                <button className="btn" type="button" onClick={() => reset()}>Cancel</button>
              </div>
            </form>
          )}

          {mode === 'enroll' && start && (
            <>
              <EnrollPanel start={start} onConfirm={confirm} busy={busy} />
              <button className="btn" type="button" onClick={() => reset()} style={{ marginTop: 8 }}>Cancel</button>
            </>
          )}

          {mode === 'codes' && <RecoveryCodes codes={codes} onDone={() => { setCodes([]); reset() }} />}

          {mode === 'disable' && (
            <form onSubmit={e => { e.preventDefault(); disable() }}>
              {passwordInput}
              {codeInput}
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn" type="submit" disabled={busy || !code}>Turn off two-factor sign-in</button>
                <button className="btn" type="button" onClick={() => reset()}>Cancel</button>
              </div>
            </form>
          )}

          {mode === 'regen' && (
            <form onSubmit={e => { e.preventDefault(); regen() }}>
              {codeInput}
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-accent" type="submit" disabled={busy || !code}>Replace recovery codes</button>
                <button className="btn" type="button" onClick={() => reset()}>Cancel</button>
              </div>
            </form>
          )}
        </>
      )}
      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.85rem', marginTop: 8 }}>{msg.text}</p>}
    </div>
  )
}
