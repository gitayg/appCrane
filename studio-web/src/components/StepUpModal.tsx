import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { PasswordInput } from './secret/PasswordInput'
import { onStepUpRequest, StepUpCancelled, type StepUpMethod } from '../stepUp'

// The dialog behind adminApi's STEP_UP_REQUIRED retry. One factor, the
// strongest the person has (the server decides): their authenticator code, a
// fresh sign-in at their identity provider in a popup, or their password.

type Pending = Parameters<Parameters<typeof onStepUpRequest>[0]>[0]

const SSO_CHANNEL = 'appcrane-sso'

export function StepUpModal() {
  const [pending, setPending] = useState<Pending>(null)
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => onStepUpRequest((p) => { setPending(p); setValue(''); setMsg(''); setBusy(false) }), [])

  if (!pending) return null
  const method: StepUpMethod | undefined = pending.hint.methods?.[0]
  const minutes = pending.hint.window_minutes ?? 10

  const submit = async (e?: React.FormEvent) => {
    e?.preventDefault()
    if (!method) return
    setBusy(true)
    setMsg('')
    try {
      if (method === 'totp') await adminApi.post('/api/identity/step-up/totp', { code: value.trim() })
      else if (method === 'password') await adminApi.post('/api/identity/step-up/password', { password: value })
      else await ssoStepUp()
      pending.resolve()
    } catch (err) {
      setMsg((err as Error).message)
      setBusy(false)
    }
  }

  const cancel = () => pending.reject(new StepUpCancelled())

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="step-up-title" style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)', zIndex: 10001,
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
    }}>
      <form className="setting-card" onSubmit={submit} style={{ maxWidth: 400, width: '100%', background: 'var(--bg, #1a1d27)' }}>
        <h3 id="step-up-title">Confirm it's you</h3>
        <p style={{ fontSize: '.9rem' }}>
          This needs a recent sign-in. Once you confirm, you will not be asked again for {minutes} minutes.
        </p>
        {method === 'totp' && (
          <input className="input" inputMode="numeric" autoComplete="one-time-code" autoFocus
            placeholder="6-digit code or a recovery code" aria-label="Authenticator code"
            value={value} onChange={(e) => setValue(e.target.value)} />
        )}
        {method === 'password' && (
          <PasswordInput styled label="password" autoComplete="current-password" autoFocus
            placeholder="Your password" value={value} onChange={(e) => setValue(e.target.value)} />
        )}
        {(method === 'oidc' || method === 'saml') && (
          <p style={{ fontSize: '.9rem' }}>Your identity provider will ask you to sign in again in a new window.</p>
        )}
        {!method && (
          <p style={{ fontSize: '.9rem' }}>
            Your account has no way to confirm it's you. Turn on two-factor sign-in in Settings, then try again.
          </p>
        )}
        {msg && <p role="alert" style={{ color: 'var(--danger, #ef4444)', fontSize: '.85rem' }}>{msg}</p>}
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          {method && (
            <button className="btn btn-accent" type="submit" disabled={busy || ((method === 'totp' || method === 'password') && !value)}>
              {method === 'oidc' || method === 'saml' ? 'Sign in again' : 'Confirm'}
            </button>
          )}
          <button className="btn" type="button" onClick={cancel} disabled={busy && method !== 'oidc' && method !== 'saml'}>Cancel</button>
        </div>
      </form>
    </div>
  )
}

// Opens the IdP re-login in a popup and waits for the completion page's
// BroadcastChannel message (utils/ssoPopup.js), then checks the server agrees.
async function ssoStepUp(): Promise<void> {
  const popup = window.open('about:blank', 'appcrane-step-up', 'width=520,height=680')
  const { url } = await adminApi.post<{ url: string }>('/api/identity/step-up/sso', {})
  if (!popup) {
    throw new Error('Allow pop-ups for this site, then try again.')
  }
  popup.location.href = url
  await new Promise<void>((resolve, reject) => {
    let ch: BroadcastChannel | null = null
    const timer = window.setInterval(() => { if (popup.closed) finish(new Error('The sign-in window was closed.')) }, 800)
    function finish(err?: Error) {
      window.clearInterval(timer)
      ch?.close()
      if (err) reject(err); else resolve()
    }
    try {
      ch = new BroadcastChannel(SSO_CHANNEL)
      ch.onmessage = (e) => {
        if (e.data?.type === 'signed-in') finish()
        else if (e.data?.type === 'sign-in-failed') finish(new Error('Your identity provider did not confirm it was you.'))
      }
    } catch (_) { /* fall back to the closed-window check */ }
  })
  const s = await adminApi.get<{ fresh: boolean }>('/api/identity/step-up')
  if (!s.fresh) throw new Error('Your identity provider did not confirm it was you.')
}
