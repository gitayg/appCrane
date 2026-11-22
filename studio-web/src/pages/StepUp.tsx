import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// /step-up. Two ways in:
//  ?h=<handle>              a hosted app sent the person here to re-authenticate;
//                           the server holds the validated return URL.
//  ?grant=<action>&app=<s>  an agent or API key was refused an action that
//                           needs a person; confirming grants it for a few minutes.
// Either way the server answers STEP_UP_REQUIRED first, and adminApi's
// StepUpModal does the confirming.

type Described = { app?: string; name?: string; env?: string; return_url?: string }

const ACTION_LABELS: Record<string, string> = {
  reveal_production_secret: 'reveal production secrets',
  delete_app: 'delete the app',
  security_settings: 'change sign-in, SSO, SCIM or security settings',
  grant_platform_admin: 'grant platform admin',
  approve_capability_request: 'approve capability requests',
  disable_mfa: "turn off a user's two-factor sign-in",
}

export function StepUp() {
  const q = new URLSearchParams(window.location.search)
  const handle = q.get('h')
  const grant = q.get('grant')
  const slug = q.get('app')
  const [described, setDescribed] = useState<Described | null>(null)
  const [msg, setMsg] = useState('')
  const [done, setDone] = useState('')

  useEffect(() => {
    if (!handle) return
    adminApi.post<Described>('/api/identity/step-up/app/describe', { h: handle })
      .then(setDescribed).catch((e) => setMsg((e as Error).message))
  }, [handle])

  const backToApp = async () => {
    setMsg('')
    try {
      const r = await adminApi.post<{ return_url: string }>('/api/identity/step-up/app/complete', { h: handle })
      window.location.assign(r.return_url)
    } catch (e) {
      setMsg((e as Error).message)
    }
  }

  const allow = async () => {
    setMsg('')
    try {
      const r = await adminApi.post<{ expires_at: string; minutes: number }>('/api/identity/step-up/grants', { action: grant, ...(slug && { slug }) })
      setDone(`Allowed for ${r.minutes} minutes. Go back to your agent or script and retry.`)
    } catch (e) {
      setMsg((e as Error).message)
    }
  }

  return (
    <div style={{ maxWidth: 520, margin: '48px auto', padding: '0 16px' }}>
      <div className="setting-card">
        <h3>Confirm it's you</h3>
        {handle && (
          <>
            <p style={{ fontSize: '.9rem' }}>
              {described?.name || described?.app || 'An app'} asked you to confirm it's you before it continues.
            </p>
            <button className="btn btn-accent" onClick={backToApp} disabled={!described}>Confirm and go back</button>
          </>
        )}
        {grant && (
          <>
            <p style={{ fontSize: '.9rem' }}>
              Your agent or API key asked to {ACTION_LABELS[grant] || grant}{slug ? ` on ${slug}` : ''}. That needs a person.
              Allow it only if you started this.
            </p>
            {done
              ? <p role="status" style={{ fontSize: '.9rem' }}>{done}</p>
              : <button className="btn btn-accent" onClick={allow}>Confirm and allow</button>}
          </>
        )}
        {!handle && !grant && <p style={{ fontSize: '.9rem' }}>Nothing to confirm.</p>}
        {msg && <p role="alert" style={{ color: 'var(--danger, #ef4444)', fontSize: '.85rem' }}>{msg}</p>}
      </div>
    </div>
  )
}
