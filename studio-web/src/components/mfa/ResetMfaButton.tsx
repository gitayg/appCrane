import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// Users page (platform admin): reset a user's two-factor sign-in after a lost
// device. POST /api/identity/mfa/users/:id/reset is audited and e-mails the user.
export function ResetMfaButton({ userId, userName }: { userId: number; userName: string }) {
  const [enrolled, setEnrolled] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => {
    adminApi.get<{ enrolled: boolean }>(`/api/identity/mfa/users/${userId}`).then(r => setEnrolled(r.enrolled)).catch(() => setEnrolled(null))
  }, [userId])

  async function reset() {
    if (!window.confirm(`Reset two-factor sign-in for ${userName}? Their authenticator and recovery codes stop working, and they are e-mailed.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ mailed: boolean }>(`/api/identity/mfa/users/${userId}/reset`)
      setEnrolled(false)
      setMsg(r.mailed ? 'Reset. They were e-mailed.' : 'Reset. They have no e-mail address on file.')
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Reset failed')
    } finally {
      setBusy(false)
    }
  }

  if (!enrolled) return msg ? <span style={{ fontSize: '.78rem', color: 'var(--dim)' }}>{msg}</span> : null
  return <button type="button" className="btn btn-xs" disabled={busy} onClick={reset}>Reset 2FA</button>
}
