import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// Users page (platform admin): forget every device a user ticked "Remember
// this device" on, so their next password sign-in asks for the code again.
// DELETE /api/identity/mfa/users/:id/trusted-devices is audited.
export function ForgetDevicesButton({ userId, userName }: { userId: number; userName: string }) {
  const [count, setCount] = useState(0)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => {
    adminApi.get<{ devices: { active: boolean }[] }>(`/api/identity/mfa/users/${userId}/trusted-devices`)
      .then(r => setCount(r.devices.length)).catch(() => setCount(0))
  }, [userId])

  async function forget() {
    if (!window.confirm(`Forget all ${count} remembered device(s) for ${userName}? Their next password sign-in asks for the code again.`)) return
    setBusy(true)
    try {
      const r = await adminApi.del<{ revoked: number }>(`/api/identity/mfa/users/${userId}/trusted-devices`)
      setCount(0)
      setMsg(`Forgot ${r.revoked} device(s).`)
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  if (!count) return msg ? <span style={{ fontSize: '.78rem', color: 'var(--dim)' }}>{msg}</span> : null
  return <button type="button" className="btn btn-xs" disabled={busy} onClick={forget}>Forget devices</button>
}
