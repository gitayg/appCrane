import { useState } from 'react'
import { adminApi } from '../adminApi'

// v2.21.5: submit a request against the AppCrane platform itself (not a
// specific app). Posts to /api/enhancements with the reserved '_platform'
// slug; those requests are visible only to platform admins.
export function PlatformRequestBar() {
  const [open, setOpen] = useState(false)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  async function submit() {
    if (!msg.trim() || busy) return
    setBusy(true)
    try {
      await adminApi.post('/api/enhancements', { message: msg.trim(), app_slug: '_platform' })
      setMsg(''); setOpen(false); setDone(true)
      setTimeout(() => setDone(false), 5000)
    } catch (e) {
      alert('Could not submit: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="platform-req-bar">
      {!open ? (
        <button className="btn" onClick={() => setOpen(true)}>💡 Request an AppCrane platform feature</button>
      ) : (
        <div className="platform-req-form">
          <textarea
            className="ask-textarea"
            value={msg}
            onChange={e => setMsg(e.target.value)}
            placeholder="Describe an improvement or feature for AppCrane itself — visible to platform admins only…"
            rows={3}
            autoFocus
          />
          <div className="platform-req-actions">
            <button className="btn" onClick={() => { setOpen(false); setMsg('') }}>Cancel</button>
            <button className="btn btn-accent" onClick={submit} disabled={busy || !msg.trim()}>
              {busy ? 'Sending…' : 'Submit'}
            </button>
          </div>
        </div>
      )}
      {done && <span className="platform-req-done">✓ Thanks — your platform request was sent.</span>}
    </div>
  )
}
