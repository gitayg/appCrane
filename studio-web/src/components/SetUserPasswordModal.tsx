import { useState } from 'react'
import { adminApi } from '../adminApi'
import { PasswordInput } from './secret/PasswordInput'

// A platform admin sets another user's password (PUT /api/users/:id/password).
// The server enforces the 12-character minimum and signs the user out
// everywhere; its refusal is shown in its own words.

const MIN_LENGTH = 12

const labelStyle: React.CSSProperties = { fontSize: '.78rem', color: 'var(--dim)', marginBottom: 4, display: 'block' }

export function SetUserPasswordModal({ user, onClose, onSaved }: {
  user: { id: number; name: string }
  onClose: () => void
  onSaved: () => void
}) {
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const done = msg?.ok === true

  async function save() {
    if (busy || done) return
    if (pw.length < MIN_LENGTH) { setMsg({ ok: false, text: `The password must be at least ${MIN_LENGTH} characters.` }); return }
    if (pw !== confirm) { setMsg({ ok: false, text: 'The password and its confirmation do not match.' }); return }
    setBusy(true)
    setMsg(null)
    try {
      await adminApi.put(`/api/users/${user.id}/password`, { password: pw })
      setPw('')
      setConfirm('')
      setMsg({ ok: true, text: `Password set for ${user.name}; their sessions were signed out.` })
      onSaved()
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Could not set the password' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
      }}
    >
      <form
        role="dialog"
        aria-label={`Set password for ${user.name}`}
        onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); save() }}
        style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 12, padding: 24, maxWidth: 420, width: '94%',
          boxShadow: '0 24px 64px rgba(0,0,0,.5)',
        }}
      >
        <h3 style={{ margin: '0 0 6px', fontSize: '1.05rem' }}>Set password for {user.name}</h3>
        <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 16 }}>
          At least {MIN_LENGTH} characters. Every session this user has is signed out.
        </p>
        {!done && (
          <>
            <div style={{ marginBottom: 12 }}>
              <label style={labelStyle}>New password</label>
              <PasswordInput styled label="new password" autoComplete="new-password" autoFocus
                value={pw} onChange={e => setPw(e.target.value)} disabled={busy} />
            </div>
            <div style={{ marginBottom: 12 }}>
              <label style={labelStyle}>Confirm password</label>
              <PasswordInput styled label="confirm password" autoComplete="new-password"
                value={confirm} onChange={e => setConfirm(e.target.value)} disabled={busy} />
            </div>
          </>
        )}
        {msg && (
          <p role={msg.ok ? 'status' : 'alert'} style={{ fontSize: '.85rem', color: msg.ok ? 'var(--green)' : 'var(--red)', margin: '0 0 12px' }}>
            {msg.text}
          </p>
        )}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" className="btn" onClick={onClose}>{done ? 'Close' : 'Cancel'}</button>
          {!done && (
            <button type="submit" className="btn btn-accent" disabled={busy || !pw || !confirm}>
              {busy ? 'Saving…' : 'Set password'}
            </button>
          )}
        </div>
      </form>
    </div>
  )
}
