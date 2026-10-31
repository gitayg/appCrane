import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// Settings -> Security (platform admin): who must use two-factor sign-in for
// password logins, and how long sessions last. GET/PUT /api/identity/mfa/policy.

type Level = 'off' | 'admins' | 'everyone'
interface Tier { absolute: number; idle: number }
interface Policy {
  mfa_required: Level
  sessions: { admin: Tier; user: Tier }
  defaults: { admin: Tier; user: Tier }
  bounds: { absolute: { min: number; max: number }; idle: { min: number; max: number } }
  remember_device_days: number
  remember_device_max_days: number
}

const LEVELS: { value: Level; label: string }[] = [
  { value: 'off', label: 'Off (optional for everyone)' },
  { value: 'admins', label: 'Platform admins only' },
  { value: 'everyone', label: 'Everyone' },
]

export function SignInPolicyCard() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [level, setLevel] = useState<Level>('admins')
  const [form, setForm] = useState({ admin: { absolute: '', idle: '' }, user: { absolute: '', idle: '' } })
  const [rememberOn, setRememberOn] = useState(false)
  const [rememberDays, setRememberDays] = useState('30')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  function adopt(p: Policy) {
    setPolicy(p)
    setLevel(p.mfa_required)
    setForm({
      admin: { absolute: String(p.sessions.admin.absolute), idle: String(p.sessions.admin.idle) },
      user: { absolute: String(p.sessions.user.absolute), idle: String(p.sessions.user.idle) },
    })
    setRememberOn(p.remember_device_days > 0)
    setRememberDays(String(p.remember_device_days > 0 ? p.remember_device_days : p.remember_device_max_days))
  }
  useEffect(() => {
    adminApi.get<Policy>('/api/identity/mfa/policy').then(adopt).catch(e => setMsg({ ok: false, text: (e as Error).message }))
  }, [])

  async function save() {
    setBusy(true)
    setMsg(null)
    try {
      const n = (s: string) => Number(s)
      const p = await adminApi.put<Policy>('/api/identity/mfa/policy', {
        mfa_required: level,
        sessions: {
          admin: { absolute: n(form.admin.absolute), idle: n(form.admin.idle) },
          user: { absolute: n(form.user.absolute), idle: n(form.user.idle) },
        },
        remember_device_days: rememberOn ? n(rememberDays) : 0,
      })
      adopt(p)
      setMsg({ ok: true, text: 'Saved. Session lengths apply to sessions started from now on; idle timeouts apply at once.' })
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }

  if (!policy) return msg ? <div className="setting-card"><h3>Sign-in security</h3><p style={{ color: 'var(--red)' }}>{msg.text}</p></div> : null

  const field = (tier: 'admin' | 'user', kind: 'absolute' | 'idle') => (
    <input className="editable" type="number" min={policy.bounds[kind].min} max={policy.bounds[kind].max}
      value={form[tier][kind]} style={{ width: 90 }}
      onChange={e => setForm(f => ({ ...f, [tier]: { ...f[tier], [kind]: e.target.value } }))} />
  )

  return (
    <div className="setting-card">
      <h3>Sign-in security</h3>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
        Require two-factor sign-in for password logins:
        <select value={level} onChange={e => setLevel(e.target.value as Level)}>
          {LEVELS.map(l => <option key={l.value} value={l.value}>{l.label}</option>)}
        </select>
      </label>
      <p style={{ color: 'var(--dim)', fontSize: '.78rem', margin: '4px 0 12px' }}>
        Someone who is required but has not set it up is asked to set it up at their next password sign-in.
        Single sign-on users get MFA from the identity provider and are not asked twice. API keys are not affected.
      </p>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
        <input type="checkbox" checked={rememberOn} onChange={e => setRememberOn(e.target.checked)} />
        Let people remember a device for
        <input className="editable" type="number" min={1} max={policy.remember_device_max_days} disabled={!rememberOn}
          value={rememberDays} style={{ width: 60 }} onChange={e => setRememberDays(e.target.value)} />
        days
      </label>
      <p style={{ color: 'var(--dim)', fontSize: '.78rem', margin: '4px 0 12px' }}>
        Off by default; at most {policy.remember_device_max_days} days. A remembered device skips only the code step of a password
        sign-in, never the password. Lowering the number applies to remembered devices at once; turning it off forgets all of them.
        Changing a password or resetting two-factor forgets that person's devices.
      </p>

      <table style={{ fontSize: '.85rem', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ color: 'var(--dim)', textAlign: 'left' }}>
            <th style={{ padding: '4px 12px 4px 0' }}></th>
            <th style={{ padding: '4px 12px 4px 0' }}>Session lifetime (min)</th>
            <th style={{ padding: '4px 12px 4px 0' }}>Idle timeout (min)</th>
          </tr>
        </thead>
        <tbody>
          <tr><td style={{ padding: '4px 12px 4px 0' }}>Platform admins</td><td>{field('admin', 'absolute')}</td><td>{field('admin', 'idle')}</td></tr>
          <tr><td style={{ padding: '4px 12px 4px 0' }}>Everyone else</td><td>{field('user', 'absolute')}</td><td>{field('user', 'idle')}</td></tr>
        </tbody>
      </table>
      <p style={{ color: 'var(--dim)', fontSize: '.78rem', margin: '6px 0 10px' }}>
        Defaults: admins {policy.defaults.admin.absolute / 60} h / {policy.defaults.admin.idle} min idle,
        everyone else {policy.defaults.user.absolute / 60} h / {policy.defaults.user.idle / 60} h idle.
        A session ends at whichever comes first.
      </p>
      <button className="btn btn-accent" disabled={busy} onClick={save}>Save</button>
      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.85rem', marginTop: 8 }}>{msg.text}</p>}
    </div>
  )
}
