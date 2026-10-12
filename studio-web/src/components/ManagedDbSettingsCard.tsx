import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Platform-wide limits for the managed databases (GET/PUT
// /api/managed-db/settings, platform admin only). Rendered under the
// Dashboard's "Managed Databases" table, which itself only appears when the
// platform-admin servers endpoint answered.
//
// Nothing here is instant, and the copy says so: per-login limits reach a
// login on its app's next deploy or restart, and a new Postgres
// max_connections takes effect when the shared Postgres is next recreated.

interface Settings {
  conn_limit: number
  pg_max_connections: number
  statement_timeout_s: number
  auth_alert_threshold: number
}
type Spec = Record<keyof Settings, { default: number; min: number; max: number }>

const FIELDS: { key: keyof Settings; label: string; hint: string }[] = [
  { key: 'conn_limit', label: 'Connections per login', hint: 'Postgres CONNECTION LIMIT / MariaDB MAX_USER_CONNECTIONS. Mongo and Redis have no per-login cap.' },
  { key: 'pg_max_connections', label: 'Postgres max_connections', hint: 'Server-wide. Applied when the shared Postgres is next recreated.' },
  { key: 'statement_timeout_s', label: 'Statement timeout (seconds)', hint: 'Per login. 0 = none.' },
  { key: 'auth_alert_threshold', label: 'Failed-login alert threshold', hint: 'Platform admins are e-mailed when one login fails more often than this in 10 minutes (at most once an hour per login).' },
]

export function ManagedDbSettingsCard() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [spec, setSpec] = useState<Spec | null>(null)
  const [draft, setDraft] = useState<Partial<Record<keyof Settings, string>>>({})
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<{ settings: Settings; spec: Spec }>('/api/managed-db/settings')
      .then(r => { setSettings(r.settings); setSpec(r.spec) })
      .catch(() => setSettings(null))
  }, [])

  if (!settings || !spec) return null

  async function save() {
    const patch: Partial<Settings> = {}
    for (const f of FIELDS) {
      const v = draft[f.key]
      if (v !== undefined && v !== '' && Number(v) !== settings![f.key]) patch[f.key] = Number(v)
    }
    if (!Object.keys(patch).length) return
    setBusy(true)
    try {
      const r = await adminApi.put<{ settings: Settings; note: string }>('/api/managed-db/settings', patch)
      setSettings(r.settings)
      setDraft({})
      setMsg({ text: r.note, ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ marginBottom: 24 }}>
      <h3 style={{ margin: '0 0 8px' }}>Database limits</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
        {FIELDS.map(f => (
          <label key={f.key} style={{ fontSize: '.82rem' }}>
            <div style={{ fontWeight: 600 }}>{f.label}</div>
            <input
              type="number"
              min={spec[f.key].min}
              max={spec[f.key].max}
              value={draft[f.key] ?? String(settings[f.key])}
              disabled={busy}
              onChange={e => setDraft(d => ({ ...d, [f.key]: e.target.value }))}
              style={{ width: '100%', marginTop: 4 }}
            />
            <div style={{ color: 'var(--dim)', fontSize: '.72rem', marginTop: 2 }}>{f.hint} Default {spec[f.key].default}.</div>
          </label>
        ))}
      </div>
      <button className="btn btn-sm" style={{ marginTop: 10 }} disabled={busy} onClick={save}>Save limits</button>
      {msg && <div style={{ marginTop: 6, fontSize: '.8rem', color: msg.ok ? 'var(--dim)' : 'var(--red)' }}>{msg.text}</div>}
    </div>
  )
}
