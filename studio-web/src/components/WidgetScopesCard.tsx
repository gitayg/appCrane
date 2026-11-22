import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

interface Props {
  slug: string
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

interface Scopes { members: boolean; app_keys: boolean; can_change?: boolean }

// GET/PUT /api/apps/:slug/widget-scopes (routes/widgetSettings.js): the two
// drop-in widgets that act with an owner's power are off until turned on here.
// Shown to the people PUT accepts (owner, platform admin).
export function WidgetScopesCard({ slug, reload, onMsg }: Props) {
  const [s, setS] = useState<Scopes | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    adminApi.get<Scopes>(`/api/apps/${encodeURIComponent(slug)}/widget-scopes`)
      .then(d => { if (!cancelled) setS(d) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [slug, reload])

  async function toggle(field: 'members' | 'app_keys', next: boolean) {
    setBusy(true)
    try {
      const d = await adminApi.put<Scopes>(`/api/apps/${encodeURIComponent(slug)}/widget-scopes`, { [field]: next })
      setS(prev => ({ ...d, can_change: prev?.can_change }))
      onMsg({ text: `${field === 'members' ? 'Members' : 'App keys'} widget turned ${next ? 'on' : 'off'}.`, ok: true })
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!s?.can_change) return null
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>Widgets</h3>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="checkbox" checked={s.members} disabled={busy} onChange={e => toggle('members', e.target.checked)} />
        &lt;appcrane-app-members&gt;: owners change roles and add members from the app's pages
      </label>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
        <input type="checkbox" checked={s.app_keys} disabled={busy} onChange={e => toggle('app_keys', e.target.checked)} />
        &lt;appcrane-app-keys&gt;: people create sign-in keys for this app from its pages
      </label>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6 }}>
        These run with the signed-in person's power inside the app's own JavaScript, so a bug or XSS in the app could use them while that person has the page open. Turn on only what the app uses. Owner or platform admin only; every change is audited.
      </div>
    </div>
  )
}
