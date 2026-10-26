import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

interface Props {
  slug: string
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

interface AppResp {
  app: { whats_new_email?: boolean; can_change_whats_new_email?: boolean }
}

// Shown to the people PUT accepts (owner, app admin, platform admin).
export function WhatsNewMailCard({ slug, reload, onMsg }: Props) {
  const [on, setOn] = useState<boolean | null>(null)
  const [canChange, setCanChange] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    adminApi.get<AppResp>(`/api/apps/${encodeURIComponent(slug)}`)
      .then(d => {
        if (cancelled) return
        setOn(d.app.whats_new_email !== false)
        setCanChange(!!d.app.can_change_whats_new_email)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [slug, reload])

  async function toggle(next: boolean) {
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${encodeURIComponent(slug)}`, { whats_new_email: next })
      setOn(next)
      onMsg({ text: next ? "What's new e-mails are on." : "What's new e-mails are off.", ok: true })
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!canChange || on === null) return null
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>What's new e-mail</h3>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: busy ? 'wait' : 'pointer' }}>
        <input type="checkbox" checked={on} disabled={busy} onChange={e => toggle(e.target.checked)} />
        E-mail owners and admins when a new version reaches production
      </label>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6 }}>
        {on
          ? "Each new production version sends one e-mail with its What's new text to the app's owners and admins. Redeploys and rollbacks send nothing."
          : 'No e-mail is sent when a new version reaches production.'}
        {' '}Owner, app admin or platform admin only.
      </div>
    </div>
  )
}
