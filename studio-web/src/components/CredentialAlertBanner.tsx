import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { useMe } from '../hooks/useMe'

type Failing = { name: string; since: string | null; error: string | null; fix: string | null }

/**
 * v2.25.3: platform-admin-only banner surfacing a failing integration
 * credential (Graph mail secret, GitHub service-account PAT). Closes the gap
 * where a dead mail token can't email its own alert — the admin sees it in the
 * UI regardless. Backed by GET /api/credentials/health (platform_admin gated).
 */
export function CredentialAlertBanner() {
  const me = useMe()
  const isPlatformAdmin = me?.user?.role === 'platform_admin'
  const [failing, setFailing] = useState<Failing[]>([])

  useEffect(() => {
    if (!isPlatformAdmin) return
    let cancelled = false
    const load = () => adminApi.get<{ ok: boolean; failing: Failing[] }>('/api/credentials/health')
      .then(r => { if (!cancelled) setFailing(Array.isArray(r?.failing) ? r.failing : []) })
      .catch(() => { /* transient — keep last state */ })
    load()
    const t = setInterval(load, 5 * 60_000)
    return () => { cancelled = true; clearInterval(t) }
  }, [isPlatformAdmin])

  if (!isPlatformAdmin || failing.length === 0) return null

  return (
    <div className="cred-alert-banner" role="alert">
      <span className="cred-alert-ico" aria-hidden>⚠</span>
      <div className="cred-alert-body">
        <strong>Platform credential {failing.length > 1 ? 'issues' : 'issue'}.</strong>{' '}
        {failing.map((f, i) => (
          <span key={f.name}>
            {i > 0 && ' · '}
            <b>{f.name}</b> is failing{f.error ? ` — ${f.error}` : ''}{f.fix ? ` (fix in ${f.fix})` : ''}
          </span>
        ))}
      </div>
    </div>
  )
}
