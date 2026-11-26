import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

interface AutoStatus {
  version: string
  enabled: boolean
  warning: string | null
  pending: { outcome: string; message: string | null; at: string } | null
  last: {
    version: string
    at: string
    ok: boolean
    exit_code: number | null
    timed_out?: boolean
    reason?: string | null
    done?: boolean
    warnings?: string[]
  } | null
}

const PATH = '/api/settings/host-hardening/auto'

// Host limits applied by AppCrane itself after an upgrade: one status line,
// the on/off switch, and the one-time setup warning for a stale root copy.
export function HostLimitsAutoLine() {
  const [s, setS] = useState<AutoStatus | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    adminApi.get<AutoStatus>(PATH).then(r => { setS(r); setErr(null) })
      .catch(e => setErr(e instanceof Error ? e.message : String(e)))
  }, [])
  useEffect(() => { load() }, [load])

  async function toggle(enabled: boolean) {
    setSaving(true)
    try { setS(await adminApi.put<AutoStatus>(PATH, { enabled })); setErr(null) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    finally { setSaving(false) }
  }

  if (!s) return err ? <p style={{ color: 'var(--red)', fontSize: '.8rem' }}>{err}</p> : null
  const l = s.last
  return (
    <div style={{ fontSize: '.8rem', marginBottom: 8 }}>
      <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
        <input type="checkbox" checked={s.enabled} disabled={saving} onChange={e => toggle(e.target.checked)} />
        Apply automatically after AppCrane is upgraded
      </label>
      <p style={{ margin: 0, color: 'var(--dim)' }}>
        {l
          ? <>Last automatic apply: v{l.version}, {serverDate(l.at).toLocaleString()},{' '}
              <span style={{ color: !l.ok ? 'var(--red)' : l.done === false ? 'var(--orange)' : 'var(--green)' }}>
                {!l.ok ? `failed${l.reason ? ` (${l.reason})` : l.exit_code != null ? ` (exit ${l.exit_code})` : ''}`
                  : l.done === false ? `finished with ${l.warnings?.length ?? 0} warning(s)` : 'succeeded'}
              </span></>
          : 'No automatic apply yet.'}
      </p>
      {s.pending?.message && <p style={{ margin: '4px 0 0', color: 'var(--orange)' }}>{s.pending.message}</p>}
      {s.warning && <p style={{ margin: '4px 0 0', color: 'var(--orange)' }}>{s.warning}</p>}
      {err && <p style={{ margin: '4px 0 0', color: 'var(--red)' }}>{err}</p>}
    </div>
  )
}
