import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { ClassificationBadge } from './ClassificationBadge'
import type { CheckStatus, ReleaseCheckItem, ReleaseCheckRecord } from './types'

const ICON: Record<CheckStatus, { mark: string; color: string }> = {
  pass: { mark: 'OK', color: 'var(--green)' },
  warn: { mark: 'WARN', color: 'var(--orange)' },
  fail: { mark: 'FAIL', color: 'var(--red)' },
  excepted: { mark: 'EXC', color: 'var(--yellow)' },
}

/** The release check body a refused promote or deploy returns, if any. */
export function readReleaseRefusal(body: unknown): ReleaseCheckRecord | null {
  const rc = (body as { release_check?: ReleaseCheckRecord })?.release_check
  return rc && Array.isArray(rc.checks) ? rc : null
}

/** One release check rendered as a checklist. */
export function ReleaseChecklist({ record }: { record: ReleaseCheckRecord }) {
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', fontSize: '.8rem', marginBottom: 6 }}>
        <ClassificationBadge level={record.data_classification} />
        <span>Mode <b>{record.mode}</b></span>
        <span style={{ color: record.blocked ? 'var(--red)' : record.result === 'pass' ? 'var(--green)' : 'var(--orange)' }}>
          {record.blocked ? 'Production refused' : record.result === 'skipped' ? 'Checks off' : `Result: ${record.result}`}
        </span>
        <span style={{ color: 'var(--dim)' }}>{record.candidate}</span>
      </div>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {record.checks.map((c: ReleaseCheckItem) => (
          <li key={c.id} style={{ display: 'flex', gap: 8, fontSize: '.8rem' }}>
            <span style={{ color: ICON[c.status].color, fontWeight: 700, minWidth: 38 }}>{ICON[c.status].mark}</span>
            <span>
              <b>{c.label}</b>
              {c.reasons.map((r, i) => <div key={i} className={i ? 'am-mono' : undefined} style={{ color: 'var(--dim)', fontSize: i ? '.72rem' : undefined }}>{r}</div>)}
              {c.exception && <div style={{ color: 'var(--yellow-text)' }}>Exception until {c.exception.expires_at}: {c.exception.reason}</div>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

interface Resp {
  mode: string
  exceptions_by: 'owner' | 'platform_admin'
  exceptable: string[]
  latest: ReleaseCheckRecord | null
  exceptions: { id: number; check_id: string; reason: string; expires_at: string; created_by_name?: string }[]
}

/** Manage page / promote dialog: the latest release check, a preview run, and exceptions. */
export function ReleaseCheckPanel({ slug, record, reload = 0, onMsg }: {
  slug: string
  record?: ReleaseCheckRecord | null
  reload?: number
  onMsg: (m: { text: string; ok: boolean }) => void
}) {
  const [data, setData] = useState<Resp | null>(null)
  const [shown, setShown] = useState<ReleaseCheckRecord | null>(record || null)
  const [busy, setBusy] = useState(false)
  const [exc, setExc] = useState<{ check_id: string; reason: string; days: number } | null>(null)

  const load = useCallback(() => {
    adminApi.get<Resp>(`/api/apps/${encodeURIComponent(slug)}/release-check`)
      .then(r => { setData(r); if (!record) setShown(r.latest) })
      .catch(() => setData(null))
  }, [slug, record])
  useEffect(() => { load() }, [load, reload])
  useEffect(() => { if (record) setShown(record) }, [record])

  async function run() {
    setBusy(true)
    try {
      const r = await adminApi.post<{ release_check: ReleaseCheckRecord }>(`/api/apps/${encodeURIComponent(slug)}/release-check/run`, { trigger: 'promote' })
      setShown(r.release_check)
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function addException() {
    if (!exc) return
    try {
      await adminApi.post(`/api/apps/${encodeURIComponent(slug)}/release-check/exceptions`, exc)
      onMsg({ text: `Exception recorded for ${exc.check_id}`, ok: true })
      setExc(null)
      load()
      void run()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    }
  }

  async function revoke(id: number) {
    try {
      await adminApi.del(`/api/apps/${encodeURIComponent(slug)}/release-check/exceptions/${id}`)
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    }
  }

  const failing = (shown?.checks || []).filter(c => c.status === 'fail' && c.id !== 'intake').map(c => c.id)
  return (
    <>
      <h2 className="am-h2">Release check</h2>
      <div className="am-card">
        {shown ? <ReleaseChecklist record={shown} /> : <span style={{ color: 'var(--dim)' }}>No release check has run yet.</span>}
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <button className="btn btn-sm btn-dim" disabled={busy} onClick={run}>{busy ? 'Checking...' : 'Run check now'}</button>
          {failing.length > 0 && !exc && (
            <button className="btn btn-sm btn-dim" onClick={() => setExc({ check_id: failing[0], reason: '', days: 14 })}>Record exception</button>
          )}
        </div>
        {exc && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
            <select className="am-input" value={exc.check_id} onChange={e => setExc({ ...exc, check_id: e.target.value })}>
              {(data?.exceptable || failing).map(id => <option key={id} value={id}>{id}</option>)}
            </select>
            <textarea className="am-input" rows={2} placeholder="Why is this risk accepted? (10+ characters)" value={exc.reason}
              onChange={e => setExc({ ...exc, reason: e.target.value })} />
            <label style={{ fontSize: '.8rem' }}>
              Expires in <input className="am-input" type="number" min={1} max={90} value={exc.days} style={{ width: 70 }}
                onChange={e => setExc({ ...exc, days: Number(e.target.value) })} /> days (max 90)
            </label>
            {data?.exceptions_by === 'platform_admin' && <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>Only platform admins can record exceptions for this classification.</span>}
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-sm" onClick={addException}>Save exception</button>
              <button className="btn btn-sm btn-dim" onClick={() => setExc(null)}>Cancel</button>
            </div>
          </div>
        )}
        {!!data?.exceptions.length && (
          <div style={{ marginTop: 10, fontSize: '.8rem' }}>
            <div style={{ fontWeight: 600 }}>Active exceptions</div>
            {data.exceptions.map(e => (
              <div key={e.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className="am-mono">{e.check_id}</span>
                <span style={{ color: 'var(--dim)' }}>until {e.expires_at}: {e.reason}</span>
                <button className="btn btn-sm btn-dim" onClick={() => revoke(e.id)}>Revoke</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  )
}
