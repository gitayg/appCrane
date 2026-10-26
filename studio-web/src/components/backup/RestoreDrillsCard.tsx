import { Fragment, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

type Check = { id: string; label: string; status: 'pass' | 'fail' | 'warn' | 'skipped'; detail: unknown }
type Drill = {
  id: number; run_id: string; source: 'local' | 's3'; trigger: string; status: string
  backup_ref: string | null; backup_created_at: string | null; rpo_seconds: number | null; rto_ms: number | null
  checks: Check[]; error: string | null; cleaned_up: boolean; started_at: string; finished_at: string | null
}
type Config = { enabled: boolean; interval_days: number; hour: number; tolerance_pct: number }
type Listing = { config: Config; running: boolean; drills: Drill[] }

const BASE = '/api/settings/restore-drills'

const fmtAge = (s: number | null) => {
  if (s == null) return '-'
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 86400 * 2) return `${(s / 3600).toFixed(1)} h`
  return `${(s / 86400).toFixed(1)} d`
}
const fmtMs = (ms: number | null) => (ms == null ? '-' : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`)
const color = (status: string) =>
  status === 'passed' || status === 'pass' ? 'var(--green)'
    : status === 'failed' || status === 'refused' || status === 'fail' ? 'var(--red)'
      : 'var(--text-muted, #888)'

/**
 * Settings → Backup: scheduled restore drills. Each drill restores the newest
 * local and off-site backups into a scratch area, checks them, records RPO
 * (backup age) and RTO (restore time), and deletes the scratch area.
 */
export function RestoreDrillsCard() {
  const [data, setData] = useState<Listing | null>(null)
  const [cfg, setCfg] = useState<Config | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState<number | null>(null)

  const load = () => adminApi.get<Listing>(BASE).then((d) => { setData(d); setCfg((c) => c ?? d.config) }).catch((e) => setMsg({ ok: false, text: (e as Error).message }))
  useEffect(() => { load() }, [])
  useEffect(() => {
    if (!data?.running) return
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [data?.running])

  async function save() {
    if (!cfg) return
    setBusy(true); setMsg(null)
    try {
      const r = await adminApi.put<{ config: Config }>(`${BASE}/config`, cfg)
      setCfg(r.config)
      setMsg({ ok: true, text: 'Restore drill schedule saved.' })
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }) } finally { setBusy(false) }
  }

  async function runNow() {
    setBusy(true); setMsg(null)
    try {
      await adminApi.post(`${BASE}/run`, {})
      setMsg({ ok: true, text: 'Restore drill started. Results appear below when it finishes.' })
      await load()
      setData((d) => (d ? { ...d, running: true } : d))
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }) } finally { setBusy(false) }
  }

  return (
    <div style={{ marginTop: 24 }}>
      <h3>Restore drills</h3>
      <p style={{ color: 'var(--text-muted, #888)', fontSize: '.9rem' }}>
        A drill restores the newest local backup, and the newest off-site set when one is configured, into a scratch area
        under <code>DATA_DIR/drills</code>. It checks the database (integrity check, row counts, decryption), every repository
        archive and every managed database dump, then deletes the scratch area. It never touches live data. RPO is the age
        of the backup when the drill started; RTO is how long the restore and checks took. A failed drill e-mails platform admins.
      </p>
      {cfg && (
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <label><input type="checkbox" checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} /> Scheduled</label>
          <label>Every <input type="number" min={1} max={90} value={cfg.interval_days} style={{ width: 60 }}
            onChange={(e) => setCfg({ ...cfg, interval_days: parseInt(e.target.value, 10) || 1 })} /> days</label>
          <label>after <input type="number" min={0} max={23} value={cfg.hour} style={{ width: 56 }}
            onChange={(e) => setCfg({ ...cfg, hour: parseInt(e.target.value, 10) || 0 })} />:00</label>
          <label>Row-count tolerance <input type="number" min={0} max={100} value={cfg.tolerance_pct} style={{ width: 60 }}
            onChange={(e) => setCfg({ ...cfg, tolerance_pct: parseInt(e.target.value, 10) || 0 })} />%</label>
          <button className="btn" onClick={save} disabled={busy}>Save</button>
          <button className="btn" onClick={runNow} disabled={busy || data?.running}>{data?.running ? 'Drill running…' : 'Run a drill now'}</button>
        </div>
      )}
      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)' }}>{msg.text}</p>}
      {data && data.drills.length === 0 && <p>No restore drill has run yet.</p>}
      {data && data.drills.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ marginTop: 8, fontSize: '.85rem' }}>
            <thead><tr><th>Started</th><th>Source</th><th>Result</th><th>Backup</th><th>RPO</th><th>RTO</th><th></th></tr></thead>
            <tbody>
              {data.drills.map((d) => (
                <Fragment key={d.id}>
                  <tr>
                    <td>{serverDate(d.started_at).toLocaleString()}</td>
                    <td>{d.source === 's3' ? 'off-site' : 'local'}{d.trigger === 'manual' ? ' (manual)' : ''}</td>
                    <td style={{ color: color(d.status) }}>{d.status}{d.error ? ` - ${d.error}` : ''}</td>
                    <td style={{ wordBreak: 'break-all' }}>{d.backup_ref || '-'}</td>
                    <td>{fmtAge(d.rpo_seconds)}</td>
                    <td>{fmtMs(d.rto_ms)}</td>
                    <td><button className="btn" onClick={() => setOpen(open === d.id ? null : d.id)}>{open === d.id ? 'Hide' : 'Checks'}</button></td>
                  </tr>
                  {open === d.id && (
                    <tr>
                      <td colSpan={7}>
                        <ul style={{ margin: 0 }}>
                          {d.checks.map((c) => (
                            <li key={c.id}>
                              <span style={{ color: color(c.status) }}>{c.status}</span> {c.label}
                              {c.detail != null && <code style={{ marginLeft: 6, fontSize: '.8rem' }}>{typeof c.detail === 'string' ? c.detail : JSON.stringify(c.detail)}</code>}
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
