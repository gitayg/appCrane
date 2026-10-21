import { useEffect, useState } from 'react'
import { adminApi, authHeaders } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import { serverDate } from '../../utils/serverDate'

export type S3OffSite = { configured?: boolean; has_off_site_copy?: boolean; notice?: string | null; missing?: string[] }
export type S3Config = {
  enabled?: boolean; bucket?: string; region?: string; prefix?: string; endpoint?: string
  access_key_id?: string; has_secret?: boolean; hour?: number
  last_run?: string | null; last_error?: string | null
  keep_daily?: number; keep_weekly?: number; keep_monthly?: number
  encrypt?: boolean; sse?: '' | 'AES256' | 'aws:kms'; sse_kms_key_id?: string; include_repos?: boolean
  last_bytes?: number | null; last_duration_ms?: number | null; last_set?: string | null; last_warnings?: string[]
  last_retention?: { applied: boolean; refused: string | null; kept: number; removed_sets: number; deleted_objects: number } | null
  covers?: string[]; excludes?: string[]; encryption_warning?: string
  off_site?: S3OffSite
}
type Step = { step: string; ok: boolean; error?: string }
type BucketBackup = { id: string; host: string; own: boolean; created_at: string; legacy: boolean; complete: boolean; objects: number; bytes: number; verified: boolean; verify_error: string | null; restorable: boolean; downloadable: boolean }
type Listing = { own_host: string; prefix: string; truncated: boolean; other_objects: number; backups: BucketBackup[] }

const BASE = '/api/settings/backup/s3'
const fmtBytes = (n?: number | null) => {
  if (n == null) return '-'
  if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

/**
 * Settings → Backup: the scheduled off-site (S3 / R2 / MinIO) backup. Config,
 * retention, encryption, a connection test, the last run, and the backups in
 * the bucket with verified download and restore. `onConfig` hands every config
 * the server returns back to the parent, which renders the off-site notice.
 */
export function S3BackupCard({ onConfig }: { onConfig?: (cfg: S3Config) => void }) {
  const [s3, setS3] = useState<S3Config>({})
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [steps, setSteps] = useState<Step[] | null>(null)
  const [listing, setListing] = useState<Listing | null>(null)
  const [listBusy, setListBusy] = useState(false)

  const apply = (cfg: S3Config) => { setS3(cfg); onConfig?.(cfg) }
  const load = () => adminApi.get<S3Config>(BASE).then(apply).catch(() => {})
  useEffect(() => { load() }, [])

  const formPatch = () => {
    const patch: Record<string, unknown> = {
      enabled: s3.enabled, bucket: s3.bucket, region: s3.region, prefix: s3.prefix, endpoint: s3.endpoint,
      access_key_id: s3.access_key_id, hour: s3.hour, keep_daily: s3.keep_daily, keep_weekly: s3.keep_weekly,
      keep_monthly: s3.keep_monthly, encrypt: s3.encrypt, sse: s3.sse ?? '', sse_kms_key_id: s3.sse_kms_key_id ?? '',
      include_repos: s3.include_repos !== false,
    }
    if (secret.trim()) patch.secret_access_key = secret.trim()
    return patch
  }

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(true); setMsg(null)
    try { await fn() } catch (e) { setMsg({ ok: false, text: `${label}: ${(e as Error).message}` }) }
    finally { setBusy(false) }
  }

  const save = () => run('Save', async () => {
    apply(await adminApi.put<S3Config>(BASE, formPatch()))
    setSecret('')
    setMsg({ ok: true, text: 'S3 backup settings saved.' })
  })

  const testConnection = () => run('Test connection', async () => {
    const p = formPatch()
    const body: Record<string, string> = {}
    for (const k of ['bucket', 'region', 'prefix', 'endpoint', 'access_key_id', 'secret_access_key', 'sse', 'sse_kms_key_id']) {
      if (typeof p[k] === 'string') body[k] = p[k] as string
    }
    const r = await adminApi.post<{ ok: boolean; steps: Step[] }>(`${BASE}/test`, body)
    setSteps(r.steps)
    setMsg({ ok: r.ok, text: r.ok ? 'Connection works: wrote, read back and deleted a probe object.' : 'Connection test failed — see the steps below.' })
  })

  const runNow = () => run('Backup', async () => {
    const r = await adminApi.post<{ ok: boolean; set?: string; size?: number; error?: string; warnings?: string[] }>(`${BASE}/run`, {})
    if (!r.ok) throw new Error(r.error || 'Backup failed')
    setMsg({ ok: true, text: `Uploaded ${r.set} (${fmtBytes(r.size)})${r.warnings?.length ? ` with ${r.warnings.length} warning(s)` : ''}.` })
    load()
    if (listing) refreshList()
  })

  async function refreshList() {
    setListBusy(true)
    try { setListing(await adminApi.get<Listing>(`${BASE}/backups`)) }
    catch (e) { setMsg({ ok: false, text: `List backups: ${(e as Error).message}` }) }
    finally { setListBusy(false) }
  }

  const download = (b: BucketBackup) => run('Download', async () => {
    const r = await fetch(`${BASE}/backups/${encodeURIComponent(b.id)}/download`, { headers: authHeaders() })
    if (!r.ok) {
      const body = await r.json().catch(() => ({}))
      throw new Error(body?.error?.message || `HTTP ${r.status}`)
    }
    const verified = r.headers.get('X-AppCrane-Verified') === 'sha256'
    const name = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '')?.[1] || `${b.id}.tar.gz`
    const url = URL.createObjectURL(await r.blob())
    const a = document.createElement('a')
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
    setMsg({ ok: true, text: `Downloaded ${name} — ${verified ? 'SHA-256 verified against the manifest' : 'NOT verified (pre-manifest backup)'}.` })
  })

  const fetchToHost = (b: BucketBackup) => run('Fetch', async () => {
    const r = await adminApi.post<{ files: { local_file: string; verified: boolean }[] }>(`${BASE}/backups/${encodeURIComponent(b.id)}/fetch`, {})
    setMsg({ ok: true, text: `Fetched ${r.files.length} file(s) into the backups directory: ${r.files.map(f => f.local_file + (f.verified ? '' : ' (unverified)')).join(', ')}. Restore them with the Import and repository restore tools.` })
  })

  const restore = (b: BucketBackup) => {
    const typed = window.prompt(
      `Restore ${b.id}?\n\nThis REPLACES the live database and .env with the backup, restores every managed-app repository in it, ` +
      'then restarts the server. Managed databases are not restored by this step.\n\nType the backup id to confirm:')
    if (typed === null) return
    run('Restore', async () => {
      const r = await adminApi.post<{ message?: string; repos?: { restored: string[]; failed: { slug: string }[] } }>(
        `${BASE}/backups/${encodeURIComponent(b.id)}/restore`, { confirm: typed.trim() })
      setMsg({ ok: true, text: `${r.message || 'Restored.'} Repositories restored: ${r.repos?.restored.length ?? 0}${r.repos?.failed.length ? `, failed: ${r.repos.failed.map(f => f.slug).join(', ')}` : ''}. Wait ~10s, then refresh.` })
    })
  }

  const num = (k: 'hour' | 'keep_daily' | 'keep_weekly' | 'keep_monthly', min: number, max: number, dflt: number) => (
    <input className="editable" type="number" min={min} max={max} value={s3[k] ?? dflt}
      onChange={e => setS3(s => ({ ...s, [k]: Number(e.target.value) }))} style={{ width: 90 }} />
  )
  const grid = { display: 'grid', gridTemplateColumns: '130px 1fr', gap: 8, maxWidth: 560, alignItems: 'center', margin: '8px 0' } as const

  return (
    <div>
      <h3 style={{ marginTop: 24 }}>Scheduled off-site backup (S3)</h3>
      <p className="settings-hint">
        Once a night, upload a backup set to an S3 bucket (or an S3-compatible store such as Cloudflare R2 or MinIO).
        No-op until you enter a bucket and credentials. Large archives go up as multipart uploads, and every object's
        SHA-256 is recorded in a manifest so downloads and restores are verified.
      </p>
      <p className="settings-hint">
        <b>Includes:</b> {(s3.covers || []).join(', ') || '…'}. <b>Not included:</b> {(s3.excludes || []).join(', ') || '…'}.
      </p>
      <p className="settings-hint">
        The key needs <code>s3:PutObject</code>, <code>s3:GetObject</code>, <code>s3:ListBucket</code>,{' '}
        <code>s3:DeleteObject</code> (retention and the connection test) and <code>s3:AbortMultipartUpload</code>.
      </p>

      <label style={{ display: 'block', margin: '6px 0' }}>
        <input type="checkbox" checked={!!s3.enabled} onChange={e => setS3(s => ({ ...s, enabled: e.target.checked }))} />
        {' '}Enable nightly S3 backup
      </label>
      <div style={grid}>
        <label>Bucket</label><input className="editable" value={s3.bucket ?? ''} onChange={e => setS3(s => ({ ...s, bucket: e.target.value }))} placeholder="my-appcrane-backups" />
        <label>Region</label><input className="editable" value={s3.region ?? ''} onChange={e => setS3(s => ({ ...s, region: e.target.value }))} placeholder="us-east-1 (R2: auto)" />
        <label>Prefix</label><input className="editable" value={s3.prefix ?? ''} onChange={e => setS3(s => ({ ...s, prefix: e.target.value }))} placeholder="(optional) appcrane/" />
        <label>Endpoint</label><input className="editable" value={s3.endpoint ?? ''} onChange={e => setS3(s => ({ ...s, endpoint: e.target.value }))} placeholder="(optional - set for R2/MinIO)" />
        <label>Access key</label><input className="editable" value={s3.access_key_id ?? ''} onChange={e => setS3(s => ({ ...s, access_key_id: e.target.value }))} placeholder="access key id" />
        <label>Secret key</label><PasswordInput className="editable" label="S3 secret key" autoComplete="new-password" value={secret} onChange={e => setSecret(e.target.value)} placeholder={s3.has_secret ? 'stored - blank keeps current' : 'secret access key'} />
        <label>Hour (0-23)</label>{num('hour', 0, 23, 3)}
      </div>

      <h4 style={{ margin: '14px 0 4px' }}>Retention in the bucket</h4>
      <p className="settings-hint">
        After each successful upload, keep the newest backup of each of the last N days, M weeks and K months and
        delete this host's older backups under the prefix. Nothing else in the bucket is touched, and nothing is
        deleted if the listing looks incomplete.
      </p>
      <div style={grid}>
        <label>Daily</label>{num('keep_daily', 1, 366, 7)}
        <label>Weekly</label>{num('keep_weekly', 0, 520, 4)}
        <label>Monthly</label>{num('keep_monthly', 0, 240, 6)}
      </div>

      <h4 style={{ margin: '14px 0 4px' }}>Contents and encryption</h4>
      <label style={{ display: 'block', margin: '6px 0' }}>
        <input type="checkbox" checked={s3.include_repos !== false} onChange={e => setS3(s => ({ ...s, include_repos: e.target.checked }))} />
        {' '}Include managed-app git repositories
      </label>
      <label style={{ display: 'block', margin: '6px 0' }}>
        <input type="checkbox" checked={!!s3.encrypt} onChange={e => setS3(s => ({ ...s, encrypt: e.target.checked }))} />
        {' '}Encrypt archives before upload (AES-256-GCM, key derived from <code>ENCRYPTION_KEY</code>)
      </label>
      {s3.encrypt && (
        <p style={{ margin: '4px 0 8px', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--yellow)', fontSize: '.85rem' }}>
          {s3.encryption_warning || 'If ENCRYPTION_KEY is lost, encrypted backups are unrecoverable.'}
        </p>
      )}
      <div style={grid}>
        <label>Server-side</label>
        <select className="editable" value={s3.sse ?? ''} onChange={e => setS3(s => ({ ...s, sse: e.target.value as S3Config['sse'] }))} style={{ maxWidth: 260 }}>
          <option value="">None (bucket default)</option>
          <option value="AES256">SSE-S3 (AES256)</option>
          <option value="aws:kms">SSE-KMS</option>
        </select>
        {s3.sse === 'aws:kms' && <>
          <label>KMS key id</label>
          <input className="editable" value={s3.sse_kms_key_id ?? ''} onChange={e => setS3(s => ({ ...s, sse_kms_key_id: e.target.value }))} placeholder="(optional - bucket default key)" />
        </>}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn" onClick={save} disabled={busy}>Save S3 settings</button>
        <button className="btn" onClick={testConnection} disabled={busy}>Test connection</button>
        <button className="btn" onClick={runNow} disabled={busy}>{busy ? '…' : 'Back up to S3 now'}</button>
      </div>
      {steps && (
        <ul style={{ margin: '8px 0', paddingLeft: 18, fontSize: '.85rem' }}>
          {steps.map(st => (
            <li key={st.step} style={{ color: st.ok ? 'var(--green)' : 'var(--red)' }}>
              {st.step}: {st.ok ? 'ok' : st.error}
            </li>
          ))}
        </ul>
      )}

      {s3.last_run && (
        <p className="settings-hint" style={{ marginTop: 6 }}>
          Last off-site backup: {serverDate(s3.last_run).toLocaleString()}
          {s3.last_set ? ` (${s3.last_set})` : ''}
          {s3.last_bytes != null ? `, ${fmtBytes(s3.last_bytes)}` : ''}
          {s3.last_duration_ms != null ? `, ${Math.round(s3.last_duration_ms / 1000)} s` : ''}
          {s3.last_retention ? (s3.last_retention.applied
            ? `. Retention kept ${s3.last_retention.kept}, removed ${s3.last_retention.removed_sets}.`
            : `. Retention not applied: ${s3.last_retention.refused}`) : ''}
        </p>
      )}
      {!!s3.last_warnings?.length && (
        <ul style={{ color: 'var(--yellow)', fontSize: '.8rem', margin: '4px 0', paddingLeft: 18 }}>
          {s3.last_warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}
      {s3.last_error && <p style={{ color: 'var(--red)', fontSize: '.8rem' }}>Last error: {s3.last_error}</p>}

      <h4 style={{ margin: '16px 0 4px' }}>Backups in the bucket</h4>
      <button className="btn" onClick={refreshList} disabled={listBusy}>{listBusy ? 'Listing…' : listing ? 'Refresh list' : 'List backups'}</button>
      {listing && (
        <>
          {listing.truncated && <p style={{ color: 'var(--yellow)', fontSize: '.8rem' }}>The listing was truncated; older backups are not shown.</p>}
          {listing.backups.length === 0
            ? <p className="settings-hint">No AppCrane backups under <code>{listing.prefix || '(bucket root)'}</code>.</p>
            : (
              <table className="table" style={{ marginTop: 8, fontSize: '.85rem' }}>
                <thead><tr><th>Backup</th><th>Taken</th><th>Size</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {listing.backups.map(b => (
                    <tr key={b.id + (b.legacy ? '.tar.gz' : '')}>
                      <td><code>{b.id}</code>{!b.own && <span style={{ color: 'var(--dim)' }}> (host {b.host})</span>}</td>
                      <td>{serverDate(b.created_at).toLocaleString()}</td>
                      <td>{fmtBytes(b.bytes)}</td>
                      <td title={b.verify_error || undefined}>{b.verified ? `verified, ${b.objects} objects` : b.legacy ? 'legacy, unverified (download only)' : b.complete ? 'UNVERIFIED: not signed by this AppCrane' : 'incomplete'}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button className="btn" onClick={() => download(b)} disabled={busy || !b.downloadable}>Download</button>{' '}
                        <button className="btn" onClick={() => fetchToHost(b)} disabled={busy || !b.downloadable}>Fetch to host</button>{' '}
                        <button className="btn" style={{ background: 'var(--red)', color: '#fff' }} onClick={() => restore(b)} disabled={busy || !b.restorable}>Restore</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </>
      )}

      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', marginTop: 12 }}>{msg.text}</p>}
    </div>
  )
}
