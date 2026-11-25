import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

// Settings > Backup: the backup recovery key. Platform backups no longer hold
// ENCRYPTION_KEY, so a person has to take it somewhere else. Nothing secret is
// fetched until the button is pressed: that POST is what steps the person up,
// audits the read and records the download; the key goes straight into a file
// and is not kept in state.

type Status = {
  available: boolean
  fingerprint: string | null
  downloaded_at: string | null
  downloaded_by: string | null
  downloaded_for_current_key: boolean
  warning: string
}
type Issued = { fingerprint: string; file_name: string; file_text: string }

const URL_ = '/api/settings/backup/recovery-key'

export function RecoveryKeyCard({ onDownloaded }: { onDownloaded?: () => void } = {}) {
  const [status, setStatus] = useState<Status | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const load = () => adminApi.get<Status>(URL_).then(setStatus).catch(() => {})
  useEffect(() => { load() }, [])

  async function download() {
    if (!confirm('Download the backup recovery key?\n\nThis file decrypts every secret on this platform. '
      + 'Store it outside this host and its backup bucket. The download is audited.')) return
    setBusy(true); setMsg(null)
    try {
      const r = await adminApi.post<Issued>(URL_, {})
      const url = URL.createObjectURL(new Blob([r.file_text], { type: 'text/plain' }))
      const a = document.createElement('a')
      a.href = url; a.download = r.file_name; document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
      setMsg({ ok: true, text: `Saved ${r.file_name}. Move it somewhere other than this computer's Downloads folder.` })
      load()
      onDownloaded?.()
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message })
    } finally { setBusy(false) }
  }

  if (!status) return null
  const missing = status.available && !status.downloaded_for_current_key
  return (
    <div style={{
      margin: '8px 0 14px', padding: '10px 12px', borderRadius: 6,
      border: `1px solid ${missing ? 'var(--yellow)' : 'var(--border, #444)'}`,
    }}>
      <h3 style={{ marginTop: 0 }}>Backup recovery key</h3>
      <p className="settings-hint">
        The nightly local backup and the off-site upload do <b>not</b> contain <code>ENCRYPTION_KEY</code>: they name
        the key they need by fingerprint{status.fingerprint ? <> (<code>{status.fingerprint}</code>)</> : null}.
        To restore one on a new host you need this key. <b>{status.warning}</b>
      </p>
      <p className="settings-hint">
        {status.downloaded_for_current_key
          ? `Downloaded ${status.downloaded_at ? serverDate(status.downloaded_at).toLocaleString() : ''}${status.downloaded_by ? ` by ${status.downloaded_by}` : ''}.`
          : status.available ? 'The current key has never been downloaded.' : 'No key is loaded on this server.'}
      </p>
      <button className="btn" onClick={download} disabled={busy || !status.available}>
        {busy ? '...' : 'Download recovery key'}
      </button>
      <span className="settings-hint" style={{ marginLeft: 8 }}>Needs a recent sign-in; recorded in the audit log.</span>
      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', marginTop: 8 }}>{msg.text}</p>}
    </div>
  )
}
