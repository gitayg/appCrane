import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// "Encrypt MariaDB data at rest" (GET/PUT /api/managed-db/encryption, POST
// /api/managed-db/encryption/unload-key; platform admin only). Rendered inside
// ManagedDbSettingsCard.
//
// The server decides everything that matters: whether the key may be unloaded
// is checked against the running MariaDB (services/managedDbEncryption.js
// unloadRefusal), not against what this page shows. The page polls while
// tablespaces are being encrypted or decrypted so the operator sees progress.

type Phase = 'off' | 'encrypting' | 'on' | 'decrypting' | 'decrypted'

interface Status {
  enabled: boolean
  key_loaded: boolean
  key_exists: boolean
  phase: Phase
  server_provisioned: boolean
  server_running: boolean
  tablespaces: { total: number; encrypted: number; plain: number; in_progress: number } | null
  // Encrypt mode only: MariaDB cannot encrypt the Aria transaction log.
  aria_log: { encryptable: false; note: string; live: { purge_type: string; checkpoint_interval: number; log_file_size: number } | null } | null
  // Last pass that moved app Aria/MyISAM tables to InnoDB (null = never ran).
  conversion: { at: string; converted_total: number; converted_last: string[]; failed_count: number; failed: { name: string; engine: string; error: string }[] } | null
  error: string | null
  caveat: string
  note?: string
}

const PHASE_LABEL: Record<Phase, string> = {
  off: 'Off',
  encrypting: 'On — encrypting existing tables',
  on: 'On — all tables encrypted',
  decrypting: 'Turning off — decrypting tables (key still loaded)',
  decrypted: 'Turning off — decrypted; the key can now be unloaded',
}

export function ManagedDbEncryptionCard() {
  const [status, setStatus] = useState<Status | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [deleteKey, setDeleteKey] = useState(false)

  const load = useCallback(() => {
    adminApi.get<Status>('/api/managed-db/encryption').then(setStatus).catch(() => setStatus(null))
  }, [])
  useEffect(load, [load])

  // Poll while the background threads are working.
  const moving = status?.phase === 'encrypting' || status?.phase === 'decrypting'
  useEffect(() => {
    if (!moving || !status?.server_running) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [moving, status?.server_running, load])

  if (!status) return null

  async function act(fn: () => Promise<Status>) {
    setBusy(true)
    setMsg(null)
    try {
      const r = await fn()
      setStatus(r)
      if (r.note) setMsg({ text: r.note, ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  function turnOn() {
    if (!confirm('Encrypt MariaDB data at rest?\n\nThe shared MariaDB server restarts once on its existing data, so every app\'s open database connections drop once. Existing tables are then encrypted in the background.')) return
    act(() => adminApi.put<Status>('/api/managed-db/encryption', { enabled: true }))
  }

  function turnOff() {
    if (!confirm('Turn MariaDB encryption off?\n\nThe server restarts once (open connections drop once) and every table is decrypted in the background. The key stays loaded until nothing is encrypted; then you can unload it here.')) return
    act(() => adminApi.put<Status>('/api/managed-db/encryption', { enabled: false, confirm: true }))
  }

  function unload() {
    const what = deleteKey ? 'unload and DELETE the key' : 'stop loading the key (it stays stored)'
    if (!confirm(`Restart MariaDB without the encryption key and ${what}?\n\nAppCrane first checks the running server: it refuses if any table is still encrypted. Open connections drop once.`)) return
    act(() => adminApi.post<Status>('/api/managed-db/encryption/unload-key', { delete_key: deleteKey }))
  }

  const ts = status.tablespaces
  const progress = ts
    ? (status.enabled ? `${ts.encrypted} of ${ts.total} InnoDB tablespaces encrypted` : `${ts.plain} of ${ts.total} InnoDB tablespaces decrypted`)
      + (ts.in_progress ? ` (${ts.in_progress} in progress)` : '')
    : status.server_provisioned ? 'MariaDB is not running; progress shows once it is.' : 'MariaDB has not been created yet; the setting applies when it is.'

  return (
    <div style={{ marginTop: 18 }}>
      <h3 style={{ margin: '0 0 6px' }}>Encrypt MariaDB data at rest</h3>
      <div style={{ fontSize: '.82rem' }}>
        <div><strong>Status:</strong> {PHASE_LABEL[status.phase]}</div>
        {status.key_loaded && <div style={{ color: 'var(--dim)', marginTop: 2 }}>{progress}</div>}
        {status.aria_log && <div style={{ color: 'var(--dim)', marginTop: 2 }}>{status.aria_log.note}</div>}
        {status.enabled && status.conversion && (
          <div style={{ color: 'var(--dim)', marginTop: 2 }}>
            App Aria/MyISAM tables moved to encrypted InnoDB: {status.conversion.converted_total}
            {status.conversion.converted_last.length > 0 && ` (last pass: ${status.conversion.converted_last.join(', ')})`}
            {status.conversion.failed_count > 0 && (
              <div style={{ color: 'var(--red)' }}>
                {status.conversion.failed_count} table(s) left unconverted (not encrypted):
                {status.conversion.failed.map(f => <div key={f.name}><code>{f.name}</code> ({f.engine}): {f.error}</div>)}
              </div>
            )}
          </div>
        )}
        {status.error && <div style={{ color: 'var(--red)', marginTop: 2 }}>Could not read progress: {status.error}</div>}
      </div>
      <div style={{ color: 'var(--dim)', fontSize: '.72rem', margin: '6px 0' }}>
        {status.caveat} MariaDB only: community Postgres has no equivalent. Turning it on or off restarts the shared MariaDB once, so open connections drop once.
        {' '}With encryption on, AppCrane's <code>ENCRYPTION_KEY</code> is required to read MariaDB data: keep it with your backups.
      </div>
      {!status.enabled && (
        <button className="btn btn-sm" disabled={busy} onClick={turnOn}>Turn on</button>
      )}
      {status.enabled && (
        <button className="btn btn-sm" disabled={busy} onClick={turnOff}>Turn off</button>
      )}
      {!status.enabled && status.key_loaded && (
        <div style={{ marginTop: 8, fontSize: '.8rem' }}>
          <label style={{ marginRight: 10 }}>
            <input type="checkbox" checked={deleteKey} disabled={busy} onChange={e => setDeleteKey(e.target.checked)} /> also delete the key
          </label>
          <button className="btn btn-sm" disabled={busy || status.phase !== 'decrypted'} onClick={unload}>Unload key</button>
          {status.phase !== 'decrypted' && <span style={{ color: 'var(--dim)', marginLeft: 8 }}>Available once every table is decrypted.</span>}
        </div>
      )}
      {!status.enabled && !status.key_loaded && status.key_exists && (
        <div style={{ marginTop: 8, fontSize: '.8rem', color: 'var(--dim)' }}>
          A key from an earlier run is still stored and is reused if you turn encryption on again.{' '}
          <button className="btn btn-sm" disabled={busy} onClick={() => { if (confirm('Delete the stored MariaDB key? Nothing is encrypted with it any more.')) act(() => adminApi.post<Status>('/api/managed-db/encryption/unload-key', { delete_key: true })) }}>Delete key</button>
        </div>
      )}
      {msg && <div style={{ marginTop: 6, fontSize: '.8rem', color: msg.ok ? 'var(--dim)' : 'var(--red)' }}>{msg.text}</div>}
    </div>
  )
}
