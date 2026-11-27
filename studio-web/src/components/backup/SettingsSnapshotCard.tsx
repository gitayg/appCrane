import { useRef, useState } from 'react'
import { PasswordInput } from '../secret/PasswordInput'
import { archiveFetch } from './configArchiveFetch'

// Settings > Backup: the platform settings alone, for moving them to another
// AppCrane (server/routes/config.js). Encrypted values stay ciphertext under
// the source key; the import re-encrypts them with this instance's key, using
// the source ENCRYPTION_KEY only for that request. Both calls need a dashboard
// session with a recent step-up and are audited. A snapshot that sets a
// protected setting is refused whole until the person ticks the box.

type ImportResult = {
  imported: number; reencrypted: number; plaintext: number
  errors: string[]; regenerate: string[]; keys: string[]
  protected: { key: string; from: unknown; to: unknown }[]
}
type Snapshot = { kind?: string; settings?: unknown[] }

const PROTECTED = 'PROTECTED_SETTINGS'

async function errorOf(r: Response) {
  const body = await r.json().catch(() => ({}))
  return { code: body?.error?.code as string | undefined, message: body?.error?.message as string | undefined, keys: body?.error?.keys as string[] | undefined }
}

export function SettingsSnapshotCard() {
  const [busy, setBusy] = useState(false)
  const [sourceKey, setSourceKey] = useState('')
  const [includeProtected, setIncludeProtected] = useState(false)
  const [refused, setRefused] = useState<string[] | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  async function download() {
    setBusy(true); setMsg(null); setResult(null)
    try {
      const r = await archiveFetch('/api/config/export')
      if (!r.ok) throw new Error((await errorOf(r)).message || `Export failed (${r.status})`)
      const snap = await r.json()
      const name = `appcrane-settings-${String(snap.exported_at || '').slice(0, 10) || 'export'}.json`
      const url = URL.createObjectURL(new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' }))
      const a = document.createElement('a')
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
      setMsg({ ok: true, text: `Saved ${name}: ${snap.settings?.length ?? 0} settings. Secrets in it are still encrypted with this instance's key.` })
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }) }
    finally { setBusy(false) }
  }

  async function doImport(file: File) {
    setMsg(null); setResult(null); setRefused(null)
    let config: Snapshot
    try { config = JSON.parse(await file.text()) }
    catch { setMsg({ ok: false, text: `${file.name} is not JSON. Choose a file saved by Export settings.` }); return }
    if (config?.kind !== 'appcrane-config' || !Array.isArray(config.settings)) {
      setMsg({ ok: false, text: `${file.name} is not an AppCrane settings export.` }); return
    }
    if (!confirm(`Import ${config.settings.length} settings from "${file.name}"?\n\n`
      + 'Each one overwrites the same setting on this instance. Apps, users and env vars are not touched. The import is audited.')) return
    setBusy(true)
    try {
      const r = await archiveFetch('/api/config/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config, old_key: sourceKey.trim() || undefined, include_protected: includeProtected }),
      })
      if (!r.ok) {
        const err = await errorOf(r)
        if (err.code === PROTECTED && err.keys) { setRefused(err.keys); throw new Error('Nothing was imported: the file sets protected settings (listed below).') }
        throw new Error(err.message || `Import failed (${r.status})`)
      }
      const out = await r.json() as ImportResult
      setResult(out)
      setSourceKey('')
      setMsg({ ok: out.errors.length === 0, text: `Imported ${out.imported} settings (${out.reencrypted} re-encrypted).${out.errors.length ? ` ${out.errors.length} were skipped.` : ''}` })
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }) }
    finally { setBusy(false); if (fileRef.current) fileRef.current.value = '' }
  }

  return (
    <div style={{ marginTop: 24 }}>
      <h3>Settings only</h3>
      <p className="settings-hint">
        Move this instance's platform settings (mail, sign-in, backup destinations, limits and the rest)
        to another AppCrane. Apps, users, env vars and data are not included: use the full backup above for those.
        Secrets stay encrypted in the file. To import them, give the source instance's <code>ENCRYPTION_KEY</code>.
        It is used for that one request and not stored. Both actions ask you to confirm your identity again and are audited.
      </p>
      <button className="btn" onClick={download} disabled={busy}>Export settings (.json)</button>

      <div style={{ marginTop: 12 }}>
        <label style={{ display: 'block', margin: '6px 0' }}>
          Source ENCRYPTION_KEY (only needed for encrypted settings):{' '}
          <PasswordInput label="source encryption key" className="editable" autoComplete="off" value={sourceKey}
            onChange={e => setSourceKey(e.target.value)} placeholder="ENCRYPTION_KEY of the instance that exported the file"
            style={{ width: 360, maxWidth: '100%' }} />
        </label>
        <label style={{ display: 'block', margin: '6px 0' }}>
          <input type="checkbox" checked={includeProtected} onChange={e => setIncludeProtected(e.target.checked)} />
          {' '}Also import protected settings (each one is audited with its old and new value)
        </label>
        <input ref={fileRef} type="file" accept=".json,application/json" style={{ display: 'none' }}
          onChange={e => { const f = e.target.files?.[0]; if (f) doImport(f) }} />
        <button className="btn" onClick={() => fileRef.current?.click()} disabled={busy}>
          {busy ? 'Working…' : 'Import settings (.json)'}
        </button>
      </div>

      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.85rem' }}>{msg.text}</p>}
      {refused && (
        <div className="settings-hint">
          Protected settings in this file: {refused.map(k => <code key={k} style={{ marginRight: 6 }}>{k}</code>)}
          <br />Remove them from the file, or tick "Also import protected settings" and import again.
        </div>
      )}
      {result && result.errors.length > 0 && (
        <ul className="settings-hint">{result.errors.map(e => <li key={e}>{e}</li>)}</ul>
      )}
      {result && result.regenerate.length > 0 && (
        <p className="settings-hint">
          Set these again on this instance (they are stored as one-way hashes and cannot be moved): {result.regenerate.map(k => <code key={k} style={{ marginRight: 6 }}>{k}</code>)}
        </p>
      )}
    </div>
  )
}
