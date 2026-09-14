import { useCallback, useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'

// Stored .env files of a Crane-hosted app (/api/apps/:slug/env-files). Kept
// outside the repository, encrypted, and written into each release at deploy.
// Rendered inside AppManager, so it uses that page's .app-manager classes.
//
// The list call decides visibility: 403 (not this app's owner) and 409 (not
// Crane-hosted) render nothing, because neither is something this viewer can
// act on. Content is fetched only when the owner asks for it (the reveal is
// audited and throttled server-side), never with the list.

type EnvName = 'production' | 'sandbox'

interface StoredFile { env: EnvName; path: string; mode: string; bytes: number; source: string; updated_at: string }
interface ListResp { files: StoredFile[] }
interface ContentResp { content: string }
interface WriteResp { message?: string }

interface Props {
  slug: string
  env: EnvName
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
  onDeploy: () => void
}

interface Editor { path: string; isNew: boolean; content: string; base64: string | null; fileName: string | null }

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(bin)
}

export function StoredEnvFilesCard({ slug, env, reload, onMsg, onDeploy }: Props) {
  const [files, setFiles] = useState<StoredFile[] | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [busy, setBusy] = useState(false)
  const [showBanner, setShowBanner] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await fetch(`/api/apps/${encodeURIComponent(slug)}/env-files`, { headers: adminApi.authHeaders() })
      if (r.status === 403 || r.status === 409 || r.status === 404) { setHidden(true); return }
      const body = await r.json().catch(() => ({}))
      if (!r.ok) { setError((body as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`); return }
      setHidden(false)
      setFiles((body as ListResp).files || [])
    } catch (e) {
      setError((e as Error).message || 'Cannot load stored .env files')
    }
  }, [slug])

  useEffect(() => { setEditor(null); setShowBanner(false); void load() }, [load, reload, env])

  if (hidden) return null

  const q = (path: string) => `env=${encodeURIComponent(env)}&path=${encodeURIComponent(path)}`

  async function loadContent() {
    if (!editor || editor.isNew) return
    setBusy(true)
    try {
      const d = await adminApi.get<ContentResp>(`/api/apps/${encodeURIComponent(slug)}/env-files/content?${q(editor.path)}`)
      setEditor({ ...editor, content: d.content, base64: null, fileName: null })
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function pickFile(f: File | undefined) {
    if (!f || !editor) return
    const buf = await f.arrayBuffer()
    setEditor({ ...editor, base64: toBase64(buf), fileName: f.name, content: '' })
  }

  async function save() {
    if (!editor) return
    const path = editor.path.trim()
    if (!path) return
    setBusy(true)
    try {
      const body = editor.base64 !== null
        ? { env, path, content: editor.base64, encoding: 'base64' }
        : { env, path, content: editor.content }
      const d = await adminApi.put<WriteResp>(`/api/apps/${encodeURIComponent(slug)}/env-files`, body)
      onMsg({ text: d.message || 'Saved', ok: true })
      setEditor(null)
      setShowBanner(true)
      void load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function remove(path: string) {
    if (!confirm(`Delete the stored ${path} for ${env}? The next deploy will no longer write it into the release.`)) return
    try {
      const d = await adminApi.del<WriteResp>(`/api/apps/${encodeURIComponent(slug)}/env-files?${q(path)}`)
      onMsg({ text: d.message || 'Deleted ' + path, ok: true })
      if (editor?.path === path) setEditor(null)
      setShowBanner(true)
      void load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    }
  }

  const rows = (files || []).filter(f => f.env === env)

  return (
    <>
      <h2 className="am-h2">Stored .env files</h2>
      {showBanner && (
        <div className="env-redeploy-banner">
          <span>⚠ Stored .env file changes take effect on the next deploy.</span>
          <button className="btn btn-sm" style={{ background: 'var(--yellow)', color: '#000', fontWeight: 700 }} onClick={onDeploy}>Redeploy Now</button>
        </div>
      )}
      <div className="am-card">
        <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 8 }}>
          Kept outside the repository, encrypted, and written into each {env} release before the build. Environment variables override matching keys.
        </div>
        {error ? (
          <span style={{ color: 'var(--red)' }}>{error}</span>
        ) : files === null ? 'Loading...' : !rows.length ? (
          <span style={{ color: 'var(--dim)' }}>No stored .env files for {env}</span>
        ) : (
          <table>
            <thead>
              <tr><th>Path</th><th>Mode</th><th>Size</th><th>Updated</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map(f => (
                <tr key={f.path}>
                  <td className="am-mono">{f.path}</td>
                  <td className="am-mono">{f.mode}</td>
                  <td>{f.bytes} B</td>
                  <td>{f.updated_at}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn btn-sm btn-dim" onClick={() => setEditor({ path: f.path, isNew: false, content: '', base64: null, fileName: null })}>Replace</button>{' '}
                    <button className="btn btn-sm btn-red" onClick={() => remove(f.path)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {editor ? (
          <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {editor.isNew ? (
              <input
                className="am-input"
                placeholder=".env or web/.env.production"
                value={editor.path}
                onChange={e => setEditor({ ...editor, path: e.target.value })}
              />
            ) : (
              <div className="am-mono">Replace {editor.path} ({env})</div>
            )}
            {editor.base64 !== null ? (
              <div style={{ fontSize: '.85rem' }}>
                Uploading file <span className="am-mono">{editor.fileName}</span>{' '}
                <button className="btn btn-sm btn-dim" onClick={() => setEditor({ ...editor, base64: null, fileName: null })}>Use text instead</button>
              </div>
            ) : (
              <textarea
                className="am-input am-mono"
                rows={10}
                spellCheck={false}
                placeholder="KEY=value"
                value={editor.content}
                onChange={e => setEditor({ ...editor, content: e.target.value })}
              />
            )}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {!editor.isNew && editor.base64 === null && (
                <button className="btn btn-sm btn-dim" disabled={busy} onClick={loadContent}>Load current content</button>
              )}
              <button className="btn btn-sm btn-dim" onClick={() => fileInput.current?.click()}>Choose file…</button>
              <input ref={fileInput} type="file" style={{ display: 'none' }} onChange={e => { void pickFile(e.target.files?.[0]); e.target.value = '' }} />
              <button className="btn btn-sm" disabled={busy || !editor.path.trim()} onClick={save}>Save</button>
              <button className="btn btn-sm btn-dim" onClick={() => setEditor(null)}>Cancel</button>
            </div>
          </div>
        ) : (
          <div className="add-row">
            <button className="btn btn-sm" onClick={() => setEditor({ path: '.env', isNew: true, content: '', base64: null, fileName: null })}>Add .env file</button>
          </div>
        )}
      </div>
    </>
  )
}
