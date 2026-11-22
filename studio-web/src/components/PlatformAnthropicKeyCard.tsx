import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { PasswordInput } from './secret/PasswordInput'

// Platform admin: the Anthropic API key AppCrane's own agents fall back to
// (Ask, Coder, enhancements) when the user has no Claude subscription token
// and the app has no credentials.json. Stored encrypted in the database; the
// page only ever shows the last four characters.

interface KeyStatus {
  configured: boolean
  source: 'database' | 'env-legacy' | null
  suffix: string | null
}

export function PlatformAnthropicKeyCard() {
  const [st, setSt] = useState<KeyStatus | null>(null)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  useEffect(() => {
    adminApi.get<KeyStatus>('/api/appstudio/anthropic-key').then(setSt).catch(() => {})
  }, [])

  if (!st) return null

  async function run(fn: () => Promise<KeyStatus & { message: string }>) {
    setBusy(true)
    try {
      const d = await fn()
      setSt({ configured: d.configured, source: d.source, suffix: d.suffix })
      setDraft('')
      setMsg({ text: d.message, ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  const dim = { color: 'var(--dim)', fontSize: '.82rem' }

  return (
    <div className="card">
      <h3>Platform Anthropic API key</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        Used by AppCrane's agents when the person has no Claude subscription connected and the app has no
        credentials.json. Stored encrypted in the AppCrane database, not in .env.
      </p>
      <p style={{ margin: '0 0 10px' }}>
        {st.configured
          ? <>Configured, ends in <span className="am-mono">{st.suffix}</span>
              {st.source === 'env-legacy' && <span style={dim}> (from the environment, not yet saved in the database: save it again here)</span>}</>
          : 'Not configured.'}
      </p>
      <PasswordInput label="Anthropic API key" autoComplete="off" placeholder={st.configured ? 'Enter a key to replace it' : 'sk-ant-...'}
        value={draft} onChange={e => setDraft(e.target.value)} style={{ width: 320 }} />{' '}
      <button className="btn" disabled={busy || !draft.trim()}
        onClick={() => void run(() => adminApi.put('/api/appstudio/anthropic-key', { key: draft.trim() }))}>
        {st.configured ? 'Replace' : 'Save'}
      </button>{' '}
      {st.source === 'database' && (
        <button className="btn" disabled={busy}
          onClick={() => { if (window.confirm('Remove the platform Anthropic API key?')) void run(() => adminApi.del('/api/appstudio/anthropic-key')) }}>
          Clear
        </button>
      )}{' '}
      {msg && <span style={{ color: msg.ok ? 'var(--ok, inherit)' : 'var(--err, #e5484d)' }}>{msg.text}</span>}
    </div>
  )
}
