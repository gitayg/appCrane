import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import { uploadZip, type Analysis, type SourceGuide } from './adoptTypes'

interface Props {
  guides: SourceGuide[]
  maxBytes: number | null
  onAnalyzed: (a: Analysis) => void
}

export function SourceStep({ guides, maxBytes, onAnalyzed }: Props) {
  const [mode, setMode] = useState<'github' | 'zip'>('github')
  const [url, setUrl] = useState('')
  const [ref, setRef] = useState('')
  const [token, setToken] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function analyze(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const a = mode === 'zip'
        ? await uploadZip(file as File)
        : await adminApi.post<Analysis>('/api/adopt/analyze', { github_url: url.trim(), ...(ref.trim() ? { ref: ref.trim() } : {}), ...(token ? { github_token: token } : {}) })
      setToken('')
      onAnalyzed(a)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const ready = mode === 'zip' ? !!file : url.trim().length > 0

  return (
    <form onSubmit={analyze} className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" className={`btn btn-sm${mode === 'github' ? ' btn-accent' : ''}`} onClick={() => setMode('github')}>GitHub repository</button>
        <button type="button" className={`btn btn-sm${mode === 'zip' ? ' btn-accent' : ''}`} onClick={() => setMode('zip')}>Upload a zip</button>
      </div>

      {mode === 'github' ? (
        <>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem' }}>
            Repository URL
            <input className="az-input" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repo" autoFocus />
          </label>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem', flex: '0 0 200px' }}>
              Branch or tag (optional)
              <input className="az-input" value={ref} onChange={e => setRef(e.target.value)} placeholder="default branch" />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem', flex: 1, minWidth: 240 }}>
              GitHub token, for a private repository (used once, not stored)
              <PasswordInput label="GitHub token" value={token} onChange={e => setToken(e.target.value)} autoComplete="off" />
            </label>
          </div>
        </>
      ) : (
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem' }}>
          Project zip{maxBytes ? ` (up to ${Math.round(maxBytes / 1024 / 1024)} MB)` : ''}
          <input type="file" accept=".zip" onChange={e => setFile(e.target.files?.[0] || null)} />
        </label>
      )}

      <div>
        <button type="submit" className="btn btn-accent" disabled={!ready || busy}>{busy ? 'Analysing...' : 'Analyse'}</button>
        <span style={{ marginLeft: 10, color: 'var(--dim)', fontSize: '.78rem' }}>Nothing is run: AppCrane reads the files and reports what it finds.</span>
      </div>
      {error && <div style={{ color: '#fca5a5', fontSize: '.85rem' }}>{error}</div>}

      {guides.length > 0 && (
        <details style={{ fontSize: '.8rem', color: 'var(--dim)' }}>
          <summary style={{ cursor: 'pointer' }}>Where do I get the code from Lovable, Bolt, v0, Replit or Figma Make?</summary>
          <ul style={{ margin: '8px 0 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {guides.map(g => <li key={g.tool}><strong>{g.label}:</strong> {g.steps}</li>)}
          </ul>
        </details>
      )}
    </form>
  )
}
