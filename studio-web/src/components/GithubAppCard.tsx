import { useEffect, useState } from 'react'
import { adminApi, authHeaders } from '../adminApi'
import { FocusInput } from './formHelpers'

// Settings → GitHub: this instance's own GitHub App (v2.75.0).
//
// Creation uses GitHub's App-manifest flow, which needs a real form POST to
// github.com. GitHub then redirects back to /settings with ?code&state; this
// card picks those up and finishes the exchange with the admin's credential,
// which is what the server binds the state to.

interface GithubAppStatus {
  configured: boolean
  github_app_id?: number
  slug?: string
  owner_login?: string | null
  html_url?: string | null
  install_url?: string | null
  created_at?: string
  attached_apps: { app_id: number; slug: string; installation_id: number; repo_full_name: string }[]
}

interface ManifestStart {
  action: string
  state: string
  manifest: Record<string, unknown>
}

export function GithubAppCard() {
  const [status, setStatus] = useState<GithubAppStatus | null>(null)
  const [org, setOrg] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function load() {
    adminApi.get<GithubAppStatus>('/api/github-app').then(setStatus).catch(e => setError(String(e.message || e)))
  }

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    if (code && state) {
      // Remove the one-time values from the address bar before anything else,
      // so a reload cannot replay them and they do not sit in history.
      window.history.replaceState(null, '', `${window.location.pathname}#github`)
      setBusy(true)
      adminApi.post('/api/github-app/exchange', { code, state })
        .catch(e => setError(String(e.message || e)))
        .finally(() => { setBusy(false); load() })
      return
    }
    load()
  }, [])

  async function create() {
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const start = await adminApi.post<ManifestStart>('/api/github-app/manifest', org.trim() ? { org: org.trim() } : {})
      const form = document.createElement('form')
      form.method = 'post'
      form.action = `${start.action}?state=${encodeURIComponent(start.state)}`
      const input = document.createElement('input')
      input.type = 'hidden'
      input.name = 'manifest'
      input.value = JSON.stringify(start.manifest)
      form.appendChild(input)
      document.body.appendChild(form)
      form.submit()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  async function disconnect() {
    if (!status?.configured || busy) return
    if (!confirm(`Forget the GitHub App "${status.slug}" on this AppCrane?\n\nGitHub has no API to delete an App — delete it on GitHub too.`)) return
    setBusy(true)
    try {
      let r = await fetch('/api/github-app', { method: 'DELETE', headers: authHeaders() })
      if (r.status === 409) {
        const body = await r.json().catch(() => ({}))
        const msg = (body as { error?: { message?: string } }).error?.message || 'Apps are still attached.'
        if (!confirm(`${msg}\n\nDetach them and delete anyway?`)) return
        r = await fetch('/api/github-app?force=1', { method: 'DELETE', headers: authHeaders() })
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="setting-card">
      <h3>GitHub App — connected repositories</h3>
      <p>
        Replace per-app personal access tokens with this instance's own GitHub App. App builders install it on only the
        repositories they choose; AppCrane clones and checks them with one-hour installation tokens that are never stored.
      </p>
      <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: -4 }}>
        Permissions requested: Contents <em>read</em>, Metadata <em>read</em>, Pull requests <em>read</em> (for the PR poller).
        The App cannot push, open pull requests or create webhooks.
      </p>

      {error && <p style={{ color: 'var(--red)', fontSize: '.85rem' }}>{error}</p>}

      {status === null ? (
        <p style={{ color: 'var(--dim)' }}>{busy ? 'Finishing GitHub App registration…' : 'Loading…'}</p>
      ) : status.configured ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 16px', alignItems: 'center', marginTop: 12, maxWidth: 640, fontSize: '.85rem' }}>
          <span style={{ color: 'var(--dim)' }}>App</span>
          <span>
            <code style={{ fontFamily: 'monospace' }}>{status.slug}</code>
            {status.owner_login && <span style={{ color: 'var(--dim)' }}> · owned by {status.owner_login}</span>}
            {status.html_url && <> · <a href={status.html_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>view on GitHub ↗</a></>}
          </span>
          <span style={{ color: 'var(--dim)' }}>Install</span>
          <span>
            {status.install_url
              ? <a href={status.install_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>Install on repositories ↗</a>
              : '—'}
          </span>
          <span style={{ color: 'var(--dim)' }}>Attached apps</span>
          <span>
            {status.attached_apps.length === 0
              ? <span style={{ color: 'var(--dim)' }}>none yet — attach from Applications → gh app</span>
              : status.attached_apps.map(a => `${a.slug} (${a.repo_full_name})`).join(', ')}
          </span>
          <span />
          <span><button className="btn btn-xs btn-red" disabled={busy} onClick={disconnect}>Disconnect</button></span>
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 12, flexWrap: 'wrap' }}>
          <FocusInput
            type="text"
            value={org}
            onChange={e => setOrg(e.target.value)}
            placeholder="GitHub organization (leave empty for your account)"
            style={{ width: 320 }}
          />
          <button className="btn" disabled={busy} onClick={create}>{busy ? 'Opening GitHub…' : 'Create GitHub App'}</button>
        </div>
      )}
    </div>
  )
}
