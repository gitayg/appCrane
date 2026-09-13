import { useEffect, useState } from 'react'
import { adminApi, authHeaders } from '../adminApi'

// Applications → gh app: attach one connected app to this instance's GitHub
// App installation, or detach it (v2.75.0).

interface AppGithubAppState {
  app_configured: boolean
  app_slug: string | null
  install_url: string | null
  eligible: boolean
  repo_full_name: string | null
  attached: boolean
  installation_id: number | null
  attached_repo: string | null
  attached_at: string | null
  has_github_token: boolean
}

export function GithubAppModal({ slug, name, onClose }: { slug: string; name: string; onClose: () => void }) {
  const [st, setSt] = useState<AppGithubAppState | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function load() {
    adminApi.get<AppGithubAppState>(`/api/apps/${slug}/github-app`).then(setSt).catch(e => setError(String(e.message || e)))
  }
  useEffect(load, [slug])

  async function attach() {
    setBusy(true); setError(null)
    try { await adminApi.put(`/api/apps/${slug}/github-app`, {}); load() }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  async function detach() {
    if (!confirm(`Stop using the GitHub App for "${name}"?${st?.has_github_token ? '\n\nThe app will authenticate with its stored personal access token again.' : ''}`)) return
    setBusy(true); setError(null)
    try {
      const r = await fetch(`/api/apps/${slug}/github-app`, { method: 'DELETE', headers: authHeaders() })
      if (!r.ok) {
        const body = await r.json().catch(() => ({}))
        throw new Error((body as { error?: { message?: string } }).error?.message || `HTTP ${r.status}`)
      }
      load()
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={onClose}
    >
      <div
        style={{ width: 'min(520px, 92vw)', background: 'var(--surface, #1a1a1a)', color: 'var(--text)', border: '1px solid var(--border, #333)', borderRadius: 8, boxShadow: '0 16px 48px rgba(0,0,0,.5)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-label={`GitHub App for ${name}`}
      >
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border, #333)', background: 'var(--surface2, #232323)', fontWeight: 600, fontSize: '.95rem' }}>
          GitHub App · {name}
        </div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, fontSize: '.85rem' }}>
          {error && <p style={{ margin: 0, color: 'var(--red)' }}>{error}</p>}
          {st === null ? (
            <p style={{ margin: 0, color: 'var(--dim)' }}>Loading…</p>
          ) : !st.app_configured ? (
            <p style={{ margin: 0, color: 'var(--dim)' }}>No GitHub App is set up on this AppCrane yet. A platform admin creates one at Settings → GitHub.</p>
          ) : !st.eligible ? (
            <p style={{ margin: 0, color: 'var(--dim)' }}>Only apps connected to a GitHub repository can use the GitHub App.</p>
          ) : st.attached ? (
            <>
              <p style={{ margin: 0 }}>
                Using installation <code style={{ fontFamily: 'monospace' }}>{st.installation_id}</code> for{' '}
                <code style={{ fontFamily: 'monospace' }}>{st.attached_repo}</code>. Deploys, the commit check, update checks
                and the PR poller use short-lived installation tokens.
              </p>
              {st.attached_repo && st.repo_full_name && st.attached_repo.toLowerCase() !== st.repo_full_name.toLowerCase() && (
                <p style={{ margin: 0, color: 'var(--red)' }}>
                  The app now points at {st.repo_full_name}. Deploys will fail until you attach again.
                </p>
              )}
              {st.has_github_token && (
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  A personal access token is still stored on this app. It is not used while the GitHub App is attached; clear it once you are confident.
                </p>
              )}
            </>
          ) : (
            <p style={{ margin: 0 }}>
              Install <code style={{ fontFamily: 'monospace' }}>{st.app_slug}</code> on{' '}
              <code style={{ fontFamily: 'monospace' }}>{st.repo_full_name}</code>
              {st.install_url && <> (<a href={st.install_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>install ↗</a>)</>},
              then attach it here.
            </p>
          )}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            {st?.app_configured && st.eligible && (
              st.attached
                ? <button className="btn btn-xs btn-red" disabled={busy} onClick={detach}>Detach</button>
                : <button className="btn btn-xs" disabled={busy} onClick={attach}>{busy ? 'Attaching…' : 'Attach'}</button>
            )}
            <button className="btn btn-xs" onClick={onClose}>Close</button>
          </div>
        </div>
      </div>
    </div>
  )
}
