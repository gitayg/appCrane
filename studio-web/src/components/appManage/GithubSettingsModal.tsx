import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { GithubAppModal } from '../GithubAppModal'
import { GithubSyncStatus } from '../GithubSyncStatus'
import { GithubExportButton } from '../GithubExportButton'
import { Modal } from './Modal'
import { errText } from './format'
import type { ManageCtx } from './types'

type HookCfg = { token?: string; auto_deploy_sandbox?: boolean; auto_deploy_prod?: boolean; branch_filter?: string }
type UpdatesRes = {
  latest_sha?: string
  production?: { update_available?: boolean }
  sandbox?: { update_available?: boolean }
  error?: { message?: string }
}

/** Repository, auto-deploy, GitHub App, sync, export and git clone, moved from the apps list's drawer. */
export function GithubSettingsModal({ ctx, onClose }: { ctx: ManageCtx; onClose: () => void }) {
  const { app, slug, isPlatformAdmin, isOwner } = ctx
  const [hook, setHook] = useState<HookCfg | null>(null)
  const [repo, setRepo] = useState(app.github_url || '')
  const [updates, setUpdates] = useState('')
  const [ghApp, setGhApp] = useState(false)
  const [copied, setCopied] = useState(false)
  const gitSource = app.source_type === 'github' || app.source_type === 'managed' || !!app.github_url
  const localRepo = app.source_type === 'managed' && app.repo_backend === 'local'
  const mayLink = localRepo && (isPlatformAdmin || isOwner)
  const cloneUrl = `${window.location.origin}/git/${slug}.git`

  useEffect(() => {
    adminApi.get<HookCfg>(`/api/apps/${slug}/webhook`).then(c => setHook(c || {})).catch(() => setHook({}))
  }, [slug])

  async function saveHook(patch: Partial<HookCfg>) {
    setHook(c => ({ ...(c ?? {}), ...patch }))
    try { await adminApi.put(`/api/apps/${slug}/webhook`, patch); ctx.refresh() } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function register() {
    const r = await adminApi.post<{ message?: string; error?: string }>(`/api/apps/${slug}/webhook/register-github`).catch((e): { message?: string; error?: string } => ({ error: errText(e) }))
    alert(r?.message ?? r?.error ?? 'Done')
    const c = await adminApi.get<HookCfg>(`/api/apps/${slug}/webhook`).catch(() => null)
    if (c) setHook(c)
  }

  async function saveRepo(v: string) {
    const value = v.trim()
    try {
      await adminApi.put(`/api/apps/${slug}`, { github_url: value })
      ctx.patchApp({ github_url: value || undefined })
      setRepo(value)
      ctx.onMsg({ text: value ? 'GitHub repository saved' : 'GitHub repository unlinked', ok: true })
    } catch (e) {
      ctx.onMsg({ text: 'Could not save the GitHub repository: ' + errText(e), ok: false })
    }
  }

  async function checkUpdates() {
    setUpdates('Checking…')
    const r = await adminApi.get<UpdatesRes>(`/api/apps/${slug}/updates`).catch(() => null)
    if (!r) return setUpdates('Error')
    if (r.error) return setUpdates(r.error.message || 'Error')
    const envs = [r.production?.update_available ? 'production' : null, r.sandbox?.update_available ? 'sandbox' : null].filter(Boolean)
    setUpdates(envs.length ? `New commits for ${envs.join(' and ')} (${r.latest_sha ?? 'new'})` : 'Up to date')
  }

  return (
    <Modal title={`GitHub settings · ${app.name}`} onClose={onClose}>
      <section>
        <div className="am2-section" style={{ marginTop: 0 }}>Repository</div>
        {mayLink ? (
          <div className="am2-row">
            <input className="am2-input" style={{ flex: 1, minWidth: 220 }} value={repo} placeholder="https://github.com/owner/repo"
              aria-label="GitHub repository" onChange={e => setRepo(e.target.value)} />
            <button className="btn btn-xs" onClick={() => saveRepo(repo)} disabled={repo.trim() === (app.github_url || '')}>Save</button>
            {app.github_url && <button className="btn btn-xs" onClick={() => saveRepo('')}>Clear</button>}
          </div>
        ) : (
          <div>{app.github_url ? <a href={app.github_url} target="_blank" rel="noreferrer">{app.github_url}</a> : <span className="am2-dim">None linked</span>}</div>
        )}
        {mayLink && <p className="am2-dim am2-small" style={{ marginTop: 6 }}>Link the GitHub repository you also push to, to see whether it is ahead of or behind AppCrane's copy.</p>}
        {gitSource && (
          <div className="am2-row" style={{ marginTop: 8 }}>
            <button className="btn btn-xs" onClick={checkUpdates} title="Check GitHub for new commits since last deploy">Check for updates</button>
            {updates && <span className="am2-small">{updates}</span>}
          </div>
        )}
      </section>

      {localRepo && (
        <section>
          <div className="am2-section" style={{ marginTop: 0 }}>Git clone</div>
          <div className="am2-row">
            <code className="am2-mono" style={{ userSelect: 'all' }}>{cloneUrl}</code>
            <button className="btn btn-xs" onClick={() => navigator.clipboard.writeText(cloneUrl).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }).catch(() => {})}>{copied ? 'Copied ✓' : 'Copy'}</button>
          </div>
          <p className="am2-dim am2-small" style={{ marginTop: 6 }}>Username anything, password = your AppCrane API key. Owners and app admins can push (no force pushes or deletions).</p>
        </section>
      )}

      {localRepo && app.github_url && (
        <section>
          <div className="am2-section" style={{ marginTop: 0 }}>Sync with GitHub</div>
          <GithubSyncStatus key={app.github_url} slug={slug} />
          {(isPlatformAdmin || isOwner) && <GithubExportButton slug={slug} />}
        </section>
      )}

      {gitSource && (
        <section>
          <div className="am2-section" style={{ marginTop: 0 }}>Auto-deploy</div>
          <p className="am2-dim am2-small" style={{ marginBottom: 8 }}>Deploy automatically when GitHub pushes to the tracked branch. AppCrane verifies the webhook signature: enable it here, then register the hook on GitHub (or paste the URL into the repo's webhook settings).</p>
          {hook === null ? <span className="am2-dim">Loading…</span> : (
            <div style={{ display: 'grid', gap: 8 }}>
              <label className="am2-row"><input type="checkbox" checked={!!hook.auto_deploy_sandbox} onChange={e => saveHook({ auto_deploy_sandbox: e.target.checked })} /> Auto-deploy sandbox on push</label>
              <label className="am2-row"><input type="checkbox" checked={!!hook.auto_deploy_prod} onChange={e => saveHook({ auto_deploy_prod: e.target.checked })} /> Auto-deploy production on push <span style={{ color: 'var(--red)', fontSize: '.75rem' }}>(use with care)</span></label>
              <label className="am2-row">Branch
                <input className="am2-input" style={{ width: 140 }} defaultValue={hook.branch_filter ?? ''} placeholder="main" onBlur={e => saveHook({ branch_filter: e.target.value.trim() || 'main' })} />
              </label>
              <div>
                <div className="am2-dim am2-small" style={{ marginBottom: 4 }}>Webhook URL (GitHub payload URL)</div>
                <input className="am2-input" readOnly style={{ width: '100%', fontFamily: 'monospace', fontSize: '.75rem' }}
                  value={hook.token ? `${window.location.origin}/api/webhooks/${hook.token}` : 'register to generate…'} onFocus={e => e.currentTarget.select()} />
              </div>
              <div><button className="btn btn-xs" onClick={register}>Register on GitHub</button></div>
            </div>
          )}
        </section>
      )}

      {(app.source_type === 'github' || app.source_type === 'managed') && (
        <section>
          <div className="am2-section" style={{ marginTop: 0 }}>GitHub App</div>
          <button className="btn btn-xs" onClick={() => setGhApp(true)} title="Authenticate with this instance's GitHub App instead of a personal access token">Configure GitHub App…</button>
        </section>
      )}
      {ghApp && <GithubAppModal slug={slug} name={app.name} onClose={() => setGhApp(false)} />}
    </Modal>
  )
}
