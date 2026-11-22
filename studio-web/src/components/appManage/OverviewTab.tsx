import { useEffect, useState, type ReactNode } from 'react'
import { adminApi } from '../../adminApi'
import { appOpenUrl } from '../../lib/appLinks'
import { SAND_HIDDEN_HINT } from '../../topbar-element/CraneAppTopbar'
import { OwnershipCard } from '../ownership/OwnershipCard'
import { AppTimeline } from '../events/AppTimeline'
import { EnvTable, type EnvDot, type EnvRow } from './EnvTable'
import { AppDetailsCard } from './AppDetailsCard'
import { DeployProgress } from './DeployProgress'
import { useEnvActions } from './useEnvActions'
import { useEnvStatus } from './useEnvStatus'
import { loadReleases, type Release } from './releaseApi'
import { errText, fmtBytes, relTime } from './format'
import { ENVS, type EnvName, type ManageCtx } from './types'

export function healthOf(ctx: ManageCtx, env: EnvName): { dot: EnvDot; text: string; cls: string } {
  const state = ctx.detail?.health?.[env]?.state
  const list = ctx.app[env]?.health?.status
  const deployed = !!ctx.app[env]?.deploy?.version || ctx.app[env]?.deploy?.status === 'live'
  if (state?.is_down || list === 'down') return { dot: 'red', text: 'Down', cls: 'bad' }
  if (state?.last_status === 200 || list === 'healthy') return { dot: 'green', text: state?.last_response_ms ? `Healthy · ${state.last_response_ms}ms` : 'Healthy', cls: 'ok' }
  if (!deployed) return { dot: 'gray', text: 'Not deployed', cls: '' }
  return { dot: 'yellow', text: 'No health response', cls: 'warn' }
}

export function OverviewTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, app, canAdmin, isOwner, isPlatformAdmin } = ctx
  const st = useEnvStatus(slug, ctx.reload)
  const act = useEnvActions(slug, ctx.onMsg, ctx.refresh)
  const [latestRel, setLatestRel] = useState<Partial<Record<EnvName, Release>>>({})

  useEffect(() => {
    if (!canAdmin) return
    let off = false
    loadReleases(slug).then(r => {
      if (off) return
      const by: Partial<Record<EnvName, Release>> = {}
      for (const x of r.releases) if (!by[x.env]) by[x.env] = x
      setLatestRel(by)
    }).catch(() => {})
    return () => { off = true }
  }, [slug, canAdmin, ctx.reload])

  const sandHidden = app.sandbox_visible === false
  const mayPromote = isOwner || isPlatformAdmin
  const per = (f: (env: EnvName) => ReactNode) => ({
    production: f('production'),
    sandbox: sandHidden ? <span className="am2-dim" title="The app owner does not show Sandbox to users">Hidden</span> : f('sandbox'),
  })

  async function testHealth(env: EnvName) {
    ctx.onMsg({ text: 'Testing health…', ok: true })
    try {
      const d = await adminApi.post<{ healthy?: boolean; status?: number | string; response_ms?: number; error?: string }>(`/api/apps/${slug}/health/${env}/test`)
      ctx.onMsg(d.healthy ? { text: `Healthy: ${d.status} (${d.response_ms}ms)`, ok: true } : { text: `Failed: ${d.error || d.status}`, ok: false })
      ctx.refresh()
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function wake(env: EnvName) {
    try { await adminApi.post(`/api/apps/${slug}/sleep/${env}/wake`); ctx.onMsg({ text: `Waking ${env}`, ok: true }); setTimeout(ctx.refresh, 2000) }
    catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  const version = (env: EnvName) => {
    const v = st.latest[env]?.status === 'live' ? st.latest[env]?.version : app[env]?.deploy?.version
    if (!v) return <span className="am2-dim">—</span>
    const text = v.startsWith('v') ? v : `v${v}`
    return canAdmin
      ? <button className="am2-pill info" onClick={() => ctx.setTab('releases')} title="Open the release log" aria-label={`${text}, open the release log`}>{text}</button>
      : <span className="am2-pill">{text}</span>
  }

  const deployed = (env: EnvName) => {
    const d = st.latest[env]
    if (d === undefined) return <span className="am2-dim">…</span>
    if (!d) return <span className="am2-dim">Never</span>
    const rel = latestRel[env]
    const by = rel?.deployed_by?.name || d.deployed_by_name
    return (
      <div>
        <div className="am2-row">
          <span title={d.finished_at || d.started_at}>{relTime(d.finished_at || d.started_at)}</span>
          {by && <span className="am2-dim">by {by}</span>}
          {rel?.deployed_by && <span className={'am2-pill' + (rel.deployed_by.kind === 'agent' ? ' info' : '')}>{rel.deployed_by.kind}</span>}
          {d.status !== 'live' && <span className={'badge ' + (d.status === 'failed' ? 'badge-failed' : d.status === 'rolled_back' ? 'badge-pending' : 'badge-building')}>{d.status}</span>}
        </div>
        <DeployProgress slug={slug} env={env} latest={d} onDone={ctx.refresh} />
      </div>
    )
  }

  const status = (env: EnvName) => {
    const h = healthOf(ctx, env)
    const sl = st.sleep?.[env]
    const ahead = st.updates?.[env]?.update_available
    return (
      <div className="am2-row">
        <span className={'am2-pill ' + h.cls}><span className={`dot dot-${h.dot}`} />{h.text}</span>
        {sl && <span className={'am2-pill' + (sl.state === 'asleep' ? ' warn' : '')}>{sl.state === 'asleep' ? 'Asleep' : 'Awake'}</span>}
        {ahead && <span className="am2-pill info" title={st.updates?.latest_message || ''}>New commits · {st.updates?.latest_sha}</span>}
        {st.updates && !ahead && !st.updates.error && <span className="am2-pill">Up to date</span>}
        <button className="btn btn-xs" onClick={() => testHealth(env)}>Test</button>
      </div>
    )
  }

  const commit = (env: EnvName) => {
    const d = st.latest[env]
    if (!d?.commit_hash) return <span className="am2-dim">—</span>
    const note = (d.commit_message || '').split('\n')[0]
    return <div><span className="am2-mono">{d.commit_hash.slice(0, 10)}</span>{note && <div className="am2-small am2-dim" style={{ marginTop: 2 }}>{note.length > 90 ? note.slice(0, 90) + '…' : note}</div>}</div>
  }

  const url = (env: EnvName) => {
    const u = appOpenUrl(app, env)
    const down = app[env]?.health?.status === 'down'
    return (
      <div>
        {down ? <span className="am2-mono am2-dim" title={`${env} is down`}>{u}</span> : <a className="am2-mono" href={u} target="_blank" rel="noreferrer">{u} ↗</a>}
        {env === 'production' && app.domain && <div className="am2-small am2-dim">Custom domain: {app.domain}</div>}
        {env === 'sandbox' && app.show_sandbox === false && <div className="am2-small am2-dim" title={SAND_HIDDEN_HINT}>Hidden from users</div>}
      </div>
    )
  }

  const storage = (env: EnvName) => st.storage === null ? '…' : st.storage === 'error' ? 'n/a' : <span title="Persistent storage used by this environment's /data volume">{fmtBytes(st.storage[env])}</span>
  const runtime = (env: EnvName) => {
    const r = st.runtime?.envs?.[env]
    if (!r) return <span className="am2-dim">—</span>
    const name = (x: string | null) => x === 'runsc' ? 'gVisor (runsc)' : x === 'runc' ? 'runc' : x || 'not running'
    return <span className="am2-row"><span>{name(r.applied ?? r.desired)}</span>{r.drift && <span className="am2-pill warn" title={r.notice}>Policy: {name(r.desired)}</span>}</span>
  }
  const sleep = (env: EnvName) => {
    const s = st.sleep?.[env]
    if (!s) return <span className="am2-dim">—</span>
    if (s.state === 'asleep') return <span className="am2-row"><span>Asleep {relTime(s.slept_at)}{s.reason ? ` (${s.reason})` : ''}</span><button className="btn btn-xs" onClick={() => wake(env)}>Wake</button></span>
    return <span className="am2-dim">{s.last_request_at ? `Last request ${relTime(s.last_request_at)}` : 'No requests recorded'}</span>
  }

  const logs = (env: EnvName) => <button className="btn btn-xs" onClick={() => ctx.setTab('logs', { env })}>Logs</button>
  const actions: EnvRow = {
    key: 'actions', label: 'Actions',
    ...per(env => env === 'production' ? (
      <span className="am2-row">
        <button className="btn btn-xs" onClick={() => act.restart('production')}>Restart</button>
        {logs('production')}
        {mayPromote && <button className="btn btn-xs" onClick={() => act.rollback('production')}>Roll back</button>}
        <button className="btn btn-xs" onClick={() => act.deploy('production')} title="Build and deploy production from its branch">Deploy</button>
      </span>
    ) : (
      <span className="am2-row">
        <button className="btn btn-xs btn-accent" onClick={() => act.deploy('sandbox')}>Deploy</button>
        <button className="btn btn-xs" onClick={() => act.restart('sandbox')}>Restart</button>
        {logs('sandbox')}
        {mayPromote && <button className="btn btn-xs" onClick={() => act.rollback('sandbox')}>Roll back</button>}
      </span>
    )),
  }

  const rows: EnvRow[] = [
    { key: 'status', label: 'Status', ...per(status) },
    { key: 'version', label: 'Version', ...per(version), diff: !sandHidden && (app.production?.deploy?.version || '') !== (app.sandbox?.deploy?.version || '') },
    { key: 'deployed', label: 'Deployed', ...per(deployed) },
    { key: 'commit', label: 'Commit', ...per(commit) },
    { key: 'url', label: 'URL', ...per(url) },
    { key: 'storage', label: 'Storage', ...per(storage) },
    { key: 'runtime', label: 'Runtime', ...per(runtime) },
    { key: 'sleep', label: 'Sleep', ...per(sleep) },
    actions,
  ]

  return (
    <>
      <EnvTable
        caption="Environments"
        rows={rows}
        dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))}
        onPromote={mayPromote && !sandHidden ? act.promote : undefined}
      />
      <div className="am2-cards">
        <OwnershipCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <AppDetailsCard ctx={ctx} />
        <AppTimeline slug={slug} />
      </div>
      {act.modal}
    </>
  )
}
