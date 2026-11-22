import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { setVisibleInterval } from '../../utils/visibleInterval'
import { limitsAppliedText, type LimitApply } from '../../utils/limitsApplied'
import { guaranteedHint } from '../../utils/guaranteedMemory'
import { BackupsCard } from '../BackupsCard'
import { ManagedDatabaseCard } from '../ManagedDatabaseCard'
import { LlmGatewayAppCard } from '../llm/LlmGatewayAppCard'
import { EnvTable, type EnvRow } from './EnvTable'
import { MetricsHistory } from './MetricsChart'
import { healthOf } from './OverviewTab'
import { useEnvStatus } from './useEnvStatus'
import { errText, fmtBytes, fmtUptime } from './format'
import { ENVS, type EnvName, type ManageCtx } from './types'

type Proc = { status?: string; cpu?: number; memory?: number; uptime?: number; restarts?: number }

function NumberEdit({ value, min, max, disabled, title, onSave, label }: { value?: number; min: number; max: number; disabled?: boolean; title?: string; onSave: (v: string) => Promise<void>; label: string }) {
  const [v, setV] = useState(value == null ? '' : String(value))
  useEffect(() => setV(value == null ? '' : String(value)), [value])
  const dirty = v !== (value == null ? '' : String(value))
  return (
    <span className="am2-row" title={title}>
      <input className="am2-input" type="number" min={min} max={max} value={v} disabled={disabled} onChange={e => setV(e.target.value)} style={{ width: 90 }} aria-label={label} placeholder="none" />
      {!disabled && dirty && <button className="btn btn-xs" onClick={() => onSave(v)}>Save</button>}
    </span>
  )
}

export function ResourcesTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, app, isPlatformAdmin } = ctx
  const st = useEnvStatus(slug, ctx.reload)
  const [proc, setProc] = useState<Partial<Record<EnvName, Proc | null>>>({})
  const [total, setTotal] = useState<number | null | undefined>(undefined)

  const poll = useCallback(() => {
    for (const env of ENVS) {
      adminApi.get<{ process?: Proc }>(`/api/apps/${slug}/metrics/${env}`)
        .then(d => setProc(p => ({ ...p, [env]: d.process && d.process.status && d.process.status !== 'unknown' ? d.process : null })))
        .catch(() => setProc(p => ({ ...p, [env]: null })))
    }
  }, [slug])
  useEffect(() => { poll(); return setVisibleInterval(poll, 10000) }, [poll])
  useEffect(() => {
    adminApi.get<{ apps: { slug: string; total_bytes: number }[] }>('/api/dashboard/app-storage')
      .then(r => setTotal(r.apps.find(a => a.slug === slug)?.total_bytes ?? null))
      .catch(() => setTotal(null))
  }, [slug, ctx.reload])

  async function saveLimit(field: 'max_ram_mb' | 'max_cpu_percent', raw: string) {
    const n = raw.trim() ? Number(raw) : null
    if (raw.trim() && (isNaN(n!) || n! < 0)) return
    try {
      const r = await adminApi.put<{ limits_applied?: LimitApply[] }>(`/api/apps/${slug}`, { [field]: n })
      ctx.onMsg(limitsAppliedText(r?.limits_applied))
      ctx.patchApp({ resource_limits: { ...(app.resource_limits || {}), [field]: n ?? undefined } })
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function saveImages(raw: string) {
    const n = parseInt(raw, 10)
    if (isNaN(n) || n < 0 || n > 50) return ctx.onMsg({ text: 'Image retention must be 0-50', ok: false })
    try { await adminApi.put(`/api/apps/${slug}`, { image_retention: n }); ctx.patchApp({ image_retention: n }); ctx.onMsg({ text: 'Saved', ok: true }) }
    catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  const p = (env: EnvName, f: (x: Proc) => string) => {
    const x = proc[env]
    if (x === undefined) return '…'
    if (!x || x.status === 'stopped') return <span className="am2-dim">{x?.status || 'Not running'}</span>
    return f(x)
  }
  const ram = app.resource_limits?.max_ram_mb
  const adminOnly = isPlatformAdmin ? undefined : 'Only platform admins can change CPU/memory limits'
  const rows: EnvRow[] = [
    { key: 'cpu', label: 'CPU now', production: p('production', x => `${(x.cpu || 0).toFixed(1)}%`), sandbox: p('sandbox', x => `${(x.cpu || 0).toFixed(1)}%`) },
    { key: 'mem', label: 'Memory now', production: p('production', x => fmtBytes(x.memory)), sandbox: p('sandbox', x => fmtBytes(x.memory)) },
    { key: 'uptime', label: 'Uptime', production: p('production', x => fmtUptime(x.uptime)), sandbox: p('sandbox', x => fmtUptime(x.uptime)) },
    { key: 'restarts', label: 'Container restarts', production: p('production', x => String(x.restarts || 0)), sandbox: p('sandbox', x => String(x.restarts || 0)) },
    { key: 'data', label: 'Persistent /data', ...Object.fromEntries(ENVS.map(e => [e, st.storage === null ? '…' : st.storage === 'error' ? 'n/a' : fmtBytes(st.storage[e])])) },
    { key: 'total', label: 'Total on disk', both: total === undefined ? '…' : total === null ? <span className="am2-dim">—</span> : <span title="Release checkouts + persistent /data, both environments">{fmtBytes(total)}</span> },
    { key: 'ram', label: 'Memory cap (MB)', both: <span className="am2-row"><NumberEdit label="Memory cap in MB" value={ram} min={0} max={65536} disabled={!isPlatformAdmin} title={adminOnly} onSave={v => saveLimit('max_ram_mb', v)} />{typeof ram === 'number' && <span className="am2-small am2-dim">{guaranteedHint(ram)}</span>}</span> },
    { key: 'cpucap', label: 'CPU cap (%)', both: <NumberEdit label="CPU cap in percent" value={app.resource_limits?.max_cpu_percent} min={0} max={1600} disabled={!isPlatformAdmin} title={adminOnly} onSave={v => saveLimit('max_cpu_percent', v)} /> },
    { key: 'images', label: 'Images kept', both: <span className="am2-row"><NumberEdit label="Image retention count" value={app.image_retention} min={0} max={50} onSave={saveImages} /><span className="am2-small am2-dim">Older images to keep for fast rollback.</span></span> },
    {
      key: 'backups', label: 'Backups',
      production: <BackupsCard slug={slug} env="production" reload={ctx.reload} onMsg={ctx.onMsg} />,
      sandbox: <BackupsCard slug={slug} env="sandbox" reload={ctx.reload} onMsg={ctx.onMsg} />,
    },
  ]
  return (
    <>
      <EnvTable caption="Resources" rows={rows} dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))} />
      <div className="am2-cards">
        <MetricsHistory slug={slug} reload={ctx.reload} />
        <ManagedDatabaseCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <LlmGatewayAppCard slug={slug} isPlatformAdmin={isPlatformAdmin} onMsg={ctx.onMsg} />
      </div>
    </>
  )
}
