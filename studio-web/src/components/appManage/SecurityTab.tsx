import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { ReleaseCheckPanel } from '../intake/ReleaseCheckPanel'
import { IntakeCard } from '../intake/IntakeCard'
import { AppSupplyChainCard } from '../imageTrust/AppSupplyChainCard'
import { CapabilitiesCard } from '../capabilities/CapabilitiesCard'
import { AutoPatchAppCard } from '../autoPatch/AutoPatchAppCard'
import { AppAuditCard } from '../appAudit/AppAuditCard'
import { EnvTable, type EnvRow } from './EnvTable'
import { healthOf } from './OverviewTab'
import { errText } from './format'
import { ENVS, type EnvName, type ManageCtx } from './types'
import type { RuntimeEnv } from './useEnvStatus'

type RuntimeView = { runtime?: string; source?: string; envs?: Partial<Record<EnvName, RuntimeEnv>>; takes_effect?: string }
const NAME: Record<string, string> = { runc: 'runc', runsc: 'gVisor (runsc)' }

export function SecurityTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, canAdmin, isPlatformAdmin } = ctx
  const [rt, setRt] = useState<RuntimeView | null>(null)
  useEffect(() => {
    adminApi.get<RuntimeView>(`/api/apps/${slug}/runtime`).then(setRt).catch(() => setRt(null))
  }, [slug, ctx.reload])

  async function setRuntime(v: string) {
    const runtime = v === 'default' ? null : v
    const reason = runtime === 'runc' ? prompt('Reason for running this app without gVisor (recorded):', '') : null
    if (runtime === 'runc' && reason === null) return
    try {
      const r = await adminApi.put<RuntimeView & { redeploy_needed?: boolean }>(`/api/apps/${slug}/runtime`, { runtime, ...(reason ? { reason } : {}) })
      setRt(r)
      ctx.onMsg({ text: `Runtime saved. ${r.takes_effect || 'Applies when the container is next recreated.'}`, ok: true })
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  const runtimeCell = (env: EnvName) => {
    const r = rt?.envs?.[env]
    if (!r) return undefined
    return (
      <span className="am2-row">
        <span>{r.applied ? NAME[r.applied] || r.applied : 'not running'}</span>
        {r.drift && <span className="am2-pill warn" title={r.notice}>Policy: {NAME[r.desired] || r.desired}</span>}
      </span>
    )
  }

  const rows: EnvRow[] = [
    { key: 'runtime', label: 'Container runtime', production: runtimeCell('production'), sandbox: runtimeCell('sandbox') },
    {
      key: 'policy', label: 'Runtime policy',
      both: (
        <span className="am2-row">
          <span>{rt?.runtime ? NAME[rt.runtime] || rt.runtime : '—'}</span>
          {rt?.source && <span className="am2-dim am2-small">from {rt.source}</span>}
          {(canAdmin || isPlatformAdmin) && (
            <select className="am2-input" aria-label="Runtime override" defaultValue="" onChange={e => { if (e.target.value) void setRuntime(e.target.value); e.target.value = '' }}>
              <option value="" disabled>Change…</option>
              <option value="default">Platform default</option>
              <option value="runsc">gVisor (runsc)</option>
              <option value="runc">runc</option>
            </select>
          )}
        </span>
      ),
    },
  ]

  return (
    <>
      <EnvTable caption="Security" rows={rows} dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))} />
      <div className="am2-cards">
        <ReleaseCheckPanel slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <IntakeCard slug={slug} onMsg={ctx.onMsg} />
        <AppSupplyChainCard slug={slug} reload={ctx.reload} />
        <CapabilitiesCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <AutoPatchAppCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <AppAuditCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
      </div>
    </>
  )
}
