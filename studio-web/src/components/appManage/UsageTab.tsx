import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { UsageCard } from '../UsageCard'
import { EnvSleepCard } from '../EnvSleepCard'
import { EnvTable, type EnvRow } from './EnvTable'
import { healthOf } from './OverviewTab'
import { useEnvStatus } from './useEnvStatus'
import { errText, fmtNum, relTime } from './format'
import { ENVS, type EnvName, type ManageCtx } from './types'

type Summary = { requests: number; dau: number; wau: number; mau: number; stickiness: number }

export function UsageTab({ ctx }: { ctx: ManageCtx }) {
  const { slug } = ctx
  const st = useEnvStatus(slug, ctx.reload)
  const [sum, setSum] = useState<Partial<Record<EnvName, Summary | string>>>({})
  useEffect(() => {
    const to = new Date().toISOString().slice(0, 10)
    const from = new Date(Date.now() - 29 * 86_400_000).toISOString().slice(0, 10)
    for (const env of ENVS) {
      adminApi.get<{ summary: Summary }>(`/api/apps/${slug}/usage?env=${env}&from=${from}&to=${to}`)
        .then(r => setSum(s => ({ ...s, [env]: r.summary })))
        .catch(e => setSum(s => ({ ...s, [env]: errText(e) })))
    }
  }, [slug, ctx.reload])

  const v = (env: EnvName, f: (x: Summary) => string) => {
    const x = sum[env]
    if (x === undefined) return '…'
    if (typeof x === 'string') return <span className="am2-dim am2-small">{x}</span>
    return f(x)
  }
  const rows: EnvRow[] = [
    { key: 'req', label: 'Requests, 30 days', production: v('production', x => fmtNum(x.requests)), sandbox: v('sandbox', x => fmtNum(x.requests)) },
    { key: 'dau', label: 'Daily active users', production: v('production', x => fmtNum(x.dau)), sandbox: v('sandbox', x => fmtNum(x.dau)) },
    { key: 'wau', label: 'Weekly active users', production: v('production', x => fmtNum(x.wau)), sandbox: v('sandbox', x => fmtNum(x.wau)) },
    { key: 'mau', label: 'Monthly active users', production: v('production', x => fmtNum(x.mau)), sandbox: v('sandbox', x => fmtNum(x.mau)) },
    { key: 'stick', label: 'Stickiness', production: v('production', x => `${Math.round(x.stickiness * 100)}%`), sandbox: v('sandbox', x => `${Math.round(x.stickiness * 100)}%`) },
    { key: 'last', label: 'Last request', ...Object.fromEntries(ENVS.map(e => [e, st.sleep?.[e]?.last_request_at ? relTime(st.sleep[e]!.last_request_at) : '—'])) },
    { key: 'sleep', label: 'Sleep', ...Object.fromEntries(ENVS.map(e => [e, st.sleep?.[e] ? (st.sleep[e]!.state === 'asleep' ? 'Asleep' : 'Awake') : '—'])) },
  ]
  return (
    <>
      <EnvTable caption="Usage" rows={rows} dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))} />
      <div className="am2-cards">
        <UsageCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
        <EnvSleepCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
      </div>
    </>
  )
}
