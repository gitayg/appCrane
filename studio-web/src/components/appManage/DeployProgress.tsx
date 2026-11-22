import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { setVisibleInterval } from '../../utils/visibleInterval'
import type { Deployment } from './useEnvStatus'
import type { EnvName } from './types'

const TERMINAL = new Set(['live', 'failed', 'rolled_back'])

/** Pull, Build, Health, Live for a deploy in flight; polls until it settles. Same heuristic as the old /app page. */
export function DeployProgress({ slug, env, latest, onDone }: { slug: string; env: EnvName; latest: Deployment; onDone: () => void }) {
  const [d, setD] = useState(latest)
  useEffect(() => setD(latest), [latest])
  useEffect(() => {
    if (TERMINAL.has(d.status)) return
    let off = false
    const stop = setVisibleInterval(async () => {
      try {
        const r = await adminApi.get<{ deployments: Deployment[] }>(`/api/apps/${slug}/deployments/${env}`)
        const next = r.deployments?.[0]
        if (off || !next) return
        setD(next)
        if (TERMINAL.has(next.status)) onDone()
      } catch { /* keep the last state */ }
    }, 2000)
    return () => { off = true; stop() }
  }, [d.id, d.status, slug, env, onDone])

  if (TERMINAL.has(d.status)) return null
  const log = d.log || ''
  const steps = [
    { label: 'Pull', done: /cloned|pulling|fetched/i.test(log) },
    { label: 'Build', done: /built|build complete/i.test(log) },
    { label: 'Health', done: /health.*pass|healthy/i.test(log) },
    { label: 'Live', done: false },
  ]
  const active = steps.findIndex(s => !s.done)
  return (
    <div className="deploy-pipeline">
      {steps.map((s, i) => (
        <div key={s.label} className={'dp-step' + (s.done ? ' dp-done' : i === active ? ' dp-active' : '')}>
          <div className="dp-dot" />{s.label}
        </div>
      ))}
    </div>
  )
}
