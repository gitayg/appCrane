import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { adminApi } from '../../adminApi'
import { setVisibleInterval } from '../../utils/visibleInterval'
import { relTime } from './format'
import { ENVS, ENV_LABEL, type EnvName, type ManageCtx } from './types'
import type { Deployment } from './useEnvStatus'

type Kind = 'runtime' | 'build'

/** Runtime and build logs for one environment at a time (?env=). Same endpoints and filters as the old log drawer. */
export function LogsTab({ ctx }: { ctx: ManageCtx }) {
  const { slug } = ctx
  const [params, setParams] = useSearchParams()
  const env: EnvName = params.get('env') === 'sandbox' ? 'sandbox' : 'production'
  const [kind, setKind] = useState<Kind>('runtime')
  const [lines, setLines] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [count, setCount] = useState('100')
  const [filter, setFilter] = useState('')
  const [levels, setLevels] = useState<Set<string>>(new Set())
  const [deps, setDeps] = useState<Deployment[]>([])
  const [depId, setDepId] = useState<number | null>(null)
  const box = useRef<HTMLDivElement | null>(null)

  const setEnv = (e: EnvName) => { const n = new URLSearchParams(params); n.set('env', e); setParams(n) }

  const runtime = useCallback(async () => {
    try {
      const d = await adminApi.get<{ logs?: string[] }>(`/api/${slug}/logs/${env}?lines=${count}`)
      setLines(d.logs || []); setError(null)
    } catch { setError('Error loading logs') }
  }, [slug, env, count])

  useEffect(() => {
    adminApi.get<{ deployments?: Deployment[] }>(`/api/apps/${slug}/deployments/${env}`)
      .then(d => { setDeps(d.deployments || []); setDepId(d.deployments?.[0]?.id ?? null) })
      .catch(() => setDeps([]))
  }, [slug, env, ctx.reload])

  useEffect(() => {
    setLines([])
    if (kind === 'runtime') { void runtime(); return setVisibleInterval(runtime, 4000) }
    if (!depId) return
    adminApi.get<{ log?: string }>(`/api/apps/${slug}/deployments/${env}/${depId}/log`)
      .then(d => { setLines((d.log || '').split('\n')); setError(null) })
      .catch(() => setError('Error loading log'))
  }, [kind, depId, runtime, slug, env])

  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight }, [lines])

  const toggle = (l: string) => setLevels(s => { const n = new Set(s); if (n.has(l)) n.delete(l); else n.add(l); return n })
  const kw = filter.toLowerCase()

  return (
    <>
      <div className="am2-toolbar">
        <div className="am2-row" role="group" aria-label="Environment">
          {ENVS.map(e => <button key={e} className={'btn btn-sm' + (env === e ? ' btn-accent' : '')} onClick={() => setEnv(e)}>{ENV_LABEL[e]}</button>)}
        </div>
        <div className="am2-row" role="group" aria-label="Log kind">
          <button className={'btn btn-sm' + (kind === 'runtime' ? ' btn-accent' : '')} onClick={() => setKind('runtime')}>Runtime</button>
          <button className={'btn btn-sm' + (kind === 'build' ? ' btn-accent' : '')} onClick={() => setKind('build')}>Build</button>
        </div>
        {kind === 'runtime' ? (
          <select className="am2-input" value={count} onChange={e => setCount(e.target.value)} aria-label="Lines">
            <option value="100">100 lines</option><option value="500">500 lines</option><option value="1000">1000 lines</option>
          </select>
        ) : (
          <select className="am2-input" value={depId ?? ''} onChange={e => setDepId(Number(e.target.value) || null)} aria-label="Deployment">
            {deps.map(d => <option key={d.id} value={d.id}>#{d.id} v{d.version || '-'} · {d.status} · {relTime(d.finished_at || d.started_at)}</option>)}
          </select>
        )}
        <input className="am2-input" placeholder="Filter" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter lines" style={{ width: 150 }} />
        {['error', 'warn', 'info'].map(l => (
          <button key={l} className={'log-lvl-btn' + (levels.has(l) ? ` lvl-on-${l === 'error' ? 'err' : l}` : '')} onClick={() => toggle(l)}>{l[0].toUpperCase() + l.slice(1)}</button>
        ))}
      </div>
      <div className="am2-log" ref={box}>
        {error ? <span style={{ color: 'var(--red)' }}>{error}</span> : kind === 'build' && !depId ? <span className="am2-dim">No deployments yet.</span> : lines.map((line, i) => {
          const isErr = /error|exception|fatal|critical/i.test(line)
          const isWrn = /\bwarn/i.test(line)
          const isInf = /\binfo\b|started|listening|ready/i.test(line)
          const lvl = isErr ? 'error' : isWrn ? 'warn' : isInf ? 'info' : ''
          const hide = (kw && !(line || '').toLowerCase().includes(kw)) || (levels.size > 0 && (!lvl || !levels.has(lvl)))
          if (hide) return null
          return <div key={i} className={isErr ? 'log-err' : isWrn ? 'log-warn' : isInf ? 'log-info' : ''}>{line}</div>
        })}
      </div>
    </>
  )
}
