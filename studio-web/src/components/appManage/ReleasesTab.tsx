import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { WhatsNewMailCard } from '../WhatsNewMailCard'
import { Modal } from './Modal'
import { ReleaseCompare } from './ReleaseCompare'
import { useEnvActions } from './useEnvActions'
import { LABEL_RE, downloadReleasesCsv, loadReleases, setReleaseLabel, type Release, type ReleaseLog } from './releaseApi'
import { errText, fmtDuration, fmtNum, relTime } from './format'
import { ENVS, ENV_LABEL, type ManageCtx } from './types'

const STATUS_CLS: Record<Release['status'], string> = {
  live: 'ok', replaced: '', 'rolled back': 'warn', 'auto-reverted': 'bad', failed: 'bad', 'in progress': 'info',
}

export function ReleasesTab({ ctx }: { ctx: ManageCtx }) {
  const { slug, isOwner, isPlatformAdmin } = ctx
  const [label, setLabel] = useState('')
  const [log, setLog] = useState<ReleaseLog | null>(null)
  const [error, setError] = useState('')
  const [picked, setPicked] = useState<number[]>([])
  const [compare, setCompare] = useState(false)
  const [buildLog, setBuildLog] = useState<{ rel: Release; text: string } | null>(null)
  const [n, setN] = useState(0)
  const act = useEnvActions(slug, ctx.onMsg, () => { setN(x => x + 1); ctx.refresh() })

  useEffect(() => {
    let off = false
    setError('')
    loadReleases(slug, label || undefined)
      .then(r => { if (!off) setLog(r) })
      .catch(e => { if (!off) setError(errText(e)) })
    return () => { off = true }
  }, [slug, label, n, ctx.reload])

  const byId = new Map((log?.releases || []).map(r => [r.id, r]))
  const pickedRel = picked.map(id => byId.get(id)).filter(Boolean) as Release[]

  function toggle(id: number) {
    setPicked(p => p.includes(id) ? p.filter(x => x !== id) : [...p.slice(-1), id])
  }

  async function editLabel(r: Release) {
    const v = prompt('Release label (empty to clear). 1-40 of letters, digits and . _ = -', r.label || '')
    if (v === null) return
    const next = v.trim() || null
    if (next && !LABEL_RE.test(next)) return ctx.onMsg({ text: 'Label must be 1-40 characters of letters, digits and . _ = -', ok: false })
    try { await setReleaseLabel(slug, r.id, next); setN(x => x + 1) } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function openLog(r: Release) {
    setBuildLog({ rel: r, text: 'Loading…' })
    try {
      const d = await adminApi.get<{ log?: string }>(`/api/apps/${slug}/deployments/${r.env}/${r.id}/log`)
      setBuildLog({ rel: r, text: d.log || '(empty)' })
    } catch (e) { setBuildLog({ rel: r, text: errText(e) }) }
  }

  async function csv() {
    try { await downloadReleasesCsv(slug, label || undefined) } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  const card = (r: Release) => {
    const m = r.metrics
    const mayRollBack = (isOwner || isPlatformAdmin) && (r.status === 'replaced' || r.status === 'rolled back')
    return (
      <div key={r.id} className={'am2-rel' + (picked.includes(r.id) ? ' picked' : '')}>
        <div className="am2-rel-top">
          <input type="checkbox" checked={picked.includes(r.id)} onChange={() => toggle(r.id)} aria-label={`Compare release ${r.version || r.id}`} />
          <span className="ver">{r.version ? (r.version.startsWith('v') ? r.version : `v${r.version}`) : `#${r.id}`}</span>
          <span className={'am2-pill ' + STATUS_CLS[r.status]}>{r.status}</span>
          {r.label
            ? <button className="am2-pill info" onClick={() => editLabel(r)} title="Edit label">{r.label}</button>
            : <button className="am2-pill" onClick={() => editLabel(r)} title="Add a label">+ label</button>}
          <span className="when" title={r.finished_at || r.started_at}>{relTime(r.live_from || r.finished_at || r.started_at)}</span>
        </div>
        {r.whats_new && <div className="am2-rel-note">{r.whats_new}</div>}
        {r.failure_reason && <div className="am2-rel-note" style={{ color: 'var(--red)' }}>{r.failure_reason}</div>}
        <div className="am2-rel-meta">
          {r.deployed_by && <span>by {r.deployed_by.name} ({r.deployed_by.kind})</span>}
          {r.commit && <span className="am2-mono">{r.commit.slice(0, 10)}</span>}
          {r.live_ms != null && <span>live {fmtDuration(r.live_ms)}</span>}
          {r.kind === 'rollback' && <span>rollback to #{r.rollback_of}</span>}
          {r.kind === 'promote' && <span>promoted from sandbox #{r.promoted_from}</span>}
          {r.promoted_to.length > 0 && <span>promoted to production #{r.promoted_to.join(', #')}</span>}
          <span>approver —</span>
        </div>
        {m && (
          <div className="am2-rel-metrics">
            <div><div className="k">Requests</div><div className="v">{fmtNum(m.requests)}</div></div>
            <div><div className="k">Active users</div><div className="v">{fmtNum(m.active_users)}</div></div>
            <div><div className="k">Restarts</div><div className="v">{fmtNum(m.restarts)}</div></div>
            <div title={log?.unavailable.error_rate}><div className="k">Error rate</div><div className="v">—</div></div>
            <div title={log?.unavailable.p95_ms}><div className="k">p95</div><div className="v">—</div></div>
          </div>
        )}
        {m && m.coverage !== 'full' && <div className="am2-small am2-dim" style={{ marginTop: 4 }}>{m.coverage === 'none' ? 'No request tracking while this release was live.' : 'Request tracking started while this release was live; counts are partial.'}</div>}
        <div className="am2-row" style={{ marginTop: 8 }}>
          <button className="btn btn-xs" onClick={() => openLog(r)}>Build log</button>
          {mayRollBack && <button className="btn btn-xs" onClick={() => act.rollback(r.env, r.id)}>Roll back to this</button>}
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="am2-toolbar">
        <label className="am2-row am2-small">Label
          <select className="am2-input" value={label} onChange={e => { setLabel(e.target.value); setPicked([]) }} aria-label="Filter by label">
            <option value="">All releases</option>
            {(log?.labels || []).map(l => <option key={l} value={l}>{l}</option>)}
          </select>
        </label>
        <span className="grow" />
        <span className="am2-small am2-dim">{picked.length === 2 ? 'Two releases selected' : 'Tick two releases to compare'}</span>
        <button className="btn btn-sm btn-accent" disabled={pickedRel.length !== 2} onClick={() => setCompare(true)}>Compare</button>
        <button className="btn btn-sm" onClick={csv}>Export CSV</button>
      </div>
      {error && <div className="am-msg msg-err">{error}</div>}
      {!log && !error && <div className="am2-empty">Loading…</div>}
      {log && (
        <div className="am2-rel-scroll">
          <div className="am2-rel-grid">
            {ENVS.map(env => {
              const list = log.releases.filter(r => r.env === env)
              return (
                <div key={env} className="am2-rel-col">
                  <h3>{ENV_LABEL[env]} <span className="am2-dim am2-small">{list.length}</span></h3>
                  {list.length ? list.map(card) : <div className="am2-empty">No releases{label ? ` labelled ${label}` : ''}.</div>}
                </div>
              )
            })}
          </div>
        </div>
      )}
      <p className="am2-small am2-dim" style={{ marginTop: 10 }}>
        Requests and active users come from AppCrane's request counting while each release was live (per UTC day, pro-rated by the hours it was live); restarts are dashboard and API restarts. Error rate and p95 response time are not recorded, so they show —.
      </p>
      <div className="am2-cards" style={{ marginTop: 14 }}>
        <WhatsNewMailCard slug={slug} reload={ctx.reload} onMsg={ctx.onMsg} />
      </div>
      {compare && pickedRel.length === 2 && <ReleaseCompare a={pickedRel[0]} b={pickedRel[1]} onClose={() => setCompare(false)} />}
      {buildLog && (
        <Modal title={`Build log · ${buildLog.rel.env} #${buildLog.rel.id}`} onClose={() => setBuildLog(null)} width={900}>
          <div className="am2-log" style={{ height: '60vh' }}>{buildLog.text}</div>
        </Modal>
      )}
      {act.modal}
    </>
  )
}
