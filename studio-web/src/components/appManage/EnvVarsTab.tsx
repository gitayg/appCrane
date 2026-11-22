import { useCallback, useEffect, useState } from 'react'
import { SecretValue } from '../secret/SecretValue'
import { EnvVarsPanel } from '../env/EnvVarsPanel'
import { StoredEnvFilesCard } from '../StoredEnvFilesCard'
import { loadMaskedEnv, revealEnvVar, setEnvVar, deleteEnvVar, type MaskedEnvList, type MaskedEnvVar } from '../env/envVarsApi'
import { EnvTable, type EnvRow } from './EnvTable'
import { useEnvActions } from './useEnvActions'
import { healthOf } from './OverviewTab'
import { errText } from './format'
import { ENVS, ENV_LABEL, type EnvName, type ManageCtx } from './types'

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/

export function EnvVarsTab({ ctx }: { ctx: ManageCtx }) {
  const { slug } = ctx
  const [lists, setLists] = useState<Partial<Record<EnvName, MaskedEnvList | { error: string }>>>({})
  const [n, setN] = useState(0)
  const [changed, setChanged] = useState<Partial<Record<EnvName, boolean>>>({})
  const [advanced, setAdvanced] = useState<EnvName | null>(null)
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')
  const [newEnvs, setNewEnvs] = useState<Record<EnvName, boolean>>({ production: false, sandbox: true })
  const act = useEnvActions(slug, ctx.onMsg, ctx.refresh)

  const load = useCallback(() => setN(x => x + 1), [])
  useEffect(() => {
    let off = false
    for (const env of ENVS) {
      loadMaskedEnv(slug, env)
        .then(d => { if (!off) setLists(l => ({ ...l, [env]: d })) })
        .catch(e => { if (!off) setLists(l => ({ ...l, [env]: { error: errText(e) } })) })
    }
    return () => { off = true }
  }, [slug, n, ctx.reload])

  const ok = (env: EnvName) => { const l = lists[env]; return l && !('error' in l) ? l : null }
  const varsOf = (env: EnvName) => new Map((ok(env)?.vars || []).map(v => [v.key, v]))
  const prod = varsOf('production')
  const sand = varsOf('sandbox')
  const keys = [...new Set([...prod.keys(), ...sand.keys()])].sort()

  function mark(env: EnvName) { setChanged(c => ({ ...c, [env]: true })) }

  const reveal = async (env: EnvName, key: string) => (await revealEnvVar(slug, env, key)).value

  async function edit(env: EnvName, key: string, existing: boolean) {
    const v = prompt(`${existing ? 'New value' : 'Value'} for ${key} in ${env}`, '')
    if (v === null) return
    try {
      const r = await setEnvVar(slug, env, key, v)
      ctx.onMsg({ text: r.message || `Updated ${key}`, ok: true })
      mark(env); load()
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function remove(env: EnvName, key: string) {
    if (!confirm(`Delete ${key} from ${env}?`)) return
    try {
      const r = await deleteEnvVar(slug, env, key)
      ctx.onMsg({ text: r.aws_secret_retained ? `Deleted ${key}. The Secrets Manager secret ${r.aws_secret_retained} was kept.` : `Deleted ${key}`, ok: true })
      mark(env); load()
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function add() {
    const key = newKey.trim()
    if (!KEY_RE.test(key)) return ctx.onMsg({ text: 'Name must start with a letter or _ and use letters, digits and _', ok: false })
    const targets = ENVS.filter(e => newEnvs[e])
    if (!targets.length) return ctx.onMsg({ text: 'Pick at least one environment', ok: false })
    try {
      for (const env of targets) { await setEnvVar(slug, env, key, newVal); mark(env) }
      ctx.onMsg({ text: `Set ${key} in ${targets.join(' and ')}`, ok: true })
      setNewKey(''); setNewVal(''); load()
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  function differs(key: string): boolean | null {
    const p = prod.get(key)
    const s = sand.get(key)
    if (!p || !s) return true
    if (p.fingerprint && s.fingerprint) return p.fingerprint !== s.fingerprint
    if (p.source || s.source) return p.value !== s.value
    return null
  }

  const cell = (env: EnvName, key: string, v?: MaskedEnvVar) => {
    const list = ok(env)
    if (!v) return <span className="am2-row"><span className="am2-dim">Not set</span><button className="btn btn-xs" onClick={() => edit(env, key, false)}>Add</button></span>
    const canReveal = list?.can_reveal !== false && !v.source
    return (
      <span className="am2-row">
        {v.source
          ? <code className="am2-mono" style={{ wordBreak: 'break-all' }}>{v.value}</code>
          : <SecretValue key={`${env}/${key}/${v.updated_at || ''}/${n}`} name={`${key} (${env})`} masked={v.preview || '••••••••'} fingerprint={v.fingerprint}
              disabled={!canReveal} disabledReason={canReveal ? undefined : 'You cannot reveal values in this environment'}
              compact reveal={() => reveal(env, key)} onError={m => ctx.onMsg({ text: m, ok: false })} />}
        {v.error && <span className="am2-pill bad">{v.error}</span>}
        <button className="btn btn-xs" onClick={() => edit(env, key, true)}>Edit</button>
        <button className="btn btn-xs btn-red" onClick={() => remove(env, key)} aria-label={`Delete ${key} from ${env}`}>✕</button>
      </span>
    )
  }

  const rows: EnvRow[] = keys.map(k => ({
    key: k,
    label: <code className="am2-mono" style={{ color: 'var(--text)' }}>{k}</code>,
    production: cell('production', k, prod.get(k)),
    sandbox: cell('sandbox', k, sand.get(k)),
    diff: differs(k) === true,
  }))
  const errs = ENVS.map(e => { const l = lists[e]; return l && 'error' in l ? `${ENV_LABEL[e]}: ${l.error}` : null }).filter(Boolean)
  const warnings = ok('sandbox')?.warnings || []

  return (
    <>
      <div className="am2-toolbar">
        <span className="am2-small am2-dim">Highlighted rows differ between environments or exist in only one.</span>
        <span className="grow" />
      </div>
      {ENVS.filter(e => changed[e]).map(e => (
        <div key={e} className="env-redeploy-banner">
          <span>Env var changes in {e} take effect when it is redeployed.</span>
          <button className="btn btn-sm" style={{ background: 'var(--yellow)', color: '#000', fontWeight: 700 }} onClick={() => act.deploy(e)}>Redeploy {e}</button>
        </div>
      ))}
      {errs.map(t => <div key={t} className="am-msg msg-err">{t}</div>)}
      {warnings.map(w => <div key={w} className="am-msg msg-err">{w}</div>)}
      <EnvTable caption="Environment variables" rows={rows.length ? rows : [{ key: 'none', label: 'Variables', both: <span className="am2-dim">{ENVS.every(e => lists[e]) ? 'No variables yet.' : 'Loading…'}</span> }]} dots={Object.fromEntries(ENVS.map(e => [e, healthOf(ctx, e).dot]))} />
      <div className="am-card">
        <h3 style={{ marginBottom: 8 }}>Add a variable</h3>
        <div className="am2-row">
          <input className="am2-input am2-mono" placeholder="NAME" value={newKey} onChange={e => setNewKey(e.target.value)} aria-label="Variable name" style={{ minWidth: 160 }} />
          <input className="am2-input am2-mono" placeholder="value" value={newVal} onChange={e => setNewVal(e.target.value)} aria-label="Variable value" style={{ flex: 1, minWidth: 160 }} />
          {ENVS.map(e => (
            <label key={e} className="am2-row am2-small"><input type="checkbox" checked={newEnvs[e]} onChange={ev => setNewEnvs(s => ({ ...s, [e]: ev.target.checked }))} />{ENV_LABEL[e]}</label>
          ))}
          <button className="btn btn-sm btn-accent" onClick={add} disabled={!newKey.trim()}>Add</button>
        </div>
      </div>
      <div className="am2-section">Stored env files and advanced editing</div>
      <EnvTable caption="Stored env files" rows={[
        { key: 'files', label: 'Stored env files', production: <StoredEnvFilesCard slug={slug} env="production" reload={ctx.reload} onMsg={ctx.onMsg} onDeploy={() => act.deploy('production')} />, sandbox: <StoredEnvFilesCard slug={slug} env="sandbox" reload={ctx.reload} onMsg={ctx.onMsg} onDeploy={() => act.deploy('sandbox')} /> },
        { key: 'adv', label: 'Full editor', production: <button className="btn btn-xs" onClick={() => setAdvanced(a => a === 'production' ? null : 'production')}>{advanced === 'production' ? 'Close' : 'Open'}</button>, sandbox: <button className="btn btn-xs" onClick={() => setAdvanced(a => a === 'sandbox' ? null : 'sandbox')}>{advanced === 'sandbox' ? 'Close' : 'Open'}</button> },
      ]} />
      {advanced && (
        <div className="am-card">
          <h3 style={{ marginBottom: 8 }}>{ENV_LABEL[advanced]} variables · full editor (Secrets Manager, outside secret references)</h3>
          <EnvVarsPanel slug={slug} env={advanced} reload={n} onMsg={ctx.onMsg} onChanged={() => { mark(advanced); load() }} />
        </div>
      )}
      {act.modal}
    </>
  )
}
