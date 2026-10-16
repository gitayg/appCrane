import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import { EnvVarRow } from './EnvVarRow'
import { loadMaskedEnv, revealEnvVar, setEnvVar, deleteEnvVar, type EnvName, type MaskedEnvList } from './envVarsApi'

export interface EnvVarsPanelProps {
  slug: string
  env: EnvName
  reload?: number
  onMsg?: (m: { text: string; ok: boolean }) => void
  onChanged?: () => void
  compact?: boolean
}

const errText = (e: unknown) => (e as Error)?.message || String(e)

export function EnvVarsPanel({ slug, env, reload, onMsg, onChanged, compact }: EnvVarsPanelProps) {
  const [data, setData] = useState<MaskedEnvList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')
  const msg = (text: string, ok: boolean) => onMsg?.({ text, ok })

  const load = useCallback(() => {
    setError(null)
    loadMaskedEnv(slug, env)
      .then(d => setData(d))
      .catch(e => setError(errText(e) || 'Cannot load env vars'))
  }, [slug, env])

  useEffect(() => {
    setRevealed({})
    load()
  }, [load, reload])

  const forget = (key: string) => setRevealed(prev => {
    const next = { ...prev }
    delete next[key]
    return next
  })

  async function reveal(key: string) {
    setBusyKey(key)
    try {
      const r = await revealEnvVar(slug, env, key)
      setRevealed(prev => ({ ...prev, [key]: r.value }))
    } catch (e) {
      msg(errText(e), false)
    } finally {
      setBusyKey(null)
    }
  }

  async function save(key: string, value: string): Promise<boolean> {
    setBusyKey(key)
    try {
      const r = await setEnvVar(slug, env, key, value)
      msg(r.message || `Updated ${key}`, true)
      forget(key)
      onChanged?.()
      load()
      return true
    } catch (e) {
      msg(errText(e), false)
      return false
    } finally {
      setBusyKey(null)
    }
  }

  async function remove(key: string) {
    if (!confirm('Delete ' + key + '?')) return
    try {
      await deleteEnvVar(slug, env, key)
      msg('Deleted ' + key, true)
      forget(key)
      onChanged?.()
      load()
    } catch (e) {
      msg(errText(e), false)
    }
  }

  async function add() {
    const k = newKey.trim()
    if (!k) return
    try {
      const r = await setEnvVar(slug, env, k, newVal)
      msg(r.message || 'Added', true)
      setNewKey(''); setNewVal('')
      forget(k)
      onChanged?.()
      load()
    } catch (e) {
      msg(errText(e), false)
    }
  }

  const canReveal = data?.can_reveal !== false
  const inputStyle: CSSProperties = {
    minWidth: 0, background: 'var(--surface2)', border: '1px solid var(--border)', color: 'var(--text)',
    padding: '6px 10px', borderRadius: 4, fontSize: '.85rem', fontFamily: "'SF Mono',Monaco,monospace",
  }

  return (
    <div className="env-vars-panel">
      {error ? (
        <span style={{ color: 'var(--red)' }}>{error}</span>
      ) : !data ? 'Loading...' : !data.vars?.length ? (
        <span style={{ color: 'var(--dim)' }}>No env vars set</span>
      ) : (
        <>
          {!canReveal && data.reveal_refusal && (
            <div style={{ color: 'var(--dim)', fontSize: '.78rem', marginBottom: 6 }}>{data.reveal_refusal}</div>
          )}
          <table style={{ width: '100%' }}>
            <thead>
              <tr><th>Key</th><th>Value</th><th></th></tr>
            </thead>
            <tbody>
              {data.vars.map(v => (
                <EnvVarRow
                  key={v.key}
                  v={v}
                  revealed={revealed[v.key]}
                  canReveal={canReveal}
                  revealRefusal={data.reveal_refusal}
                  busy={busyKey === v.key}
                  compact={compact}
                  onReveal={() => reveal(v.key)}
                  onHide={() => forget(v.key)}
                  onSave={value => save(v.key, value)}
                  onDelete={() => remove(v.key)}
                />
              ))}
            </tbody>
          </table>
          {data.warnings?.map((w, i) => (
            <div key={i} style={{ color: 'var(--yellow)', fontSize: '.8rem', marginTop: 6 }}>⚠ {w}</div>
          ))}
        </>
      )}
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <input type="text" placeholder="KEY" value={newKey} onChange={e => setNewKey(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
        <input type="text" placeholder="value" autoComplete="off" value={newVal} onChange={e => setNewVal(e.target.value)} style={{ ...inputStyle, flex: 2 }} />
        <button className={compact ? 'btn btn-xs' : 'btn btn-sm'} onClick={add}>Add</button>
      </div>
    </div>
  )
}
