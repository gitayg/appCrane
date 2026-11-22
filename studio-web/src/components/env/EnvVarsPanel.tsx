import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import { EnvVarRow } from './EnvVarRow'
import { StoreInSecretsManager } from './StoreInSecretsManager'
import { PasswordInput } from '../secret/PasswordInput'
import { ApiError } from '../../adminApi'
import { loadMaskedEnv, revealEnvVar, setEnvVar, deleteEnvVar, loadSecretsProviderStatus, type EnvName, type EnvStore, type MaskedEnvList } from './envVarsApi'

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
  const [generation, setGeneration] = useState(0)
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')
  const [newStore, setNewStore] = useState(false)
  const [offerSecretsManager, setOfferSecretsManager] = useState(false)
  const [localMsg, setLocalMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [retained, setRetained] = useState<{ key: string; name: string } | null>(null)
  // Dashboard cards mount this panel without onMsg; a refusal must still reach the operator.
  const msg = (text: string, ok: boolean) => { if (onMsg) onMsg({ text, ok }); else setLocalMsg({ text, ok }) }

  const load = useCallback(() => {
    setError(null)
    loadMaskedEnv(slug, env)
      .then(d => { setData(d); setGeneration(g => g + 1) })
      .catch(e => setError(errText(e) || 'Cannot load env vars'))
  }, [slug, env])

  useEffect(() => { setData(null); setRetained(null); setLocalMsg(null) }, [slug, env])

  // Only platform admins can read the status. Everyone else gets the checkbox,
  // and the PUT's 400 explains when the provider is off.
  useEffect(() => {
    loadSecretsProviderStatus()
      .then(s => setOfferSecretsManager(s.app_secrets))
      .catch(e => setOfferSecretsManager(e instanceof ApiError && e.status === 403))
  }, [])

  useEffect(() => {
    load()
  }, [load, reload])

  const reveal = async (key: string) => (await revealEnvVar(slug, env, key)).value

  async function save(key: string, value: string, store?: EnvStore): Promise<boolean> {
    setBusyKey(key)
    try {
      const r = await setEnvVar(slug, env, key, value, store)
      msg(r.message || `Updated ${key}`, true)
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
      const r = await deleteEnvVar(slug, env, key)
      msg('Deleted ' + key, true)
      setRetained(r.aws_secret_retained ? { key, name: r.aws_secret_retained } : null)
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
      const r = await setEnvVar(slug, env, k, newVal, newStore ? 'secrets_manager' : undefined)
      msg(r.message || 'Added', true)
      setNewKey(''); setNewVal(''); setNewStore(false)
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
                  key={`${env}/${v.key}/${generation}`}
                  v={v}
                  canReveal={canReveal}
                  revealRefusal={data.reveal_refusal}
                  busy={busyKey === v.key}
                  offerSecretsManager={offerSecretsManager}
                  compact={compact}
                  onReveal={() => reveal(v.key)}
                  onSave={(value, store) => save(v.key, value, store)}
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
        <span style={{ flex: 2, minWidth: 0, display: 'flex' }}>
          <PasswordInput label="new value" placeholder="value" autoComplete="new-password" value={newVal} onChange={e => setNewVal(e.target.value)} style={{ ...inputStyle, width: '100%' }} />
        </span>
        <button className={compact ? 'btn btn-xs' : 'btn btn-sm'} onClick={add}>Add</button>
      </div>
      {offerSecretsManager && (
        <StoreInSecretsManager name={newKey.trim() || 'new variable'} checked={newStore} onChange={setNewStore} />
      )}
      {retained && (
        <div data-aws-secret-retained style={{ color: 'var(--yellow-text)', fontSize: '.8rem', marginTop: 6 }}>
          Deleted {retained.key} from AppCrane and kept its AWS secret <code>{retained.name}</code>. Delete the secret in AWS when nothing else needs it.
        </div>
      )}
      {localMsg && (
        <div style={{ color: localMsg.ok ? 'var(--dim)' : 'var(--red)', fontSize: '.8rem', marginTop: 6 }}>{localMsg.text}</div>
      )}
    </div>
  )
}
