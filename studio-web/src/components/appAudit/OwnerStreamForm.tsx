import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import { configFields, SECRET_LABELS, type SiemOptions, type SinkType } from '../siem/siemTypes'

// New owner audit stream: the platform SIEM field set (siemTypes.configFields)
// for HTTPS presets, syslog over TLS and the S3 / R2 export. No UDP and no
// "skip TLS verification": the server refuses both for owner streams.

const row = { display: 'grid', gridTemplateColumns: '200px 1fr', gap: 8, alignItems: 'center', margin: '6px 0' } as const
const input = { width: '100%', boxSizing: 'border-box' } as const

interface Props { base: string; options: SiemOptions; onDone: (saved: boolean) => void }

export function OwnerStreamForm({ base, options, onDone }: Props) {
  const [type, setType] = useState<SinkType>('https')
  const [preset, setPreset] = useState('generic')
  const [name, setName] = useState('')
  const [format, setFormat] = useState<'json' | 'cef'>('json')
  const [config, setConfig] = useState<Record<string, string | number | boolean>>({})
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [caPem, setCaPem] = useState('')
  const [actions, setActions] = useState('')
  const [startFrom, setStartFrom] = useState<'now' | 'all'>('now')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const secretKeys = type === 'https' ? (options.presets[preset]?.secrets ?? []) : type === 's3' ? options.s3_secrets : []
  const fields = configFields(type, preset)
  const setField = (k: string, v: string | number | boolean) => setConfig(c => ({ ...c, [k]: v }))

  async function save() {
    setBusy(true); setErr('')
    const cfg: Record<string, string | number | boolean> = {}
    for (const f of fields) {
      const v = config[f.key]
      if (v === undefined || v === '') continue
      cfg[f.key] = f.kind === 'number' ? Number(v) : v
    }
    if (type === 'syslog') cfg.transport = 'tcp-tls'
    const sec: Record<string, string> = {}
    for (const k of secretKeys) if (secrets[k]) sec[k] = secrets[k]
    try {
      await adminApi.post(base, {
        name, type, preset: type === 'https' ? preset : undefined, format: type === 's3' ? 'json' : format, config: cfg, secrets: sec,
        ca_pem: type !== 's3' && caPem.trim() ? caPem.trim() : null, start_from: startFrom,
        filters: { actions: actions.split(/[\s,]+/).map(a => a.trim()).filter(Boolean) },
      })
      onDone(true)
    } catch (e) {
      setErr((e as Error).message)
    } finally { setBusy(false) }
  }

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <h4 style={{ marginTop: 0 }}>Add a stream</h4>
      <div style={row}><label>Name</label><input style={input} value={name} onChange={e => setName(e.target.value)} /></div>
      <div style={row}><label>Type</label>
        <select value={type} onChange={e => { setType(e.target.value as SinkType); setConfig({}); setSecrets({}); setFormat('json') }}>
          <option value="https">HTTPS JSON</option><option value="syslog">Syslog over TLS</option><option value="s3">S3 / R2 daily JSONL export</option>
        </select>
      </div>
      {type === 'https' && (
        <div style={row}><label>Preset</label>
          <select value={preset} onChange={e => { setPreset(e.target.value); setSecrets({}) }}>
            {Object.entries(options.presets).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
      )}
      {type !== 's3' && preset !== 'sentinel' && (
        <div style={row}><label>Format</label>
          <select value={format} onChange={e => setFormat(e.target.value as 'json' | 'cef')}>
            <option value="json">JSON (ECS field names)</option><option value="cef">CEF</option>
          </select>
        </div>
      )}
      {fields.map(f => (
        <div style={row} key={f.key}><label>{f.label}</label>
          {f.kind === 'bool'
            ? <input type="checkbox" checked={!!config[f.key]} onChange={e => setField(f.key, e.target.checked)} />
            : <input style={input} type={f.kind === 'number' ? 'number' : 'text'} placeholder={f.placeholder}
                value={config[f.key] === undefined ? '' : String(config[f.key])} onChange={e => setField(f.key, e.target.value)} />}
        </div>
      ))}
      {secretKeys.map(k => (
        <div style={row} key={k}><label>{SECRET_LABELS[k] ?? k}</label>
          <PasswordInput label={SECRET_LABELS[k] ?? k} styled autoComplete="off" value={secrets[k] ?? ''}
            onChange={e => setSecrets(s => ({ ...s, [k]: e.target.value }))} />
        </div>
      ))}
      {type !== 's3' && (
        <div style={row}><label>Server CA (PEM, optional)</label>
          <textarea style={{ ...input, minHeight: 50, fontFamily: 'monospace', fontSize: '.75rem' }} value={caPem}
            placeholder="-----BEGIN CERTIFICATE-----" onChange={e => setCaPem(e.target.value)} />
        </div>
      )}
      <div style={row}><label>Actions (blank = all)</label><input style={input} placeholder="invoice, user.signed_in" value={actions} onChange={e => setActions(e.target.value)} /></div>
      <div style={row}><label>Start from</label>
        <select value={startFrom} onChange={e => setStartFrom(e.target.value as 'now' | 'all')}>
          <option value="now">New events only</option><option value="all">Every event still kept</option>
        </select>
      </div>
      <div style={{ fontSize: '.8rem', color: 'var(--text-dim)' }}>The destination must be a public address. TLS is always verified.</div>
      {err && <p style={{ color: 'var(--red)' }}>{err}</p>}
      <button className="btn btn-sm" disabled={busy || !name} onClick={save}>{busy ? 'Saving...' : 'Save'}</button>{' '}
      <button className="btn btn-sm" onClick={() => onDone(false)}>Cancel</button>
    </div>
  )
}
