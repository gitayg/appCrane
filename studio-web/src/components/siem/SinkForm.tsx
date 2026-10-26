import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import { configFields, SECRET_LABELS, type Sink, type SinkType, type SiemOptions, type Severity } from './siemTypes'

const row = { display: 'grid', gridTemplateColumns: '220px 1fr', gap: 8, alignItems: 'center', margin: '6px 0' } as const
const input = { width: '100%', boxSizing: 'border-box' } as const

function list(s: string): string[] {
  return s.split(/[\s,]+/).map(x => x.trim()).filter(Boolean)
}

export function SinkForm({ sink, options, onDone }: { sink: Sink | null; options: SiemOptions; onDone: () => void }) {
  const [type, setType] = useState<SinkType>(sink?.type ?? 'https')
  const [preset, setPreset] = useState(sink?.preset ?? 'splunk')
  const [name, setName] = useState(sink?.name ?? '')
  const [format, setFormat] = useState<'json' | 'cef'>(sink?.format ?? 'json')
  const [enabled, setEnabled] = useState(sink?.enabled ?? true)
  const [config, setConfig] = useState<Record<string, string | number | boolean>>(sink?.config ?? { transport: 'tcp-tls' })
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [caPem, setCaPem] = useState(sink?.ca_pem ?? '')
  const [skip, setSkip] = useState(sink?.tls_skip_verify ?? false)
  const [kinds, setKinds] = useState((sink?.filters.kinds ?? []).join(', '))
  const [apps, setApps] = useState((sink?.filters.apps ?? []).join(', '))
  const [minSev, setMinSev] = useState<Severity>(sink?.filters.min_severity ?? 'info')
  const [startFrom, setStartFrom] = useState<'now' | 'all'>('now')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const secretKeys = type === 'https' ? (options.presets[preset]?.secrets ?? []) : type === 's3' ? options.s3_secrets : []
  const fields = configFields(type, preset)
  const setField = (k: string, v: string | number | boolean) => setConfig(c => ({ ...c, [k]: v }))

  const save = async () => {
    setBusy(true); setErr('')
    const cfg: Record<string, string | number | boolean> = {}
    for (const f of fields) {
      const v = config[f.key]
      if (v === undefined || v === '') continue
      cfg[f.key] = f.kind === 'number' ? Number(v) : v
    }
    if (type === 'syslog') cfg.transport = (config.transport as string) || 'tcp-tls'
    const sec: Record<string, string> = {}
    for (const k of secretKeys) if (secrets[k]) sec[k] = secrets[k]
    const body = {
      name, type, preset: type === 'https' ? preset : undefined, format, enabled, config: cfg, secrets: sec,
      ca_pem: caPem.trim() || null, tls_skip_verify: skip,
      filters: { kinds: list(kinds), apps: list(apps), min_severity: minSev },
      ...(sink ? {} : { start_from: startFrom }),
    }
    try {
      if (sink) await adminApi.put(`/api/settings/siem/${sink.id}`, body)
      else await adminApi.post('/api/settings/siem', body)
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const tlsApplies = type === 'https' || (type === 'syslog' && config.transport !== 'udp')

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <h4 style={{ marginTop: 0 }}>{sink ? `Edit ${sink.name}` : 'Add a SIEM destination'}</h4>
      <div style={row}><label>Name</label><input style={input} value={name} onChange={e => setName(e.target.value)} /></div>
      <div style={row}><label>Type</label>
        <select value={type} disabled={!!sink} onChange={e => { setType(e.target.value as SinkType); setFormat('json') }}>
          <option value="https">HTTPS JSON</option><option value="syslog">Syslog</option><option value="s3">S3 / R2 daily JSONL export</option>
        </select>
      </div>
      {type === 'https' && (
        <div style={row}><label>Preset</label>
          <select value={preset} onChange={e => setPreset(e.target.value)}>
            {Object.entries(options.presets).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
      )}
      {type === 'syslog' && (
        <div style={row}><label>Transport</label>
          <select value={String(config.transport || 'tcp-tls')} onChange={e => setField('transport', e.target.value)}>
            <option value="tcp-tls">TCP + TLS (RFC 5425, octet counting)</option><option value="udp">UDP (plain, legacy)</option>
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
            placeholder={sink?.secrets[k]?.set ? `Stored (${sink.secrets[k].preview}); leave blank to keep` : ''}
            onChange={e => setSecrets(s => ({ ...s, [k]: e.target.value }))} />
        </div>
      ))}
      {tlsApplies && (
        <>
          <div style={row}><label>Custom CA (PEM, optional)</label>
            <textarea style={{ ...input, minHeight: 60, fontFamily: 'monospace', fontSize: '.75rem' }} value={caPem}
              placeholder="-----BEGIN CERTIFICATE-----" onChange={e => setCaPem(e.target.value)} />
          </div>
          <div style={row}><label>Skip TLS verification</label>
            <span><input type="checkbox" checked={skip} onChange={e => setSkip(e.target.checked)} />{' '}
              <span style={{ color: 'var(--danger, #c33)', fontSize: '.8rem' }}>Not recommended. Audited. Upload the CA instead.</span></span>
          </div>
        </>
      )}
      <div style={row}><label>Event kinds (blank = all)</label><input style={input} placeholder="login, secret.reveal, deploy" value={kinds} onChange={e => setKinds(e.target.value)} /></div>
      <div style={row}><label>Minimum severity</label>
        <select value={minSev} onChange={e => setMinSev(e.target.value as Severity)}>
          <option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option>
        </select>
      </div>
      <div style={row}><label>Apps (blank = all, incl. platform events)</label><input style={input} placeholder="app-slug, other-app" value={apps} onChange={e => setApps(e.target.value)} /></div>
      {!sink && (
        <div style={row}><label>Start from</label>
          <select value={startFrom} onChange={e => setStartFrom(e.target.value as 'now' | 'all')}>
            <option value="now">New events only</option><option value="all">Everything the event store still holds</option>
          </select>
        </div>
      )}
      <div style={row}><label>Enabled</label><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} /></div>
      {err && <p style={{ color: 'var(--danger, #c33)' }}>{err}</p>}
      <button className="btn" disabled={busy || !name} onClick={save}>{busy ? 'Saving...' : 'Save'}</button>{' '}
      <button className="btn" onClick={onDone}>Cancel</button>
    </div>
  )
}
