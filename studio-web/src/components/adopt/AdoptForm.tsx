import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { PasswordInput } from '../secret/PasswordInput'
import type { AdoptResult, Analysis } from './adoptTypes'

interface Props {
  analysis: Analysis
  onAdopted: (r: AdoptResult) => void
}

const CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted']
const labelStyle: React.CSSProperties = { display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem' }

export function AdoptForm({ analysis, onAdopted }: Props) {
  const r = analysis.report
  const [name, setName] = useState(analysis.suggested.name)
  const [slug, setSlug] = useState(analysis.suggested.slug)
  const [values, setValues] = useState<Record<string, string>>({})
  const [purpose, setPurpose] = useState('')
  const [classification, setClassification] = useState('internal')
  const [personalData, setPersonalData] = useState(false)
  const [openRequests, setOpenRequests] = useState(true)
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const critical = r.risk_counts.critical > 0

  async function adopt(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const env_vars = Object.fromEntries(Object.entries(values).filter(([, v]) => v !== ''))
      const res = await adminApi.post<AdoptResult>(`/api/adopt/${encodeURIComponent(analysis.id)}/adopt`, {
        name: name.trim(), slug: slug.trim(), stage: 'sandbox', env_vars, open_requests: openRequests, acknowledge_risks: ack,
        intake: { purpose: purpose.trim(), data_classification: classification, intake_answers: { personal_data: personalData } },
      })
      setValues({})
      onAdopted(res)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }


  return (
    <form onSubmit={adopt} className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <h3 style={{ margin: 0, fontSize: '.95rem' }}>Adopt to the sandbox</h3>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <label style={{ ...labelStyle, flex: 1, minWidth: 200 }}>
          Name
          <input className="az-input" value={name} onChange={e => setName(e.target.value)} required />
        </label>
        <label style={{ ...labelStyle, flex: '0 0 220px' }}>
          Slug
          <input className="az-input" value={slug} onChange={e => setSlug(e.target.value.toLowerCase())} pattern="[a-z0-9-]+" required />
        </label>
      </div>

      <div>
        <div style={{ fontSize: '.85rem', fontWeight: 600, marginBottom: 4 }}>Environment variables (sandbox, stored encrypted)</div>
        {r.env.length === 0 && <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>The code reads no env vars AppCrane does not set itself.</div>}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {r.env.map(v => (
            <label key={v.key} style={labelStyle}>
              <span>
                <code>{v.key}</code>
                <span style={{ color: 'var(--dim)', marginLeft: 6 }}>
                  {v.scope === 'client' ? 'client, built into the bundle' : 'server'}
                  {v.value_in_upload ? ' | value found in the uploaded .env, leave blank to use it' : ''}
                </span>
              </span>
              <PasswordInput label={v.key} value={values[v.key] || ''} onChange={e => setValues(s => ({ ...s, [v.key]: e.target.value }))} autoComplete="off" />
              {v.hint && <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>{v.hint}</span>}
            </label>
          ))}
        </div>
      </div>

      <div>
        <div style={{ fontSize: '.85rem', fontWeight: 600, marginBottom: 4 }}>Intake</div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <label style={{ ...labelStyle, flex: 1, minWidth: 240 }}>
            What is the app for?
            <input className="az-input" value={purpose} onChange={e => setPurpose(e.target.value)} />
          </label>
          <label style={labelStyle}>
            Data classification
            <select className="az-input" value={classification} onChange={e => setClassification(e.target.value)}>
              {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label style={{ fontSize: '.8rem', display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={personalData} onChange={e => setPersonalData(e.target.checked)} /> Handles personal data
          </label>
        </div>
      </div>

      <label style={{ fontSize: '.8rem', display: 'flex', gap: 6, alignItems: 'center' }}>
        <input type="checkbox" checked={openRequests} onChange={e => setOpenRequests(e.target.checked)} />
        Open a request for each change the report lists, so the coder can work on them
      </label>
      {critical && (
        <label style={{ fontSize: '.8rem', display: 'flex', gap: 6, alignItems: 'center', color: '#fca5a5' }}>
          <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
          I have rotated the exposed credentials and want to adopt anyway
        </label>
      )}

      <div>
        <button type="submit" className="btn btn-accent" disabled={busy || !name.trim() || !slug.trim() || (critical && !ack)}>
          {busy ? 'Adopting...' : 'Adopt and deploy to the sandbox'}
        </button>
        <span style={{ marginLeft: 10, color: 'var(--dim)', fontSize: '.78rem' }}>Production is never touched; promote from the app later.</span>
      </div>
      {error && <div style={{ color: '#fca5a5', fontSize: '.85rem' }}>{error}</div>}
    </form>
  )
}
