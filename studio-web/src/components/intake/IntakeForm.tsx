import { LEVELS, type IntakeDraft, type Level } from './types'

const HINT: Record<Level, string> = {
  public: 'Safe for anyone to see.',
  internal: 'Company-internal, no sensitive data.',
  confidential: 'Customer, financial or personal data. Production waits for security approval by default.',
  restricted: 'Highly sensitive data. Needs security approval, path access rules and the SSO gate by default.',
}

/** The intake questions. Controlled: used in the New App flow and on the Manage page. */
export function IntakeForm({ value, onChange, lockedLevel }: {
  value: IntakeDraft
  onChange: (v: IntakeDraft) => void
  lockedLevel?: boolean
}) {
  const set = <K extends keyof IntakeDraft>(k: K, v: IntakeDraft[K]) => onChange({ ...value, [k]: v })
  const label = { display: 'flex', flexDirection: 'column' as const, gap: 4, fontSize: '.8rem' }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <label style={label}>
        What is the app for?
        <textarea className="am-input" rows={2} maxLength={2000} value={value.purpose} onChange={e => set('purpose', e.target.value)} />
      </label>
      <label style={label}>
        Data classification
        <select className="am-input" value={value.data_classification} disabled={lockedLevel}
          onChange={e => set('data_classification', e.target.value as Level)}>
          {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
        </select>
        <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
          {HINT[value.data_classification]}{lockedLevel ? ' Set by a platform admin.' : ''}
        </span>
      </label>
      <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '.8rem' }}>
        <input type="checkbox" checked={value.personal_data} onChange={e => set('personal_data', e.target.checked)} />
        Stores personal or customer data
      </label>
      <label style={label}>
        External integrations (APIs, services, data sources)
        <input className="am-input" maxLength={2000} value={value.external_integrations} onChange={e => set('external_integrations', e.target.value)} />
      </label>
      <label style={label}>
        Who should have access?
        <input className="am-input" maxLength={2000} value={value.access} onChange={e => set('access', e.target.value)} />
      </label>
    </div>
  )
}
