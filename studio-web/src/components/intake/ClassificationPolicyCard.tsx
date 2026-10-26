import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { LEVELS, type Level } from './types'

interface LevelPolicy {
  intake_approval: boolean
  release_check: 'enforce' | 'warn' | 'off'
  require_access_rules: boolean
  allow_sso_bypass: boolean
  allow_public_visibility: boolean
  exceptions_by: 'owner' | 'platform_admin'
}
interface Policy { release_check_mode: 'by_classification' | 'enforce' | 'warn' | 'off'; block_vulnerable_dependencies: boolean; levels: Record<Level, LevelPolicy> }

const BOOLS: { key: keyof LevelPolicy; label: string }[] = [
  { key: 'intake_approval', label: 'Intake approval before production' },
  { key: 'require_access_rules', label: 'Path access rules required' },
  { key: 'allow_sso_bypass', label: 'Headless, bypass paths or custom domain allowed' },
  { key: 'allow_public_visibility', label: 'Public visibility allowed' },
]

/** Settings, platform admins: what each data classification requires before production. */
export function ClassificationPolicyCard() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  useEffect(() => {
    adminApi.get<{ policy: Policy }>('/api/data-classification/policy').then(r => setPolicy(r.policy)).catch(() => setPolicy(null))
  }, [])

  async function save(patch: Partial<Policy> | { levels: Partial<Record<Level, Partial<LevelPolicy>>> }) {
    try {
      const r = await adminApi.put<{ policy: Policy }>('/api/data-classification/policy', patch)
      setPolicy(r.policy)
      setMsg({ text: 'Saved', ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    }
  }

  if (!policy) return null
  const cell = { padding: '4px 8px', textAlign: 'center' as const }
  return (
    <div className="am-card" style={{ marginTop: 16 }}>
      <h3 style={{ marginTop: 0 }}>Data classification and release check</h3>
      <label style={{ fontSize: '.85rem', display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
        Release check mode
        <select className="am-input" value={policy.release_check_mode}
          onChange={e => save({ release_check_mode: e.target.value as Policy['release_check_mode'] })}>
          <option value="by_classification">By classification (below)</option>
          <option value="enforce">Enforce for every app</option>
          <option value="warn">Warn only, for every app</option>
          <option value="off">Off for every app (intake still applies)</option>
        </select>
      </label>
      <label style={{ fontSize: '.85rem', display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
        <input type="checkbox" checked={policy.block_vulnerable_dependencies}
          onChange={e => save({ block_vulnerable_dependencies: e.target.checked })} />
        Block production deploys of any app with a vulnerable dependency that has a published fix
      </label>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ fontSize: '.8rem' }}>
          <thead>
            <tr><th style={{ textAlign: 'left' }}>Rule</th>{LEVELS.map(l => <th key={l} style={cell}>{l}</th>)}</tr>
          </thead>
          <tbody>
            <tr>
              <td>Release check</td>
              {LEVELS.map(l => (
                <td key={l} style={cell}>
                  <select className="am-input" value={policy.levels[l].release_check}
                    onChange={e => save({ levels: { [l]: { release_check: e.target.value as LevelPolicy['release_check'] } } })}>
                    <option value="enforce">enforce</option><option value="warn">warn</option><option value="off">off</option>
                  </select>
                </td>
              ))}
            </tr>
            {BOOLS.map(b => (
              <tr key={b.key}>
                <td>{b.label}</td>
                {LEVELS.map(l => (
                  <td key={l} style={cell}>
                    <input type="checkbox" checked={!!policy.levels[l][b.key]}
                      onChange={e => save({ levels: { [l]: { [b.key]: e.target.checked } } })} />
                  </td>
                ))}
              </tr>
            ))}
            <tr>
              <td>Who records exceptions</td>
              {LEVELS.map(l => (
                <td key={l} style={cell}>
                  <select className="am-input" value={policy.levels[l].exceptions_by}
                    onChange={e => save({ levels: { [l]: { exceptions_by: e.target.value as LevelPolicy['exceptions_by'] } } })}>
                    <option value="owner">owner</option><option value="platform_admin">platform admin</option>
                  </select>
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
      {msg && <div style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.8rem', marginTop: 6 }}>{msg.text}</div>}
    </div>
  )
}
