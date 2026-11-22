import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { POLICY_LABELS, type RiskOverview, type RiskPolicy } from './signinRiskTypes'

// Settings -> Security (platform admin): sign-in risk signals. Locked
// accounts (with unlock), flagged networks, stale accounts, recent signals and
// the policy. GET/PUT /api/signin-security, POST .../users/:id/unlock.

const dim = { color: 'var(--dim)', fontSize: '.78rem' } as const
const cell = { padding: '4px 12px 4px 0', verticalAlign: 'top' } as const
const when = (s: string | null) => (s ? new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z').toLocaleString() : 'never')
const sevColor = (s: string) => (s === 'critical' ? 'var(--red)' : s === 'warning' ? 'var(--amber, #b7791f)' : 'var(--dim)')

export function SignInRiskPanel() {
  const [data, setData] = useState<RiskOverview | null>(null)
  const [form, setForm] = useState<Record<string, string | boolean>>({})
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const load = useCallback(() => {
    adminApi.get<RiskOverview>('/api/signin-security').then((d) => {
      setData(d)
      setForm(Object.fromEntries(Object.entries(d.policy).map(([k, v]) => [k, typeof v === 'boolean' ? v : String(v)])))
    }).catch((e) => setMsg({ ok: false, text: (e as Error).message }))
  }, [])
  useEffect(load, [load])

  async function act(fn: () => Promise<unknown>, ok: string) {
    setBusy(true)
    setMsg(null)
    try {
      await fn()
      setMsg({ ok: true, text: ok })
      load()
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }

  const savePolicy = () => act(() => adminApi.put('/api/signin-security/policy', Object.fromEntries(
    Object.entries(form).map(([k, v]) => [k, typeof v === 'boolean' ? v : Number(v)]),
  )), 'Saved.')

  if (!data) return msg ? <div className="setting-card"><h3>Sign-in risk signals</h3><p style={{ color: 'var(--red)' }}>{msg.text}</p></div> : null

  return (
    <div className="setting-card">
      <h3>Sign-in risk signals</h3>
      <p style={{ ...dim, margin: '4px 0 12px' }}>
        New-browser sign-ins, per-account password lockouts, credential-stuffing networks and stale accounts. Every signal is also
        an event (kind login.risk.*), so SIEM streaming carries it. Lockouts cover password guessing only: single sign-on, existing
        sessions, API keys and browsers the person has signed in from before are not locked out.
      </p>

      <h4 style={{ margin: '12px 0 4px' }}>Locked accounts ({data.locked.length})</h4>
      {data.locked.length === 0 ? <p style={dim}>None.</p> : (
        <table style={{ fontSize: '.85rem', borderCollapse: 'collapse' }}>
          <tbody>
            {data.locked.map((l) => (
              <tr key={`${l.user_id}-${l.scope}`}>
                <td style={cell}>{l.name || l.username} <span style={dim}>{l.email}</span></td>
                <td style={cell}>{l.scope === 'device' ? 'one known browser' : 'unknown browsers'}</td>
                <td style={cell}>until {when(l.locked_until)} <span style={dim}>(lock #{l.lock_count}, last IP {l.last_ip || '?'})</span></td>
                <td style={cell}>
                  <button className="btn" disabled={busy}
                    onClick={() => act(() => adminApi.post(`/api/signin-security/users/${l.user_id}/unlock`), 'Unlocked.')}>Unlock</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4 style={{ margin: '12px 0 4px' }}>Flagged networks ({data.flagged_networks.length})</h4>
      {data.flagged_networks.length === 0 ? <p style={dim}>None.</p> : (
        <table style={{ fontSize: '.85rem', borderCollapse: 'collapse' }}>
          <tbody>
            {data.flagged_networks.map((n) => (
              <tr key={n.network}>
                <td style={cell}><code>{n.network}</code></td>
                <td style={cell}>{n.accounts} accounts failed</td>
                <td style={cell}>flagged until {when(n.until)}</td>
                <td style={cell}>
                  <button className="btn" disabled={busy}
                    onClick={() => act(() => adminApi.post('/api/signin-security/networks/clear', { network: n.network }), 'Flag cleared.')}>Clear</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4 style={{ margin: '12px 0 4px' }}>Stale accounts ({data.stale.length})</h4>
      <p style={{ ...dim, margin: '0 0 4px' }}>
        No sign-in for {data.policy.stale_days} days or more. {data.policy.stale_deactivate_days
          ? `Accounts idle ${data.policy.stale_deactivate_days} days are deactivated daily (never the last active platform admin).`
          : 'Automatic deactivation is off.'}
      </p>
      {data.stale.length > 0 && (
        <table style={{ fontSize: '.85rem', borderCollapse: 'collapse' }}>
          <tbody>
            {data.stale.slice(0, 50).map((s) => (
              <tr key={s.id}>
                <td style={cell}>{s.name || s.username} <span style={dim}>{s.email}</span></td>
                <td style={cell}>{s.role}</td>
                <td style={cell}>{s.never_signed_in ? 'never signed in' : `last sign-in ${when(s.last_login_at)}`}</td>
                <td style={cell}>{s.idle_days} days</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4 style={{ margin: '12px 0 4px' }}>Recent signals</h4>
      {data.signals.length === 0 ? <p style={dim}>None yet.</p> : (
        <div style={{ maxHeight: 240, overflowY: 'auto' }}>
          <table style={{ fontSize: '.8rem', borderCollapse: 'collapse' }}>
            <tbody>
              {data.signals.slice(0, 50).map((s) => (
                <tr key={s.id}>
                  <td style={{ ...cell, whiteSpace: 'nowrap' }}>{when(s.ts)}</td>
                  <td style={{ ...cell, color: sevColor(s.severity) }}>{s.severity}</td>
                  <td style={cell}>{s.summary}{s.subject_name || s.subject_username ? <span style={dim}> ({s.subject_name || s.subject_username})</span> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h4 style={{ margin: '12px 0 4px' }}>Policy</h4>
      <div style={{ display: 'grid', gap: 6 }}>
        {(Object.keys(POLICY_LABELS) as (keyof RiskPolicy)[]).map((k) => {
          const f = data.policy_fields[k]
          return (
            <label key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {f.type === 'bool' ? (
                <input type="checkbox" checked={form[k] === true} onChange={(e) => setForm((p) => ({ ...p, [k]: e.target.checked }))} />
              ) : (
                <input className="editable" type="number" min={f.min} max={f.max} style={{ width: 80 }}
                  value={String(form[k] ?? '')} onChange={(e) => setForm((p) => ({ ...p, [k]: e.target.value }))} />
              )}
              {POLICY_LABELS[k]}
            </label>
          )
        })}
      </div>
      <p style={{ ...dim, margin: '8px 0' }}>{data.geo.reason}</p>
      <button className="btn btn-primary" disabled={busy} onClick={savePolicy}>Save</button>
      {msg && <span style={{ marginLeft: 10, color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.85rem' }}>{msg.text}</span>}
    </div>
  )
}
