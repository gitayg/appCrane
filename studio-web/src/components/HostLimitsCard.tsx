import { useCallback, useEffect, useState } from 'react'
import { adminApi, ApiError } from '../adminApi'
import { serverDate } from '../utils/serverDate'

type ItemState = 'applied' | 'missing' | 'not-applicable' | 'unknown'

interface HardeningItem {
  id: string
  label: string
  state: ItemState
  detail: string
}

interface HardeningStatus {
  supported: boolean
  reason?: string
  items: HardeningItem[]
  run: {
    mode: 'root' | 'sudo' | 'manual' | 'unsupported'
    command: string | null
    reason?: string
    installed_copy_stale?: boolean
    setup_command?: string
  }
  mfa_required: boolean
  running: boolean
  last_run: { at: string; ok: boolean; exit_code: number | null; by: string } | null
}

interface ApplyResult {
  ok: boolean
  exit_code: number | null
  output: string
  status: HardeningStatus
}

const STATUS_PATH = '/api/settings/host-hardening'
const APPLY_PATH = '/api/settings/host-hardening/apply'
const POLL_MS = 5_000

const STATE_STYLE: Record<ItemState, { label: string; color: string }> = {
  applied:          { label: 'Applied',        color: 'var(--green)' },
  missing:          { label: 'Missing',        color: 'var(--orange)' },
  'not-applicable': { label: 'Not applicable', color: 'var(--dim)' },
  unknown:          { label: 'Unknown',        color: 'var(--dim)' },
}

function StatePill({ state }: { state: ItemState }) {
  const s = STATE_STYLE[state] || STATE_STYLE.unknown
  return (
    <span className="badge" style={{
      color: s.color,
      background: `color-mix(in srgb, ${s.color} 14%, transparent)`,
      whiteSpace: 'nowrap',
    }}>
      {s.label}
    </span>
  )
}

function CommandBlock({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(command)
      .then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800) })
      .catch(() => {})
  }
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, margin: '4px 0 10px' }}>
      <pre style={{
        flex: 1, margin: 0, padding: 8, borderRadius: 6, overflow: 'auto',
        border: '1px solid var(--border)', background: 'var(--surface2)', fontSize: '.8rem',
      }}><code>{command}</code></pre>
      <button className="btn" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
    </div>
  )
}

function applyErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case 'MFA_REQUIRED': return 'Enter a two-factor code to apply these changes.'
      case 'MFA_INVALID': return 'That code is wrong or has expired. Try the current code from your authenticator app, or a recovery code.'
      case 'RUNNING': return 'These changes are already being applied. This card updates when they finish.'
      case 'MANUAL_ONLY': return 'AppCrane can\'t apply these changes itself on this server. Run the command below as root instead.'
    }
    if (e.status === 429) return 'Too many attempts. Wait a minute, then try again.'
    return e.message
  }
  return e instanceof Error ? e.message : String(e)
}

export function HostLimitsCard() {
  const [status, setStatus] = useState<HardeningStatus | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [step, setStep] = useState<'idle' | 'confirm' | 'applying'>('idle')
  const [code, setCode] = useState('')
  const [applyError, setApplyError] = useState<string | null>(null)
  const [manualCommand, setManualCommand] = useState<string | null>(null)
  const [result, setResult] = useState<{ ok: boolean; exit_code: number | null; output: string } | null>(null)

  const load = useCallback(() => {
    adminApi.get<HardeningStatus>(STATUS_PATH)
      .then(r => { setStatus(r); setLoadError(null) })
      .catch(e => setLoadError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => { load() }, [load])

  const running = !!status?.running
  useEffect(() => {
    if (!running || step === 'applying') return
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [running, step, load])

  async function apply() {
    if (!status) return
    setStep('applying'); setApplyError(null); setManualCommand(null); setResult(null)
    try {
      const body = status.mfa_required ? { mfa_code: code.trim() } : {}
      const r = await adminApi.post<ApplyResult>(APPLY_PATH, body)
      setResult({ ok: r.ok, exit_code: r.exit_code, output: r.output })
      if (r.status) setStatus(r.status)
      setCode('')
      setStep('idle')
    } catch (e) {
      setApplyError(applyErrorText(e))
      if (e instanceof ApiError && e.code === 'MANUAL_ONLY' && typeof e.details.command === 'string') {
        setManualCommand(e.details.command)
      }
      if (e instanceof ApiError && e.code === 'RUNNING') load()
      setStep(e instanceof ApiError && (e.code === 'MFA_INVALID' || e.code === 'MFA_REQUIRED') ? 'confirm' : 'idle')
    }
  }

  function cancel() {
    setStep('idle'); setCode(''); setApplyError(null)
  }

  const items = status?.items || []
  const counted = items.filter(i => i.state !== 'not-applicable')
  const applied = counted.filter(i => i.state === 'applied').length
  const anyMissing = items.some(i => i.state === 'missing')
  const canRun = status?.run.mode === 'root' || status?.run.mode === 'sudo'
  const busy = step === 'applying' || running

  return (
    <div className="setting-card" style={{ marginTop: 20 }}>
      <h3>Host limits</h3>
      <p>Log size caps, disk reserve and automatic security updates for this server.</p>

      {loadError && <p style={{ color: 'var(--red)' }}>{loadError}</p>}
      {!status && !loadError && <p style={{ color: 'var(--dim)' }}>Loading...</p>}

      {status && !status.supported && (
        <p style={{ color: 'var(--dim)' }}>{status.reason || 'These settings are not available on this server.'}</p>
      )}

      {status && status.supported && (
        <>
          <p style={{ fontWeight: 600, color: anyMissing ? 'var(--orange)' : 'var(--green)', marginBottom: 6 }}>
            {applied} of {counted.length} applied
          </p>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse', marginBottom: 12 }}>
            <tbody>
              {items.map(i => (
                <tr key={i.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 6px', width: 120 }}><StatePill state={i.state} /></td>
                  <td style={{ padding: '8px 6px' }}>
                    <div style={{ fontWeight: 600 }}>{i.label}</div>
                    {i.detail && <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>{i.detail}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {status.last_run && (
            <p style={{ fontSize: '.8rem', marginBottom: 8 }}>
              Last applied {serverDate(status.last_run.at).toLocaleString()} by {status.last_run.by} —{' '}
              <span style={{ color: status.last_run.ok ? 'var(--green)' : 'var(--red)' }}>
                {status.last_run.ok ? 'succeeded' : `failed${status.last_run.exit_code != null ? ` (exit ${status.last_run.exit_code})` : ''}`}
              </span>
            </p>
          )}

          {status.run.installed_copy_stale && (
            <div style={{ marginBottom: 8 }}>
              <p style={{ color: 'var(--orange)', fontSize: '.8rem', marginBottom: 4 }}>
                The copy of the script that runs as root is older than this version of AppCrane.
                {status.run.setup_command ? ' Run this on the server to refresh it:' : ''}
              </p>
              {status.run.setup_command && <CommandBlock command={status.run.setup_command} />}
            </div>
          )}

          {status.run.mode === 'manual' && (
            <div>
              <p style={{ fontSize: '.8rem', marginBottom: 4 }}>
                AppCrane can't run this itself (it runs without root and no sudo rule is installed). Run on the server:
              </p>
              {status.run.command && <CommandBlock command={status.run.command} />}
              {status.run.reason && <p style={{ fontSize: '.8rem' }}>{status.run.reason}</p>}
              {status.run.setup_command && !status.run.installed_copy_stale && (
                <>
                  <p style={{ fontSize: '.8rem', marginBottom: 4 }}>To apply it from this page instead, run this once on the server:</p>
                  <CommandBlock command={status.run.setup_command} />
                </>
              )}
            </div>
          )}

          {status.run.mode === 'unsupported' && status.run.reason && (
            <p style={{ fontSize: '.8rem' }}>{status.run.reason}</p>
          )}

          {canRun && (
            <div>
              {status.run.reason && <p style={{ fontSize: '.8rem' }}>{status.run.reason}</p>}
              {step === 'idle' && (
                <button className="btn btn-accent" disabled={busy} onClick={() => { setApplyError(null); setStep('confirm') }}>
                  {anyMissing ? 'Apply' : 'Re-apply'}
                </button>
              )}
              {step === 'confirm' && (
                <form onSubmit={e => { e.preventDefault(); apply() }} style={{ maxWidth: 420 }}>
                  <p style={{ fontSize: '.8rem', marginBottom: 8 }}>
                    Runs scripts/host-hardening.sh as root on this server. It restarts journald and logrotate's timer, never Docker.
                  </p>
                  {status.mfa_required && (
                    <>
                      <label htmlFor="host-limits-mfa" style={{ display: 'block', fontSize: '.8rem', color: 'var(--dim)', marginBottom: 4 }}>
                        Code from your authenticator app, or a recovery code
                      </label>
                      <input
                        id="host-limits-mfa" type="text" autoComplete="one-time-code" autoFocus
                        value={code} onChange={e => setCode(e.target.value)}
                        style={{ width: '100%', marginBottom: 8, fontFamily: 'monospace' }}
                      />
                    </>
                  )}
                  <div className="save-row" style={{ marginTop: 0 }}>
                    <button className="btn btn-accent" type="submit" disabled={status.mfa_required && !code.trim()}>
                      {anyMissing ? 'Apply' : 'Re-apply'}
                    </button>
                    <button className="btn" type="button" onClick={cancel}>Cancel</button>
                  </div>
                </form>
              )}
              {busy && (
                <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: 8 }}>
                  Applying… this can take a few minutes.
                </p>
              )}
            </div>
          )}

          {applyError && <p style={{ color: 'var(--red)', fontSize: '.85rem', marginTop: 8 }}>{applyError}</p>}
          {manualCommand && <CommandBlock command={manualCommand} />}

          {result && (
            <div style={{ marginTop: 10 }}>
              <p style={{ fontSize: '.8rem', marginBottom: 4, color: result.ok ? 'var(--green)' : 'var(--red)' }}>
                {result.ok ? 'Applied.' : `The script failed${result.exit_code != null ? ` (exit ${result.exit_code})` : ''}.`} Output:
              </p>
              <pre style={{
                margin: 0, padding: 8, borderRadius: 6, overflow: 'auto', maxHeight: 320,
                whiteSpace: 'pre-wrap', border: '1px solid var(--border)', background: 'var(--surface2)', fontSize: '.78rem',
              }}>{result.output || '(no output)'}</pre>
            </div>
          )}
        </>
      )}
    </div>
  )
}
