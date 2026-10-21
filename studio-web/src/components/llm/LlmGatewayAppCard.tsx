import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { LlmUsageTable } from './LlmUsageTable'
import { LIMIT_LABELS } from './llmTypes'
import type { AppGatewayView, EnvName } from './llmTypes'

// Per-app LLM gateway: the opt-in (owners, admins, platform admins), the
// limits that apply per environment with today's spend, the platform admin's
// overrides, and usage. 403 and 404 render nothing.

interface Props {
  slug: string
  isPlatformAdmin?: boolean
  onMsg?: (m: { text: string; ok: boolean }) => void
}

const ENVS: EnvName[] = ['production', 'sandbox']

export function LlmGatewayAppCard({ slug, isPlatformAdmin = false, onMsg }: Props) {
  const [view, setView] = useState<AppGatewayView | null>(null)
  const [hidden, setHidden] = useState(false)
  const [draft, setDraft] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  const base = `/api/apps/${encodeURIComponent(slug)}/llm-gateway`
  const say = (text: string, ok: boolean) => onMsg?.({ text, ok })

  const load = useCallback(async () => {
    const r = await fetch(base, { headers: adminApi.authHeaders() })
    if (r.status === 403 || r.status === 404) { setHidden(true); return }
    if (r.ok) { setHidden(false); setView(await r.json() as AppGatewayView) }
  }, [base])

  useEffect(() => { void load() }, [load])

  if (hidden || !view) return null
  const anyProvider = view.providers.anthropic || view.providers.openai

  async function toggle(enabled: boolean) {
    setBusy(true)
    try {
      setView(await adminApi.put<AppGatewayView>(base, { enabled }))
      say(enabled ? 'LLM gateway on. Redeploy the app to inject the gateway URL and token.' : 'LLM gateway off. Gateway calls are refused now; redeploy to remove the variables.', true)
    } catch (e) {
      say((e as Error).message, false)
    } finally {
      setBusy(false)
    }
  }

  async function saveOverrides() {
    if (draft === null) return
    let overrides: unknown
    try { overrides = JSON.parse(draft.trim() || '{}') } catch (e) { say(`Not valid JSON: ${(e as Error).message}`, false); return }
    setBusy(true)
    try {
      setView(await adminApi.put<AppGatewayView>(`${base}/overrides`, { overrides }))
      setDraft(null)
      say('LLM gateway overrides saved', true)
    } catch (e) {
      say((e as Error).message, false)
    } finally {
      setBusy(false)
    }
  }

  const dim = { color: 'var(--dim)', fontSize: '.82rem' }

  return (
    <div className="card">
      <h3>LLM gateway</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        Call Anthropic and OpenAI through AppCrane instead of keeping a provider key in the app. The official SDKs work unchanged:
        the deploy sets their base URL and API key variables to the gateway and this app's own token.
      </p>
      {!anyProvider && <p style={dim}>No provider is configured on this AppCrane yet. A platform admin sets one up in Settings.</p>}
      <label>
        <input type="checkbox" checked={view.enabled} disabled={busy || (!anyProvider && !view.enabled)} onChange={e => void toggle(e.target.checked)} />
        {' '}Use AppCrane's LLM gateway
      </label>

      <table style={{ marginTop: 10 }}>
        <thead><tr><th>Limit</th>{ENVS.map(e => <th key={e}>{e}</th>)}</tr></thead>
        <tbody>
          {LIMIT_LABELS.map(([k, label]) => (
            <tr key={k}><td>{label}</td>{ENVS.map(e => <td key={e}>{view.envs[e].limits[k] ?? 'none'}</td>)}</tr>
          ))}
          <tr><td>Requests today</td>{ENVS.map(e => <td key={e}>{view.envs[e].spent.requestsToday}</td>)}</tr>
          <tr><td>Tokens today</td>{ENVS.map(e => <td key={e}>{view.envs[e].spent.tokensToday}</td>)}</tr>
          <tr><td>Estimated $ this month</td>{ENVS.map(e => <td key={e}>${view.envs[e].spent.usdThisMonth.toFixed(4)}</td>)}</tr>
        </tbody>
      </table>

      {isPlatformAdmin && (
        <details style={{ marginTop: 10 }}>
          <summary>Overrides (platform admin)</summary>
          <p style={dim}>{'{ "allowed_models": { "anthropic": ["claude-*"] }, "limits": { "requests_per_day": 500 }, "env_limits": { "sandbox": { "usd_per_month": 5 } } }'}</p>
          <textarea rows={6} className="am-mono" style={{ width: '100%' }}
            value={draft ?? JSON.stringify(view.overrides || {}, null, 2)} onChange={e => setDraft(e.target.value)} />
          <button className="btn" disabled={busy || draft === null} onClick={() => void saveOverrides()}>Save overrides</button>
        </details>
      )}

      <h4 style={{ marginTop: 14 }}>Usage <button className="btn" onClick={() => { setReload(r => r + 1); void load() }}>Refresh</button></h4>
      <LlmUsageTable url={`${base}/usage`} reload={reload} />
    </div>
  )
}
