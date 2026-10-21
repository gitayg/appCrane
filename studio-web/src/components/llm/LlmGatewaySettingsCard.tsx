import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { LlmUsageTable } from './LlmUsageTable'
import { PasswordInput } from '../secret/PasswordInput'
import { LIMIT_LABELS } from './llmTypes'
import type { GatewayConfig, Limits, Provider } from './llmTypes'

// Platform admin: AppCrane's LLM gateway. Apps that opt in call Anthropic and
// OpenAI through AppCrane with a gateway token; the provider keys set here
// never enter a container. Keys are write-only: the page only ever shows a
// masked tail.

const PROVIDERS: Provider[] = ['anthropic', 'openai']

const list = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean)

interface Draft {
  enabled: Record<Provider, boolean>
  keys: Record<Provider, string>
  baseUrl: Record<Provider, string>
  authHeader: 'bearer' | 'api-key'
  privateHosts: string
  allowed: Record<Provider, string>
  modelMap: string
  prices: string
  classification: string
  limits: Limits
  maxBodyKb: string
}

function toDraft(c: GatewayConfig): Draft {
  return {
    enabled: { anthropic: c.providers.anthropic.enabled, openai: c.providers.openai.enabled },
    keys: { anthropic: '', openai: '' },
    baseUrl: { anthropic: c.providers.anthropic.base_url, openai: c.providers.openai.base_url },
    authHeader: c.providers.openai.auth_header || 'bearer',
    privateHosts: (c.private_hosts || []).join(', '),
    allowed: { anthropic: (c.allowed_models.anthropic || []).join(', '), openai: (c.allowed_models.openai || []).join(', ') },
    modelMap: JSON.stringify(c.model_map || {}, null, 2),
    prices: JSON.stringify(c.prices || {}, null, 2),
    classification: JSON.stringify(c.classification_models || {}, null, 2),
    limits: { ...c.limits },
    maxBodyKb: c.limits.max_body_kb ? String(c.limits.max_body_kb) : '',
  }
}

export function LlmGatewaySettingsCard() {
  const [cfg, setCfg] = useState<GatewayConfig | null>(null)
  const [gatewayUrl, setGatewayUrl] = useState('')
  const [draft, setDraft] = useState<Draft | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    adminApi.get<{ config: GatewayConfig; gateway_url: string }>('/api/llm-gateway/config')
      .then(d => { setCfg(d.config); setGatewayUrl(d.gateway_url); setDraft(toDraft(d.config)) })
      .catch(() => {})
  }, [])

  if (!cfg || !draft) return null

  async function save(patch?: Record<string, unknown>) {
    if (!draft) return
    let body: Record<string, unknown>
    try {
      body = patch || {
        providers: Object.fromEntries(PROVIDERS.map(p => [p, {
          enabled: draft.enabled[p],
          base_url: draft.baseUrl[p],
          ...(draft.keys[p] ? { api_key: draft.keys[p] } : {}),
          ...(p === 'openai' ? { auth_header: draft.authHeader } : {}),
        }])),
        private_hosts: list(draft.privateHosts),
        allowed_models: { anthropic: list(draft.allowed.anthropic), openai: list(draft.allowed.openai) },
        model_map: JSON.parse(draft.modelMap || '{}'),
        prices: JSON.parse(draft.prices || '{}'),
        classification_models: JSON.parse(draft.classification || '{}'),
        limits: { ...Object.fromEntries(LIMIT_LABELS.map(([k]) => [k, draft.limits[k] ?? null])), max_body_kb: draft.maxBodyKb ? Number(draft.maxBodyKb) : null },
      }
    } catch (e) {
      setMsg({ text: `Not valid JSON: ${(e as Error).message}`, ok: false })
      return
    }
    setBusy(true)
    try {
      const d = await adminApi.put<{ config: GatewayConfig }>('/api/llm-gateway/config', body)
      setCfg(d.config)
      setDraft(toDraft(d.config))
      setMsg({ text: 'LLM gateway settings saved. Apps pick up provider changes at their next deploy.', ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  const set = (fn: (d: Draft) => void) => setDraft(d => { if (!d) return d; const n = structuredClone(d); fn(n); return n })
  const dim = { color: 'var(--dim)', fontSize: '.82rem' }

  return (
    <div className="card">
      <h3>LLM gateway</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        Apps that turn on the gateway reach Anthropic and OpenAI through AppCrane at <span className="am-mono">{gatewayUrl}</span>.
        Their deploy gets <span className="am-mono">ANTHROPIC_BASE_URL</span> / <span className="am-mono">OPENAI_BASE_URL</span> and
        a gateway token as the API key; the keys below never enter a container. Prompts and responses are not stored.
      </p>

      {PROVIDERS.map(p => (
        <fieldset key={p} style={{ marginBottom: 10 }}>
          <legend>{p === 'anthropic' ? 'Anthropic' : 'OpenAI or OpenAI-compatible'}</legend>
          <label><input type="checkbox" checked={draft.enabled[p]} onChange={e => set(d => { d.enabled[p] = e.target.checked })} /> Enabled</label>
          <div style={{ marginTop: 6 }}>
            <label>API key{' '}
              <PasswordInput label="API key" autoComplete="off" placeholder={cfg.providers[p].key_configured ? `Saved ${cfg.providers[p].key_preview}` : 'Not set'}
                value={draft.keys[p]} onChange={e => set(d => { d.keys[p] = e.target.value })} style={{ width: 280 }} />
            </label>{' '}
            {cfg.providers[p].key_configured && (
              <button className="btn" disabled={busy} onClick={() => void save({ providers: { [p]: { api_key: '' } } })}>Remove key</button>
            )}
          </div>
          <div style={{ marginTop: 6 }}>
            <label>Base URL{' '}
              <input value={draft.baseUrl[p]} onChange={e => set(d => { d.baseUrl[p] = e.target.value })} style={{ width: 320 }} />
            </label>
            {p === 'openai' && (
              <label style={{ marginLeft: 10 }}>Auth header{' '}
                <select value={draft.authHeader} onChange={e => set(d => { d.authHeader = e.target.value as 'bearer' | 'api-key' })}>
                  <option value="bearer">Authorization: Bearer</option>
                  <option value="api-key">api-key</option>
                </select>
              </label>
            )}
          </div>
          <div style={{ marginTop: 6 }}>
            <label>Allowed models (comma separated, * suffix allowed, empty = any){' '}
              <input value={draft.allowed[p]} onChange={e => set(d => { d.allowed[p] = e.target.value })} style={{ width: 360 }} />
            </label>
          </div>
        </fieldset>
      ))}

      <div style={{ marginBottom: 8 }}>
        <label>Private hosts the gateway may call (an on-prem server; every other host must be public https){' '}
          <input value={draft.privateHosts} onChange={e => set(d => { d.privateHosts = e.target.value })} style={{ width: 320 }} />
        </label>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 8 }}>
        {LIMIT_LABELS.map(([k, label]) => (
          <label key={k}>{label}{' '}
            <input type="number" min={0} placeholder="none" value={draft.limits[k] ?? ''} style={{ width: 100 }}
              onChange={e => set(d => { d.limits[k] = e.target.value === '' ? null : Number(e.target.value) })} />
          </label>
        ))}
        <label>Max request body (KB){' '}
          <input type="number" min={1} placeholder="8192" value={draft.maxBodyKb} style={{ width: 100 }} onChange={e => set(d => { d.maxBodyKb = e.target.value })} />
        </label>
      </div>
      <p style={dim}>Default limits for every app and environment. A platform admin can override them per app. Budgets reset daily (UTC) and monthly.</p>

      <details style={{ marginBottom: 8 }}>
        <summary>Model map, prices and data-classification lists</summary>
        <label style={{ display: 'block', marginTop: 6 }}>Model map: {'{ "anthropic": { "requested": "used", "default": "..." }, "openai": { ... } }'}
          <textarea rows={4} value={draft.modelMap} onChange={e => set(d => { d.modelMap = e.target.value })} style={{ width: '100%' }} className="am-mono" />
        </label>
        <label style={{ display: 'block', marginTop: 6 }}>Prices, USD per million tokens: {'{ "model": { "input": 3, "output": 15 } }'}
          <textarea rows={4} value={draft.prices} onChange={e => set(d => { d.prices = e.target.value })} style={{ width: '100%' }} className="am-mono" />
        </label>
        <label style={{ display: 'block', marginTop: 6 }}>Allowed models per data classification: {'{ "confidential": ["model-*"] }'}
          <textarea rows={3} value={draft.classification} onChange={e => set(d => { d.classification = e.target.value })} style={{ width: '100%' }} className="am-mono" />
        </label>
      </details>

      <button className="btn" disabled={busy} onClick={() => void save()}>Save</button>{' '}
      {msg && <span style={{ color: msg.ok ? 'var(--ok, inherit)' : 'var(--err, #e5484d)' }}>{msg.text}</span>}

      <h4 style={{ marginTop: 16 }}>Usage <button className="btn" onClick={() => setReload(r => r + 1)}>Refresh</button></h4>
      <LlmUsageTable url="/api/llm-gateway/usage" showApp reload={reload} />
    </div>
  )
}
