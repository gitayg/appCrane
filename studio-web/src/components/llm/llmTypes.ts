export type Provider = 'anthropic' | 'openai'
export type EnvName = 'production' | 'sandbox'

export interface Limits {
  requests_per_minute?: number | null
  requests_per_day?: number | null
  tokens_per_day?: number | null
  usd_per_month?: number | null
  max_tokens_per_request?: number | null
  max_body_kb?: number | null
}

export interface ProviderConfig {
  enabled: boolean
  base_url: string
  auth_header?: 'bearer' | 'api-key'
  key_configured: boolean
  key_preview: string | null
}

export interface GatewayConfig {
  providers: Record<Provider, ProviderConfig>
  private_hosts: string[]
  allowed_models: Record<Provider, string[]>
  model_map: Record<Provider, Record<string, string>>
  prices: Record<string, { input: number; output: number }>
  limits: Limits
  classification_models: Record<string, string[]>
}

export interface UsageRow {
  day: string
  app_id: number
  app_slug: string | null
  env: EnvName
  provider: Provider
  model: string | null
  requests: number
  failed: number
  refused: number
  input_tokens: number
  output_tokens: number
  cost_usd: number | null
  avg_latency_ms: number | null
}

export interface AppOverrides {
  allowed_models?: Partial<Record<Provider, string[]>>
  limits?: Limits
  env_limits?: Partial<Record<EnvName, Limits>>
}

export interface AppGatewayView {
  app: string
  enabled: boolean
  overrides: AppOverrides
  providers: Record<Provider, boolean>
  envs: Record<EnvName, { limits: Limits; spent: { requestsToday: number; tokensToday: number; usdThisMonth: number } }>
}

export const LIMIT_LABELS: [keyof Limits, string][] = [
  ['requests_per_minute', 'Requests / minute'],
  ['requests_per_day', 'Requests / day'],
  ['tokens_per_day', 'Tokens / day'],
  ['usd_per_month', 'Estimated $ / month'],
  ['max_tokens_per_request', 'Max tokens / request'],
]
