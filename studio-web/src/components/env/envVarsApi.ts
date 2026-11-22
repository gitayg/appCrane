import { adminApi } from '../../adminApi'

export type EnvName = 'production' | 'sandbox'
export type EnvStore = 'secrets_manager'

export interface MaskedEnvVar {
  id?: number
  key: string
  value: string
  length?: number
  preview?: string
  fingerprint?: string
  error?: string
  updated_at?: string
  // Set on a Secrets Manager reference: value is `secretsmanager:<NAME>`, never the secret.
  source?: EnvStore
}

export interface MaskedEnvList {
  env: EnvName
  vars: MaskedEnvVar[]
  warnings?: string[]
  can_reveal?: boolean
  reveal_refusal?: string
}

export interface RevealedEnvVar {
  env: EnvName
  key: string
  value: string
  fingerprint?: string
  updated_at?: string
  source?: EnvStore
}

export interface SecretsProviderStatus {
  active: boolean
  provider: string | null
  region: string | null
  platform_secret_configured: boolean
  app_prefix: string | null
  app_secrets: boolean
}

const base = (slug: string, env: EnvName) =>
  `/api/apps/${encodeURIComponent(slug)}/env/${env}`

// The masked list: no ?reveal, so opening a card decrypts nothing for the
// viewer, writes no env-reveal row and mails nobody.
export const loadMaskedEnv = (slug: string, env: EnvName) =>
  adminApi.get<MaskedEnvList>(base(slug, env))

export const revealEnvVar = (slug: string, env: EnvName, key: string) =>
  adminApi.post<RevealedEnvVar>(`${base(slug, env)}/${encodeURIComponent(key)}/reveal`)

export const setEnvVar = (slug: string, env: EnvName, key: string, value: string, store?: EnvStore) =>
  adminApi.put<{ message?: string }>(base(slug, env), { vars: { [key]: value }, ...(store && { store }) })

export const deleteEnvVar = (slug: string, env: EnvName, key: string) =>
  adminApi.del<{ message?: string; aws_secret_retained?: string }>(`${base(slug, env)}/${encodeURIComponent(key)}`)

// Platform admin only.
export const loadSecretsProviderStatus = () =>
  adminApi.get<SecretsProviderStatus>('/api/settings/secrets-provider')
