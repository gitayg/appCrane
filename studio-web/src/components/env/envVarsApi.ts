import { adminApi } from '../../adminApi'

export type EnvName = 'production' | 'sandbox'

export interface MaskedEnvVar {
  id?: number
  key: string
  value: string
  length?: number
  preview?: string
  fingerprint?: string
  error?: string
  updated_at?: string
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
}

const base = (slug: string, env: EnvName) =>
  `/api/apps/${encodeURIComponent(slug)}/env/${env}`

// The masked list: no ?reveal, so opening a card decrypts nothing for the
// viewer, writes no env-reveal row and mails nobody.
export const loadMaskedEnv = (slug: string, env: EnvName) =>
  adminApi.get<MaskedEnvList>(base(slug, env))

export const revealEnvVar = (slug: string, env: EnvName, key: string) =>
  adminApi.post<RevealedEnvVar>(`${base(slug, env)}/${encodeURIComponent(key)}/reveal`)

export const setEnvVar = (slug: string, env: EnvName, key: string, value: string) =>
  adminApi.put<{ message?: string }>(base(slug, env), { vars: { [key]: value } })

export const deleteEnvVar = (slug: string, env: EnvName, key: string) =>
  adminApi.del<{ message?: string }>(`${base(slug, env)}/${encodeURIComponent(key)}`)
