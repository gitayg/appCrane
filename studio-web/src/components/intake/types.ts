export type Level = 'public' | 'internal' | 'confidential' | 'restricted'
export const LEVELS: Level[] = ['public', 'internal', 'confidential', 'restricted']

export interface IntakeDraft {
  purpose: string
  data_classification: Level
  personal_data: boolean
  external_integrations: string
  access: string
}

export const EMPTY_INTAKE: IntakeDraft = {
  purpose: '', data_classification: 'internal', personal_data: false, external_integrations: '', access: '',
}

export interface IntakeRow {
  app_id: number
  data_classification: Level
  classification_locked: boolean
  purpose: string | null
  personal_data: boolean
  external_integrations: string | null
  access_notes: string | null
  status: 'pending' | 'approved' | 'rejected'
  grandfathered: boolean
  submitted_at: string
  reviewed_at: string | null
  review_comment: string | null
  slug?: string
  name?: string
  submitted_by_name?: string | null
  reviewed_by_name?: string | null
}

export interface IntakeGate { ok: boolean; required: boolean; status: string; data_classification: Level; message: string }

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'excepted'
export interface ReleaseCheckItem {
  id: string
  label: string
  status: CheckStatus
  reasons: string[]
  exception?: { id: number; reason: string; expires_at: string; created_by: string | number }
}
export interface ReleaseCheckRecord {
  id: number
  trigger: string
  candidate: string
  data_classification: Level
  mode: 'enforce' | 'warn' | 'off'
  result: 'pass' | 'warn' | 'fail' | 'skipped'
  blocked: boolean
  checks: ReleaseCheckItem[]
  created_at?: string
}
