export type AiUse = 'none' | 'assistive' | 'decisions_about_people' | 'annex_iii'

export interface LiteracyStatement { version: string; text: string; sha256: string }
export interface Literacy { statement: LiteracyStatement; acknowledged: boolean; acknowledged_at: string | null }

export interface AiActView {
  app: string
  ai: { ai_use: AiUse | null; annex_iii_category: string | null; ai_use_set_at: string | null; uses_ai: boolean; guidance: string | null; locked: boolean; review_required: boolean }
  options: { ai_uses: AiUse[]; annex_iii_categories: { id: string; label: string }[]; guidance: Record<string, string> }
  notice: { enabled: boolean; text: string; custom_text: boolean; default_text: string; max_length: number; updated_at: string | null }
  retention: { llm_gateway_logs_days: number; configured_days: number; floor_applied: boolean; ai_floor_days: number }
  gate: { ok: boolean; message: string }
  literacy: Literacy
  can_edit: boolean
}

export interface InventoryRow {
  app: string; name: string; ai_use: AiUse | null; annex_iii_category: string | null; data_classification: string
  intake_status: string; gateway_enabled: boolean; providers: string[]; models: string[]
  first_seen: string | null; last_seen: string | null; calls: number; refused_calls: number
  transparency_notice: boolean; llm_log_retention_days: number; mismatch: boolean; mismatch_reason: string | null
}

export const AI_USE_LABELS: Record<AiUse, string> = {
  none: 'No AI',
  assistive: 'Assistive (AI helps a person who decides)',
  decisions_about_people: 'Makes decisions about people',
  annex_iii: 'An Annex III use (pick the area)',
}
