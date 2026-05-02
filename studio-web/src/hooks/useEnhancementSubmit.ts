import { useCallback, useState } from 'react'
import { adminApi } from '../adminApi'

export interface SubmitResult {
  ok: boolean
  enhancementId?: number
  message?: string
}

export interface EnhancementSubmit {
  submit: (text: string) => Promise<SubmitResult>
  busy: boolean
  last: SubmitResult | null
  reset: () => void
}

/**
 * Submit an enhancement request for a given app slug. Returns the new
 * enhancement_id on success. Mirrors the portal's plan-submit path:
 * POST /api/enhancements with { message, app_slug }.
 */
export function useEnhancementSubmit(slug: string | null | undefined): EnhancementSubmit {
  const [busy, setBusy] = useState(false)
  const [last, setLast] = useState<SubmitResult | null>(null)

  const submit = useCallback(async (text: string): Promise<SubmitResult> => {
    const trimmed = text.trim()
    if (!trimmed || !slug || busy) {
      const r: SubmitResult = { ok: false, message: 'Empty or busy' }
      setLast(r)
      return r
    }
    setBusy(true)
    try {
      const d = await adminApi.post<{ enhancement_id?: number; message?: string }>(
        '/api/enhancements',
        { message: trimmed, app_slug: slug },
      )
      const r: SubmitResult = { ok: true, enhancementId: d.enhancement_id, message: d.message }
      setLast(r)
      return r
    } catch (err) {
      const r: SubmitResult = { ok: false, message: err instanceof Error ? err.message : 'Submit failed' }
      setLast(r)
      return r
    } finally {
      setBusy(false)
    }
  }, [slug, busy])

  const reset = useCallback(() => { setLast(null) }, [])

  return { submit, busy, last, reset }
}
