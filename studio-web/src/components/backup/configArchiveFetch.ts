import { adminApi, authHeaders } from '../../adminApi'
import { requestStepUp, stepUpHintOf } from '../../stepUp'

// Platform backup export and import (server/services/configArchiveGuard.js):
// a dashboard session with a recent step-up. These calls stream a file, so
// they use fetch directly; a 401 STEP_UP_REQUIRED opens the step-up dialog and
// the request is sent once more.
export async function archiveFetch(path: string, init: RequestInit = {}, stepped = false): Promise<Response> {
  const r = await fetch(path, { ...init, headers: { ...authHeaders(), ...(init.headers || {}) } })
  if (r.status === 401 && !stepped) {
    const hint = stepUpHintOf(await r.clone().json().catch(() => ({})))
    if (hint?.mode === 'reauth') {
      await requestStepUp(hint)
      return archiveFetch(path, init, true)
    }
  }
  return r
}

/** Asks the person to type this instance's name; null when cancelled or mistyped. */
export async function confirmInstanceName(): Promise<string | null> {
  const { instance } = await adminApi.get<{ instance: string }>('/api/settings/config/instance')
  const typed = window.prompt(`To restore a backup over this AppCrane, type its name: ${instance}`)
  if (typed == null) return null
  if (typed.trim().toLowerCase() !== instance.toLowerCase()) {
    window.alert(`That is not ${instance}. Nothing was restored.`)
    return null
  }
  return typed.trim()
}
