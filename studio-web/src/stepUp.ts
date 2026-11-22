// Step-up (server/services/stepUp.js). A dangerous request answers
// 401 STEP_UP_REQUIRED with a hint; adminApi asks the person to confirm it's
// them through the StepUpModal and retries the request once.

export type StepUpMethod = 'totp' | 'oidc' | 'saml' | 'password'

export interface StepUpHint {
  action: string
  mode: 'reauth' | 'grant'
  methods?: StepUpMethod[]
  window_minutes?: number
  grant_url?: string
}

type Pending = { hint: StepUpHint; resolve: () => void; reject: (e: Error) => void }
type Listener = (p: Pending | null) => void

let current: Pending | null = null
let waiting: Promise<void> | null = null
const listeners = new Set<Listener>()

export function onStepUpRequest(fn: Listener): () => void {
  listeners.add(fn)
  fn(current)
  return () => { listeners.delete(fn) }
}

function publish() {
  for (const fn of listeners) fn(current)
}

export class StepUpCancelled extends Error {
  constructor() {
    super('Cancelled: confirm it is you to continue.')
    this.name = 'StepUpCancelled'
  }
}

/**
 * Resolves once the person stepped up, rejects with StepUpCancelled if they
 * close the dialog. Concurrent refusals share one dialog. With no dialog
 * mounted (a page outside the admin shell) it rejects at once.
 */
export function requestStepUp(hint: StepUpHint): Promise<void> {
  if (!listeners.size) return Promise.reject(new StepUpCancelled())
  if (waiting) return waiting
  waiting = new Promise<void>((resolve, reject) => {
    current = {
      hint,
      resolve: () => { current = null; waiting = null; publish(); resolve() },
      reject: (e) => { current = null; waiting = null; publish(); reject(e) },
    }
    publish()
  })
  return waiting
}

export function stepUpHintOf(body: unknown): StepUpHint | null {
  const err = (body as { error?: { code?: string; step_up?: StepUpHint } })?.error
  return err?.code === 'STEP_UP_REQUIRED' && err.step_up ? err.step_up : null
}
