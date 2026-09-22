import { ApiError } from '../../adminApi'

/**
 * A refusal rendered as itself.
 *
 * /api/coder answers a handful of conditions that are not failures — they are
 * the user being told what to do next, and each has a different next step. A
 * generic red "Error: <message>" throws that away, so every code the routes
 * actually emit gets a heading here and the server's own sentence underneath
 * (the server wording is specific and stays the single source of truth; this
 * only adds the framing).
 */
const HEADINGS: Record<string, string> = {
  NOT_CRANE_HOSTED: 'This app keeps its source on GitHub',
  NO_REPO:          'This app has no source code yet',
  NOT_CONFIGURED:   'No Claude credential available',
  BUILDER_OCCUPIED: 'Someone else is working on this app',
  ENV_FILE_IN_PUSH: 'Environment files cannot be released',
  NOT_CHANGED:      'That file is not in this session’s changes',
  NO_WORKSPACE:     'This session’s workspace is gone',
  WRONG_STATUS:     'Not right now',
  FORBIDDEN:        'You do not have permission',
  VALIDATION:       'That request was not valid',
}

/** Extra guidance the server message does not carry, keyed by code. */
const HINTS: Record<string, string> = {
  NOT_CONFIGURED:
    'Run `claude setup-token` and save the token to your AppCrane profile, upload a '
    + 'credentials.json for this app, or ask a platform admin to set ANTHROPIC_API_KEY.',
  BUILDER_OCCUPIED:
    'One container per app, so one session at a time. Try again once they are done.',
  ENV_FILE_IN_PUSH:
    'Nothing was released. Deselect the .env file and release the rest; set secrets '
    + 'through the app’s environment variables instead.',
}

export function CoderRefusal({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null
  const api = error instanceof ApiError ? error : null
  const code = api?.code || ''
  const heading = HEADINGS[code] || (api?.status === 403 ? HEADINGS.FORBIDDEN : 'Something went wrong')
  const hint = HINTS[code]
  return (
    <div className="coder-refusal">
      <div className="coder-refusal-title">{heading}</div>
      <p className="coder-refusal-body">{(error as Error).message}</p>
      {hint && <p className="coder-refusal-hint">{hint}</p>}
      {onRetry && (
        <button type="button" className="coder-btn" onClick={onRetry}>Try again</button>
      )}
    </div>
  )
}
