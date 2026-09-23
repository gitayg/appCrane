// Why a coder turn failed, in words the user can act on.
//
// The Claude CLI reports a rejected credential as ordinary assistant text
// ("Failed to authenticate. API Error: 401 API key is invalid.") followed by a
// result with is_error set. Streamed as-is, that reads like the coder's answer.
// This turns it into an error that names the credential that was rejected and
// where to replace it.

const AUTH_PATTERN = /failed to authenticate|\b401\b|invalid (x-)?api[ -]?key|api key is invalid|oauth token (has )?(expired|is invalid|revoked)|authentication_error|invalid bearer token/i;

const FIX_BY_KIND = {
  user_oauth:
    'Your Claude subscription token was rejected. Run `claude setup-token` again and paste the new token '
    + 'under "Claude subscription token" on your profile.',
  app_credentials:
    "This app's uploaded Claude credentials (credentials.json) were rejected. Upload fresh credentials for the app, "
    + 'or add your own Claude subscription token on your profile, which is used first.',
  api_key:
    "The platform's Anthropic API key was rejected. Add your own Claude subscription token on your profile "
    + '(it is used first), or ask a platform admin to replace ANTHROPIC_API_KEY.',
};

export function isAuthFailure(text) {
  return AUTH_PATTERN.test(String(text || ''));
}

/**
 * Returns null when the turn succeeded, otherwise the message to show.
 *   text:        everything the agent said this turn
 *   isError:     the CLI's result.is_error
 *   code:        process exit code
 *   kind:        agentCredentialKind() for this turn
 *   stderrTail:  last stderr lines, already scrubbed of secrets
 */
export function explainTurnFailure({ text = '', isError = false, code = 0, kind = null, stderrTail = [] } = {}) {
  // Only a turn that failed is classified: a successful reply that mentions
  // "401" (say, a fixed auth handler) is an answer, not an auth failure.
  if (!isError && (code === 0 || code == null)) return null;
  const said = String(text || '').trim();
  const tail = (stderrTail || []).join('\n').trim();
  if (isAuthFailure(said) || isAuthFailure(tail)) {
    const fix = FIX_BY_KIND[kind] || 'The Claude credential for this turn was rejected. Add your own Claude subscription token on your profile.';
    return `${fix}\n\nClaude said: ${said || tail}`;
  }
  const detail = said || tail;
  return `The coder's turn failed (exit ${code ?? 'unknown'}).${detail ? `\n${detail}` : ''}\n\nNothing was changed by this turn unless the Changes tab shows otherwise. Try again, or report this with the text above.`;
}
