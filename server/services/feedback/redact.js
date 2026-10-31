// Secrets out of feedback text before it is stored, mailed or mirrored.
//
// An agent attaches error text it was just handed, and error text is where
// tokens leak (a failed git clone echoes its URL, a 401 echoes the header).
// URL credentials go first, while the user:pass@host shape is still intact;
// then the provider key prefixes Job Health's sanitizeError knows (it also
// truncates to 300 characters, so it cannot be used whole here); then the
// client-error scrubber (dhk_ keys, Bearer, JWTs, query strings, key=value
// secrets, e-mails, long hex and base64). Newlines survive.

import { stripUrlCredentials } from '../gitCredentialScrub.js';
import { scrub } from '../clientErrors.js';

const PROVIDER_KEYS = [
  [/\b(gh[pousr]_|github_pat_|sk-ant-|sk-|xox[abpr]-)[A-Za-z0-9_-]+/g, '$1[redacted]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[redacted]'],
];

export function redactFeedbackText(value) {
  if (value == null || value === '') return '';
  let s = stripUrlCredentials(String(value));
  for (const [re, rep] of PROVIDER_KEYS) s = s.replace(re, rep);
  return scrub(s);
}
