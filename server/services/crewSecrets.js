/**
 * Secret detection for Crew message bodies (v2.105.0).
 *
 * AppCrane had no value-based secret scanner before this: audit redaction
 * (utils/auditRedact.js) masks by ARGUMENT NAME on purpose, and the env-file
 * push guard (envFilePushGuard.js) refuses by PATH. Neither looks inside free
 * text, and a Crew message is nothing but free text that is stored for 30 days
 * and shown to another person's agent. So this is new, and deliberately
 * conservative: it matches only shapes that are credentials with near
 * certainty, because a false positive here blocks a legitimate hand-off and
 * teaches agents to paraphrase around the scanner.
 *
 * What it catches: PEM private keys, AWS access key ids, AppCrane's own dhk_
 * keys, GitHub / Anthropic / OpenAI / Slack tokens, and `Bearer <token>`.
 * What it does not: arbitrary passwords, connection strings without a known
 * token shape, base64 blobs. Those still must not be sent; the tool
 * descriptions say so, and the refusal message names the rule that matched so
 * the agent can tell its owner what it almost relayed.
 */

const RULES = [
  { id: 'private-key',     re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/ },
  { id: 'aws-access-key',  re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'appcrane-key',    re: /\bdhk_[A-Za-z0-9]+_[A-Za-z0-9_-]{24,}/ },
  { id: 'github-token',    re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { id: 'anthropic-key',   re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'openai-key',      re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}/ },
  { id: 'slack-token',     re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  // "Bearer" followed by something token-shaped. 20+ chars keeps prose like
  // "the Bearer header" from matching.
  { id: 'bearer-token',    re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/ },
];

/** The id of the first rule a text matches, or null. Never returns the match itself. */
export function findSecret(text) {
  if (typeof text !== 'string' || !text) return null;
  for (const r of RULES) if (r.re.test(text)) return r.id;
  return null;
}
