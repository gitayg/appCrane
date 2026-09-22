// Which models a coder dispatch may ask for.
//
// SECURITY — this is the first of two defences, and the reason the list is a
// list. buildClaudeCmd() in runAgent.js assembles a SHELL STRING that is run by
// `sh -c` inside the app container. Before v2.85.0 nothing outside the server
// could choose the model, so `--model ${model}` was interpolated raw. The
// moment a browser can name the model, that interpolation is a remote shell:
// `sonnet; touch /tmp/pwned` would run.
//
// Two independent defences, because either one alone is a single edit away
// from being wrong:
//   1. this allowlist of EXACT strings, enforced at the route boundary — not a
//      regex over "safe-looking" characters, which is a judgement call someone
//      relaxes later;
//   2. shellQuote() around the value in buildClaudeCmd, so even a value that
//      got past the list (a mistaken entry, a future caller that forgets to
//      validate) is one argv word rather than a command.
//
// The strings themselves were read off the Claude Code CLI this platform runs
// (`claude --help`: "Provide an alias for the latest model (e.g. 'fable',
// 'opus', or 'sonnet') or a model's full name (e.g. 'claude-fable-5')"), not
// invented. An id the CLI does not know is refused by the CLI with
// `[claude-code:unrecognized_model]`, which is a bad turn, not a bad platform —
// but there is no reason to offer one.

/** CLI aliases: "the current model in this family", resolved by the CLI itself. */
export const CODER_MODEL_ALIASES = ['opus', 'sonnet', 'haiku', 'fable'];

/** Pinned ids, for a deployment that wants a turn to keep answering the same way. */
export const CODER_MODEL_IDS = [
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-5',
  'claude-sonnet-4-6',
  'claude-haiku-4-5',
  'claude-fable-5-1',
  'claude-fable-5',
];

/** The model every caller gets when none is named. Operator-set, never browser-set. */
export function defaultCoderModel() {
  return process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
}

/**
 * Every exact string a dispatch may name.
 *
 * The configured default is always in it. An operator who sets
 * APPSTUDIO_CODER_MODEL to something this file has never heard of has made a
 * deliberate choice on the host; hiding it from the picker would mean the one
 * model the deployment actually runs is the one option nobody can select.
 * It comes from the server's own environment, so it is not attacker-controlled
 * the way a request body is.
 */
export function allowedCoderModels() {
  const out = [...CODER_MODEL_ALIASES, ...CODER_MODEL_IDS];
  const cfg = defaultCoderModel();
  if (!out.includes(cfg)) out.unshift(cfg);
  return out;
}

export function isAllowedCoderModel(model) {
  return typeof model === 'string' && allowedCoderModels().includes(model);
}

/** What GET /api/coder/models answers: the same list the validator enforces. */
export function coderModelChoices() {
  const cfg = defaultCoderModel();
  return allowedCoderModels().map((id) => ({
    id,
    kind: CODER_MODEL_ALIASES.includes(id) ? 'alias' : 'pinned',
    label: CODER_MODEL_ALIASES.includes(id) ? `${id} (latest)` : id,
    is_default: id === cfg,
  }));
}
