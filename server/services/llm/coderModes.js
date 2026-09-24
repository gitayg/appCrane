// How much a coder turn may do on its own.
//
// Each mode maps to one Claude Code `--permission-mode`, read off the CLI this
// platform runs (Claude Code 2.1.197, `claude --help`: choices "acceptEdits",
// "auto", "bypassPermissions", "default", "dontAsk", "plan").
//
// A coder turn runs `claude -p` with no terminal behind it, so nobody can
// answer a permission prompt mid-turn: whatever a mode would ASK about is
// refused instead. That is what makes "Edits only" mean edits only: file edits
// are pre-approved, and a shell command is refused. Per-action approval from
// the panel ("Manual") needs a permission-prompt bridge and is not here yet.
//
// SECURITY: the id arrives in a request body and the permission mode ends up in
// a `sh -c` string, so this is an allowlist of exact strings, and runAgent.js
// quotes the value as well (same two defences as coderModels.js).

export const CODER_MODES = [
  {
    id: 'auto',
    permissionMode: 'bypassPermissions',
    label: 'Auto',
    description: 'Reads, edits and runs commands without asking.',
  },
  {
    id: 'edits',
    permissionMode: 'acceptEdits',
    label: 'Edits only',
    description: 'Reads and edits files. Shell commands are refused.',
  },
  {
    id: 'plan',
    permissionMode: 'plan',
    label: 'Plan',
    description: 'Reads the code and proposes a plan. Changes nothing.',
  },
];

export const DEFAULT_CODER_MODE = 'auto';

export function isAllowedCoderMode(id) {
  return CODER_MODES.some((m) => m.id === id);
}

/** The CLI permission mode for a coder mode id; the default for null/empty. */
export function permissionModeFor(id) {
  const m = CODER_MODES.find((x) => x.id === (id || DEFAULT_CODER_MODE));
  if (!m) throw new Error(`Unsupported coder mode '${id}'`);
  return m.permissionMode;
}

export function coderModeChoices() {
  return CODER_MODES.map(({ id, label, description }) => ({ id, label, description, is_default: id === DEFAULT_CODER_MODE }));
}
