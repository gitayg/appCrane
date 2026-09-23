// Client for /api/coder — the Crane-hosted coder surface (server/routes/coder.js).
//
// Every shape here was read off that router rather than guessed; the two that
// most easily go wrong are marked:
//   • dispatch takes `{ prompt }`, not `{ text }`.
//   • the SSE stream carries TWO encodings of the same thing — see CoderEvent.

import { adminApi, authParamsForSSE } from '../../adminApi'

export type CoderStatus =
  | 'starting' | 'idle' | 'active' | 'queued' | 'paused' | 'shipped' | 'error'

export interface CoderSession {
  id:                 string
  app_slug:           string
  user_id:            number
  branch_name:        string
  container_id:       string | null
  workspace_dir:      string | null
  status:             CoderStatus
  claude_session_id:  string | null
  cost_tokens:        number
  cost_usd_cents:     number
  created_at:         string
}

export interface CoderMessage {
  id:         number
  session_id: string
  role:       'user' | 'assistant'
  content:    string
  /** Which model produced (or was asked for) this turn. Null on pre-v2.85.0 rows. */
  model:      string | null
  created_at: string
}

/** One entry of GET /api/coder/models — the server's allowlist, verbatim. */
export interface CoderModel {
  id:         string
  kind:       'alias' | 'pinned'
  label:      string
  is_default: boolean
}

/**
 * A message typed while a turn was running. It has NOT been sent to the model.
 * Server-side (coder_session_followups) rather than a client array, so it
 * survives a reload and is visible to everyone watching the session.
 */
export interface CoderFollowup {
  id:         number
  prompt:     string
  model:      string | null
  user_id:    number | null
  created_at: string
}

export interface ChangedFile {
  path:   string
  status: 'added' | 'modified' | 'deleted'
  diff:   string
}

export interface DeployInfo {
  action:    string | null
  branch?:   string
  commit?:   string
  triggered: { env: string; deployment_id: number }[]
}

export interface ReleaseResult {
  commit:   { sha: string }
  released: string[]
  deleted:  string[]
  deploy:   DeployInfo | null
}

// GET /:slug/queue is deliberately NOT wired. The only thing the chat needs
// from the queue is this session's position, and builderSession already pushes
// that down the stream it is already subscribed to (`{type:'queue', ahead}`) —
// live, rather than as a poll that is stale the moment it lands.

/** One parsed line of the agent's stream-json (server/services/builder/streamJsonParser.js). */
export type StreamEvent =
  | { type: 'text';   text: string }
  | { type: 'tool';   name: string; input?: unknown }
  | { type: 'result'; inputTokens: number; outputTokens: number; costUsdCents: number }
  | { type: 'system'; subtype: string; data?: unknown }

/**
 * What arrives on the SSE channel.
 *
 * The route replays buffered `role='system'` rows by sending the stored event
 * VERBATIM — `{"type":"text",…}` — while live events from builderSession are
 * published WRAPPED as `{ type:'stream', event:{…} }`. So the same text block
 * has two encodings on one channel depending on whether you are catching up or
 * caught up, and a reader that handles only the wrapped form silently drops
 * the entire replayed transcript.
 */
export type CoderEvent =
  | { type: 'stream'; event: StreamEvent }
  | { type: 'status'; status: CoderStatus; ahead?: number; exitCode?: number; reason?: string }
  | { type: 'turn';   model: string }
  | { type: 'followups'; items: CoderFollowup[] }
  | { type: 'note';   message: string }
  | { type: 'queue';  ahead: number; depth: number; running?: unknown }
  | { type: 'cost';   inputTokens: number; outputTokens: number; costUsdCents: number }
  | { type: 'error';  message: string; turnFailed?: boolean }
  | StreamEvent

/**
 * One reason the coder is unavailable here, as the server explains it.
 * `fix` is written for the person reading it; `href` is where that fix lives,
 * when it lives somewhere in AppCrane.
 */
export interface CoderGap {
  code: string
  title: string
  detail: string
  fix: string
  href?: string
}

export interface CoderAvailability {
  available: boolean
  can_release: boolean
  gaps: CoderGap[]
}

const enc = encodeURIComponent
const base = (slug: string) => `/api/coder/${enc(slug)}`

export const coderApi = {
  /**
   * Every reason the coder would refuse this user on this app, all at once.
   * Always answers — the point is that someone on an app where the coder does
   * not work still learns what it would take.
   */
  availability: (slug: string) =>
    adminApi.get<CoderAvailability>(`${base(slug)}/availability`),

  /** Latest session for this app, or null. */
  latestSession: (slug: string) =>
    adminApi.get<{ session: CoderSession | null }>(`${base(slug)}/session`),

  /** 201 { session_id, log[] }. Refuses with NOT_CRANE_HOSTED / NO_REPO / NOT_CONFIGURED / BUILDER_OCCUPIED. */
  startSession: (slug: string) =>
    adminApi.post<{ session_id: string; log: string[] }>(`${base(slug)}/session`),

  session: (slug: string, id: string) =>
    adminApi.get<{ session: CoderSession; messages: CoderMessage[]; followups: CoderFollowup[] }>(
      `${base(slug)}/session/${enc(id)}`),

  /** The allowlist the dispatch validator enforces. Not app-scoped. */
  models: () =>
    adminApi.get<{ models: CoderModel[]; default: string }>('/api/coder/models'),

  /**
   * `model` must be one of coderApi.models() — anything else is a 400
   * VALIDATION, because the value reaches a shell command in the container.
   * When a turn is already running the route QUEUES this as a follow-up and
   * answers `{ queued: true, followup }` rather than refusing.
   */
  dispatch: (slug: string, id: string, prompt: string, model?: string) =>
    adminApi.post<{ message: string; queued?: boolean; followup?: CoderFollowup }>(
      `${base(slug)}/session/${enc(id)}/dispatch`,
      model ? { prompt, model } : { prompt }),

  followups: (slug: string, id: string) =>
    adminApi.get<{ followups: CoderFollowup[] }>(`${base(slug)}/session/${enc(id)}/followups`),

  cancelFollowup: (slug: string, id: string, followupId: number) =>
    adminApi.del<{ cancelled: boolean; followups: CoderFollowup[] }>(
      `${base(slug)}/session/${enc(id)}/followups/${followupId}`),

  stop: (slug: string, id: string) =>
    adminApi.post<{ message: string }>(`${base(slug)}/session/${enc(id)}/stop`),

  resume: (slug: string, id: string) =>
    adminApi.post<{ message: string; log: string[] }>(`${base(slug)}/session/${enc(id)}/resume`),

  changes: (slug: string, id: string) =>
    adminApi.get<{ files: ChangedFile[] }>(`${base(slug)}/session/${enc(id)}/changes`),

  release: (slug: string, id: string, paths: string[], message?: string) =>
    adminApi.post<ReleaseResult>(`${base(slug)}/session/${enc(id)}/release`,
      message ? { paths, message } : { paths }),

  /**
   * EventSource cannot set headers, so the credential travels as a query
   * param under the name the route resolves it by.
   * `after` is a coder_session_messages id: the route replays buffered system
   * rows with id > after, which is how a reconnect avoids re-rendering
   * everything already on screen.
   */
  eventsUrl(slug: string, id: string, after: number): string {
    const qs = new URLSearchParams({ after: String(after), ...authParamsForSSE() })
    return `${base(slug)}/session/${enc(id)}/events?${qs.toString()}`
  },
}

/** Statuses a session can still be talked to in. Anything else needs a new one. */
export function isLiveStatus(s: CoderStatus | undefined | null): boolean {
  return s === 'idle' || s === 'active' || s === 'queued' || s === 'paused' || s === 'starting'
}
