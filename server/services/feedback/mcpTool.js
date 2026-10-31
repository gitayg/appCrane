// appcrane_submit_feedback: registered in mcpTools.js's TOOLS array.
//
// readOnly is false because the call writes a record, which keeps it out of
// View as previews. readOnlyKeyMayCall lets a read-only key (and read-only
// OAuth connection) send feedback anyway: the only thing it creates is a
// request carrying the caller's own words, rate limited, and the people who
// most often hit a confusing error are the ones holding read-only keys.

import { submitFeedback } from './submit.js';
import { KINDS, ENVS, MESSAGE_MAX, ERROR_MAX, CONTEXT_LIMITS } from './input.js';

export const submitFeedbackTool = {
  name: 'appcrane_submit_feedback',
  description:
    'Send feedback (a bug, an idea, anything else) about an app or about AppCrane itself, when the user asks you to report something, ' +
    'for example "send AppCrane feedback that the deploy error did not name the missing env var". ' +
    'Put the user\'s point in message in plain words; attach what you know in context (the appcrane_* tool you were using, what the user asked for, ' +
    'the deploy id, the error text, your client name and version) without asking the user for it. ' +
    'With slug set, it goes to that app\'s request queue (you need access to the app); with slug omitted, it goes to the AppCrane platform admins. ' +
    `Secrets and e-mail addresses are removed before it is stored. Limit 20 an hour per user. Returns { id, target, where }: tell the user where to see it.`,
  inputSchema: {
    type: 'object',
    properties: {
      message: { type: 'string', minLength: 1, maxLength: MESSAGE_MAX, description: 'The feedback in plain language, in the user\'s words.' },
      kind: { type: 'string', enum: KINDS, default: 'bug', description: 'bug, feature or other.' },
      slug: { type: 'string', description: 'The app the feedback is about. Omit (or "appcrane") for feedback about AppCrane itself.' },
      env: { type: 'string', enum: ENVS, description: 'The environment it happened in, if any.' },
      context: {
        type: 'object',
        description: 'What you know about the situation. Only these fields are accepted.',
        properties: {
          tool: { type: 'string', maxLength: CONTEXT_LIMITS.tool, description: 'The appcrane_* tool you were using.' },
          task: { type: 'string', maxLength: CONTEXT_LIMITS.task, description: 'What the user asked you to do.' },
          deploy_id: { type: ['string', 'integer'], description: 'The deploy id, if one is involved.' },
          error: { type: 'string', description: `The error text you got. Cut to ${ERROR_MAX} characters.` },
          client: { type: 'string', maxLength: CONTEXT_LIMITS.client, description: 'Your client name and version, e.g. "Claude Code 2.1".' },
        },
        additionalProperties: false,
      },
    },
    required: ['message'],
    additionalProperties: false,
  },
  requiredRole: 'any',
  readOnlyKeyMayCall: true,
  handler: async (user, args) => submitFeedback(user, args),
};
