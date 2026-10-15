// The one coder turn a batch of requests becomes (POST /api/coder/:slug/requests/dispatch).
//
// One prompt, one session, one turn: the requests are worked through in the
// order the caller picked them, and the user reviews and releases the result
// together. Each request's text is fenced and labelled with its number so the
// agent's report — and the changes — can be traced back to the request.

/** Most requests one dispatch may carry. One turn has one context window, and
 *  every request's changes land in the same change set the user reviews before
 *  releasing; past ten that review stops being something a person does. */
export const MAX_DISPATCH_REQUESTS = 10;

function requester(r) {
  return r.user_name ? `filed by ${r.user_name}` : 'filed by an unknown user';
}

export function buildRequestsPrompt(requests) {
  const n = requests.length;
  const lines = [
    n === 1
      ? 'Address the request below, filed against this app.'
      : `Work through the ${n} requests below, filed against this app, one at a time and in the order given.`,
    '',
    'For each request:',
    '- Make the change it asks for. A request may begin with a description of the page element it is about; use it to find the code.',
    '- Keep each request\'s changes identifiable: do not mix two requests\' edits in one change where you can avoid it, and name the request number in anything you report about it.',
    '- If you cannot address it (unclear, out of scope, or blocked), do not guess — say why and move on to the next one.',
    '- Do not commit or release. The user reviews and releases these changes together.',
    '',
    'When you are done, reply with one line per request, in the same order:',
    '  Request #<id>: done — <what you changed, and in which files>',
    '  Request #<id>: not done — <why>',
    '',
  ];
  for (const r of requests) {
    lines.push(`=== Request #${r.id} (${requester(r)}${r.created_at ? `, ${r.created_at}` : ''}) ===`);
    lines.push(String(r.message ?? '').trim());
    lines.push(`=== End of request #${r.id} ===`, '');
  }
  return lines.join('\n').trimEnd();
}
