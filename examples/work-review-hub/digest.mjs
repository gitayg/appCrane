// Weekly digest: on Monday, each person who uploaded in the last week gets one
// email with their own numbers and their top three fixes. Sent through
// AppCrane's email service for hosted apps (POST /api/service/email with the
// injected APPCRANE_SERVICE_TOKEN), so the hub holds no mail credentials, the
// recipient must be a platform user, and the idempotency key makes a repeated
// send a no-op. Only the person themselves receives it.

// Finding ids the uploader sends (fixed slugs, never text) → what to do.
export const FIXES = {
  'rework': ['Prompts that ended in a correction', 'Rewrite your costliest ones with the missing piece: where, what done looks like, or the constraint'],
  'vague-prompts': ['Vague prompts', 'Name the file, the error text or what done looks like'],
  'subagents-no-benefit': ['Subagents that gained nothing', 'Do small tasks in the main agent; turn a repeated brief into a skill'],
  'redundant-reads': ['Re-reading unchanged files', 'Add a short map of where things live to CLAUDE.md'],
  'idle-reruns': ['Re-running commands with nothing changed', 'Run slow checks in the background and wait for them'],
  'error-output': ['Tool errors', 'Fix the error that comes up most; /work-review shows which'],
};
const SETUP_FIXES = {
  'claude-md-long': 'CLAUDE.md is over 200 lines: cut what Claude can read from the code',
  'claude-md-procedure': 'A long procedure in CLAUDE.md: move it into a skill',
  'always-on-heavy': 'A lot of CLAUDE.md loads on every request: trim it or move parts into skills',
  'agent-unused': 'A subagent you never use: delete it',
  'agent-is-a-skill': 'A subagent that is really a playbook: make it a skill',
  'mcp-unused': 'An MCP server you never call: disable it with /mcp',
  'allow-all-bash': 'Bash(*) is allowed: narrow it, or use auto mode',
  'skill-side-effect-auto': 'A deploy-style skill Claude can run on its own: set disable-model-invocation',
  'skill-installed-twice': 'A skill installed twice, as your own copy and from a plugin: delete your copy',
};

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const usd = n => (n == null ? 'not measured' : n >= 100 ? `$${n.toFixed(0)}` : `$${n.toFixed(2)}`);

/** ISO week label, e.g. 2026-W44, for "once per week" markers and idempotency. */
export function isoWeek(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const y = t.getUTCFullYear();
  const w = Math.ceil(((t - Date.UTC(y, 0, 1)) / 864e5 + 1) / 7);
  return `${y}-W${String(w).padStart(2, '0')}`;
}

/**
 * The email for one person, from their snapshot history (oldest first), or
 * null when there is nothing recent to say.
 */
export function digestFor(name, history, { now = new Date(), hubUrl = '' } = {}) {
  const latest = history.at(-1);
  const weekAgo = new Date(now.getTime() - 7 * 864e5).toISOString().slice(0, 10);
  if (!latest || latest.day < weekAgo) return null;
  const prev = [...history].reverse().find(s => s.day <= new Date(Date.parse(latest.day) - 6 * 864e5).toISOString().slice(0, 10));
  const cost = latest.totals.usd || 0;
  const lines = [];
  lines.push(`Cost at API list prices, last 7 days: ${usd(cost)}${prev ? ` (the week before: ${usd(prev.totals.usd || 0)})` : ''}. On a seat plan this is the API-equivalent value of the work, not a bill.`);
  if (latest.outcomes?.commits) lines.push(`Commits landed: ${latest.outcomes.commits}, ${usd(latest.outcomes.usdPerCommit)} each.`);
  const fixes = [
    ...(latest.findings || []).filter(f => FIXES[f.id]).map(f => `${FIXES[f.id][0]} (${usd(f.usd)}, ${Math.round(f.share * 100)}% of spend): ${FIXES[f.id][1]}.`),
    ...Object.keys(latest.setup?.findings || {}).filter(k => SETUP_FIXES[k]).map(k => `${SETUP_FIXES[k]}.`),
  ].slice(0, 3);
  const first = (name || '').split(/[\s@]/)[0] || 'there';
  const subject = fixes.length ? `Your week with Claude: ${usd(cost)}, ${fixes.length} thing${fixes.length > 1 ? 's' : ''} to try` : `Your week with Claude: ${usd(cost)}`;
  const footer = 'Only you get this email. Turn it off on your Work Review page.';
  const text = [`Hi ${first},`, '', ...lines, '', fixes.length ? 'Worth trying this week:' : 'Nothing stood out this week. Nice.', ...fixes.map((f, i) => `${i + 1}. ${f}`),
    '', hubUrl ? `Your page: ${hubUrl}` : 'Open Work Review in AppCrane for the details.', '', footer].join('\n');
  const html = `<p>Hi ${esc(first)},</p>${lines.map(l => `<p>${esc(l)}</p>`).join('')}` +
    (fixes.length ? `<p><strong>Worth trying this week:</strong></p><ol>${fixes.map(f => `<li>${esc(f)}</li>`).join('')}</ol>` : '<p>Nothing stood out this week. Nice.</p>') +
    (hubUrl ? `<p><a href="${esc(hubUrl)}">Open your Work Review page</a></p>` : '') + `<p style="color:#6b6f76;font-size:12px">${esc(footer)}</p>`;
  return { subject, text, html };
}

/** Send through AppCrane's internal email service. Throws on a refused send. */
export async function sendViaAppCrane({ to, subject, text, html, idempotencyKey }, env = process.env) {
  const base = env.CRANE_INTERNAL_URL, token = env.APPCRANE_SERVICE_TOKEN;
  if (!base || !token) throw new Error('no AppCrane email service (CRANE_INTERNAL_URL / APPCRANE_SERVICE_TOKEN not set)');
  const res = await fetch(new URL('/api/service/email', base), {
    method: 'POST',
    signal: AbortSignal.timeout(15_000),
    headers: { 'Content-Type': 'application/json', 'X-AppCrane-Service-Token': token },
    body: JSON.stringify({ to, subject, text, html, idempotencyKey, fromName: 'Work Review', env: env.WORK_REVIEW_ENV === 'sandbox' ? 'sandbox' : 'production' }),
  });
  if (!res.ok) throw new Error(`email service answered ${res.status}: ${(await res.text()).slice(0, 200)}`);
}
