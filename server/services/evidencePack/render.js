import { CONTROLS, FRAMEWORK, DISCLAIMER } from './controls.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function verifyText(packId) {
  return [
    'How to verify this pack',
    '',
    `1. Every file listed in manifest.json carries its SHA-256. Recompute them (for example \`shasum -a 256 <file>\`) and compare.`,
    '2. manifest.sig is an HMAC-SHA256 of manifest.json under a key derived from the producing instance\'s ENCRYPTION_KEY.',
    `   Upload the pack to Settings > Compliance > Verify on that instance, or call POST /api/evidence-packs/verify, to check it (pack ${packId}).`,
    '3. A changed, added or removed file, or an edited manifest, makes verification fail.',
  ].join('\n');
}

export function renderReadme(ctx) {
  const lines = [
    '# AppCrane compliance evidence pack',
    '',
    `> ${DISCLAIMER}`,
    '',
    `- Framework: ${FRAMEWORK}`,
    `- Period: ${ctx.period.from} to ${ctx.period.to} (UTC, inclusive)`,
    `- Generated: ${ctx.generatedAt} by user ${ctx.generatedBy.id}${ctx.generatedBy.username ? ` (${ctx.generatedBy.username})` : ''}`,
    `- AppCrane version: ${ctx.version || 'unknown'}`,
    `- Pack id: ${ctx.packId}`,
    '',
    'Point-in-time files (users, roles, settings, key ages, configuration) describe the state when the pack was generated, not over the period.',
    'Period files (audit log, events, deploys, scans, release checks, backup runs, restore drills) cover the period only.',
    '',
    '## Controls',
    '',
  ];
  for (const c of CONTROLS) {
    lines.push(`### ${c.id} ${c.title}`, '', c.implementation, '', 'Evidence:');
    for (const f of c.evidence) lines.push(`- \`${f}\``);
    lines.push('');
  }
  if (ctx.degraded.length || ctx.notes.length) {
    lines.push('## Gaps in this pack', '');
    for (const d of ctx.degraded) lines.push(`- \`${d.file}\`: ${d.source} unavailable (${d.reason}).`);
    for (const n of ctx.notes) lines.push(`- ${n}`);
    lines.push('');
  }
  lines.push('## What is never in this pack', '',
    'Passwords, password hashes, API keys and their hashes, tokens, encryption keys, encrypted values, environment variable values, '
    + 'SSO client secrets, certificates and storage credentials. Every file was scanned for these before the pack was written.', '',
    '## ' + verifyText(ctx.packId).split('\n')[0], '', ...verifyText(ctx.packId).split('\n').slice(2), '');
  return lines.join('\n');
}

export function renderIndexHtml(ctx) {
  const rows = CONTROLS.map((c) => `<tr><td><b>${esc(c.id)}</b></td><td>${esc(c.title)}<p>${esc(c.implementation)}</p></td><td>${c.evidence.map((f) => `<a href="${esc(f)}">${esc(f)}</a>`).join('<br>')}</td></tr>`).join('\n');
  const gaps = [...ctx.degraded.map((d) => `<li><code>${esc(d.file)}</code>: ${esc(d.source)} unavailable (${esc(d.reason)})</li>`), ...ctx.notes.map((n) => `<li>${esc(n)}</li>`)].join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AppCrane evidence pack ${esc(ctx.period.from)} to ${esc(ctx.period.to)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:24px;max-width:1100px;color:#1a1a1a;background:#fff}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;vertical-align:top;text-align:left}p{margin:4px 0 0;color:#444}.note{background:#fff4d6;border:1px solid #e0c060;padding:10px}</style>
</head><body>
<h1>AppCrane compliance evidence pack</h1>
<p class="note">${esc(DISCLAIMER)}</p>
<p>Framework: ${esc(FRAMEWORK)}<br>Period: ${esc(ctx.period.from)} to ${esc(ctx.period.to)} (UTC, inclusive)<br>Generated: ${esc(ctx.generatedAt)} by user ${esc(ctx.generatedBy.id)}<br>AppCrane version: ${esc(ctx.version || 'unknown')}<br>Pack id: ${esc(ctx.packId)}</p>
<table><thead><tr><th>Criterion</th><th>How AppCrane implements it</th><th>Evidence</th></tr></thead><tbody>
${rows}
</tbody></table>
${gaps ? `<h2>Gaps in this pack</h2><ul>${gaps}</ul>` : ''}
<h2>Verification</h2><pre>${esc(verifyText(ctx.packId))}</pre>
</body></html>
`;
}
