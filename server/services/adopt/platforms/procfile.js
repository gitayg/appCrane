// Procfile (Heroku, also read by other buildpack platforms).
// https://devcenter.heroku.com/articles/procfile
//   "<process type>: <command>"
//   "A Heroku app's web process type is special: it's the only process type
//    that can receive external HTTP traffic from Heroku's routers."
//   "The release process type is used to specify the command to run during
//    your app's release phase."

const LINE_RE = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/;

export function parseProcfile(text) {
  const processes = [];
  const bad = [];
  String(text || '').split(/\r?\n/).forEach((raw, idx) => {
    const l = raw.trim();
    if (!l || l.startsWith('#')) return;
    const m = l.match(LINE_RE);
    if (!m || !m[2].trim()) { bad.push(idx + 1); return; }
    processes.push({ type: m[1], command: m[2].trim(), line: idx + 1 });
  });
  return { processes, bad_lines: bad };
}

export function mapProcfile(text, file = 'Procfile') {
  const { processes, bad_lines } = parseProcfile(text);
  const out = { format: 'procfile', file, web: null, release: [], crons: [], env: [], databases: [], unmapped: [], notes: [] };
  const seen = new Set();
  for (const p of processes) {
    if (seen.has(p.type)) {
      out.unmapped.push({ field: p.type, title: `${file} declares "${p.type}" twice`, detail: `Line ${p.line} is ignored; Heroku also takes one command per process type.` });
      continue;
    }
    seen.add(p.type);
    if (p.type === 'web') out.web = { start: p.command, build: null, field: 'web' };
    else if (p.type === 'release') out.release.push({ command: p.command, field: 'release' });
    else {
      out.unmapped.push({
        field: p.type, kind: 'process',
        title: `Process "${p.type}" is not run`,
        detail: `${file} runs "${p.command}" as its own process. An AppCrane app runs one container per stage, serving the web process only. Run it as a separate AppCrane app from the same repository, fold it into the web process, or turn it into a cron job if it is periodic.`,
      });
    }
  }
  if (bad_lines.length) {
    out.unmapped.push({ field: 'lines', title: `${file} lines AppCrane could not read`, detail: `Line(s) ${bad_lines.join(', ')} are not "<process type>: <command>".` });
  }
  return out;
}
